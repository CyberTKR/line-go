package registration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type WebAuthDetails struct {
	BaseURL       string
	Authorization string
}

func (d WebAuthDetails) Valid() bool {
	parsed, err := url.Parse(d.BaseURL)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() == "w.line.me" && d.Authorization != ""
}

type HumanVerifier interface {
	Verify(context.Context, WebAuthDetails) error
}

type BrowserVerifier struct {
	Executable string
	Timeout    time.Duration
}

type browserProxy struct {
	server   string
	username string
	password string
}

func (v BrowserVerifier) Verify(ctx context.Context, details WebAuthDetails) error {
	if !details.Valid() {
		return fmt.Errorf("invalid LINE WebAuthDetails")
	}
	executable, err := browserExecutable(v.Executable)
	if err != nil {
		return err
	}
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	profileDir, err := os.MkdirTemp("", "line-human-verification-")
	if err != nil {
		return fmt.Errorf("create browser profile: %w", err)
	}
	defer os.RemoveAll(profileDir)

	proxy, err := browserProxyFor(details.BaseURL)
	if err != nil {
		return err
	}
	if proxy != nil && proxy.username != "" {
		localProxy, closeProxy, err := startAuthenticatedProxyBridge(ctx, proxy)
		if err != nil {
			return err
		}
		defer closeProxy()
		proxy = &browserProxy{server: localProxy}
	}
	if proxy != nil {
		fmt.Fprintf(os.Stderr, "[HUMAN VERIFICATION] Chrome proxy enabled: %s\n", proxy.server)
	}
	arguments := []string{
		"--remote-debugging-port=0",
		"--user-data-dir=" + profileDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--new-window",
		"about:blank",
	}
	if proxy != nil {
		arguments = append([]string{"--proxy-server=" + proxy.server}, arguments...)
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdout = io.Discard
	stderr, err := command.StderrPipe()
	if err != nil {
		return fmt.Errorf("open browser stderr: %w", err)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start Chrome/Chromium: %w", err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()

	devToolsURL, err := waitDevToolsURL(ctx, stderr, processDone)
	if err != nil {
		return err
	}
	cdp, err := newCDPClient(ctx, devToolsURL)
	if err != nil {
		return err
	}
	defer cdp.close()
	defer cdp.send(context.Background(), "Browser.close", nil, "")

	createResult, err := cdp.send(ctx, "Target.createTarget", map[string]any{"url": "about:blank"}, "")
	if err != nil {
		return err
	}
	var created struct {
		TargetID string `json:"targetId"`
	}
	if err := json.Unmarshal(createResult, &created); err != nil || created.TargetID == "" {
		return fmt.Errorf("Chrome did not return a target ID")
	}
	attachResult, err := cdp.send(ctx, "Target.attachToTarget", map[string]any{"targetId": created.TargetID, "flatten": true}, "")
	if err != nil {
		return err
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(attachResult, &attached); err != nil || attached.SessionID == "" {
		return fmt.Errorf("Chrome did not return a session ID")
	}
	for _, method := range []string{"Page.enable", "Network.enable"} {
		if _, err := cdp.send(ctx, method, map[string]any{}, attached.SessionID); err != nil {
			return err
		}
	}
	if _, err := cdp.send(ctx, "Fetch.enable", map[string]any{
		"handleAuthRequests": proxy != nil && proxy.username != "",
		"patterns": []map[string]any{{
			"urlPattern":   details.BaseURL + "*",
			"resourceType": "Document",
			"requestStage": "Request",
		}},
	}, attached.SessionID); err != nil {
		return err
	}
	navigationResult := make(chan error, 1)
	go func() {
		_, err := cdp.send(ctx, "Page.navigate", map[string]any{"url": details.BaseURL}, attached.SessionID)
		navigationResult <- err
	}()

	authorizationInjected := false
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("human verification: %w", ctx.Err())
		case err := <-navigationResult:
			if err != nil {
				return fmt.Errorf("navigate to LINE verification: %w", err)
			}
			navigationResult = nil
		case err := <-processDone:
			if err == nil {
				return fmt.Errorf("verification browser closed before completion")
			}
			return fmt.Errorf("verification browser stopped: %w", err)
		case event, ok := <-cdp.events:
			if !ok {
				return fmt.Errorf("Chrome DevTools connection closed")
			}
			if event.SessionID != attached.SessionID {
				continue
			}
			if event.Method == "Fetch.authRequired" {
				var challenge struct {
					RequestID string `json:"requestId"`
				}
				if err := json.Unmarshal(event.Params, &challenge); err != nil {
					return fmt.Errorf("decode browser proxy authentication request: %w", err)
				}
				response := map[string]string{"response": "Default"}
				if proxy != nil && proxy.username != "" {
					response = map[string]string{
						"response": "ProvideCredentials",
						"username": proxy.username,
						"password": proxy.password,
					}
				}
				if _, err := cdp.send(ctx, "Fetch.continueWithAuth", map[string]any{
					"requestId":             challenge.RequestID,
					"authChallengeResponse": response,
				}, attached.SessionID); err != nil {
					return err
				}
				continue
			}
			if event.Method == "Fetch.requestPaused" {
				var paused struct {
					RequestID    string `json:"requestId"`
					ResourceType string `json:"resourceType"`
					Request      struct {
						URL     string            `json:"url"`
						Headers map[string]string `json:"headers"`
					} `json:"request"`
				}
				if err := json.Unmarshal(event.Params, &paused); err != nil {
					return fmt.Errorf("decode paused browser request: %w", err)
				}
				parameters := map[string]any{"requestId": paused.RequestID}
				if !authorizationInjected && paused.ResourceType == "Document" && strings.HasPrefix(paused.Request.URL, details.BaseURL) {
					headers := make([]map[string]string, 0, len(paused.Request.Headers)+1)
					for name, value := range paused.Request.Headers {
						if !strings.EqualFold(name, "authorization") {
							headers = append(headers, map[string]string{"name": name, "value": value})
						}
					}
					headers = append(headers, map[string]string{"name": "Authorization", "value": details.Authorization})
					parameters["headers"] = headers
					authorizationInjected = true
					fmt.Fprintln(os.Stderr, "[HUMAN VERIFICATION] LINE authorization attached to the initial verification document")
				}
				if _, err := cdp.send(ctx, "Fetch.continueRequest", parameters, attached.SessionID); err != nil {
					return err
				}
				continue
			}
			if event.Method == "Network.loadingFailed" {
				var failed struct {
					ErrorText string `json:"errorText"`
					Canceled  bool   `json:"canceled"`
				}
				if json.Unmarshal(event.Params, &failed) == nil && !failed.Canceled {
					fmt.Fprintf(os.Stderr, "[HUMAN VERIFICATION] Browser resource failed: %s\n", failed.ErrorText)
				}
			}
			if event.Method == "Network.responseReceived" {
				var received struct {
					Type     string `json:"type"`
					Response struct {
						URL    string  `json:"url"`
						Status float64 `json:"status"`
					} `json:"response"`
				}
				if json.Unmarshal(event.Params, &received) == nil && isLINEVerificationURL(received.Response.URL) && received.Response.Status >= 400 {
					fmt.Fprintf(os.Stderr, "[HUMAN VERIFICATION] LINE page returned HTTP %.0f for %s\n", received.Response.Status, received.Type)
				}
			}
			callbackURL := eventURL(event)
			switch callbackURL {
			case "lineconnect://accepted":
				return nil
			case "lineconnect://closeBrowser", "lineconnect://fatalError":
				return fmt.Errorf("LINE web verification was cancelled or failed")
			}
		}
	}
}

func isLINEVerificationURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() == "w.line.me"
}

func browserProxyFor(target string) (*browserProxy, error) {
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("create browser proxy request: %w", err)
	}
	proxyURL, err := http.ProxyFromEnvironment(request)
	if err != nil {
		return nil, fmt.Errorf("resolve browser proxy: %w", err)
	}
	if proxyURL == nil {
		return nil, nil
	}
	scheme := strings.ToLower(proxyURL.Scheme)
	if scheme != "http" && scheme != "https" && scheme != "socks5" && scheme != "socks5h" {
		return nil, fmt.Errorf("browser proxy scheme %q is unsupported", proxyURL.Scheme)
	}
	if proxyURL.Host == "" {
		return nil, fmt.Errorf("browser proxy host is empty")
	}
	configuration := &browserProxy{server: scheme + "://" + proxyURL.Host}
	if proxyURL.User != nil {
		configuration.username = proxyURL.User.Username()
		configuration.password, _ = proxyURL.User.Password()
	}
	return configuration, nil
}

func browserExecutable(configured string) (string, error) {
	if configured == "" {
		configured = os.Getenv("LINEGO_VERIFICATION_BROWSER")
	}
	candidates := []string{configured}
	switch runtime.GOOS {
	case "darwin":
		candidates = append(candidates,
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		)
	case "windows":
		for _, root := range []string{os.Getenv("PROGRAMFILES"), os.Getenv("PROGRAMFILES(X86)"), os.Getenv("LOCALAPPDATA")} {
			if root != "" {
				candidates = append(candidates,
					filepath.Join(root, "Google", "Chrome", "Application", "chrome.exe"),
					filepath.Join(root, "Microsoft", "Edge", "Application", "msedge.exe"),
				)
			}
		}
	default:
		candidates = append(candidates, "google-chrome", "google-chrome-stable", "chromium", "chromium-browser")
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if strings.ContainsRune(candidate, os.PathSeparator) {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
			continue
		}
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("Chrome/Chromium not found; set LINEGO_VERIFICATION_BROWSER")
}

func waitDevToolsURL(ctx context.Context, stderr io.Reader, processDone <-chan error) (string, error) {
	result := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if index := strings.Index(line, "DevTools listening on "); index >= 0 {
				result <- strings.TrimSpace(line[index+len("DevTools listening on "):])
				return
			}
		}
		close(result)
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case err := <-processDone:
		if err == nil {
			return "", fmt.Errorf("Chrome closed before DevTools started")
		}
		return "", fmt.Errorf("Chrome failed before DevTools started: %w", err)
	case value := <-result:
		if !strings.HasPrefix(value, "ws://") {
			return "", fmt.Errorf("Chrome did not expose a DevTools WebSocket URL")
		}
		return value, nil
	}
}

type cdpMessage struct {
	ID        int64           `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Error     *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type cdpClient struct {
	connection *websocket.Conn
	writeMu    sync.Mutex
	pendingMu  sync.Mutex
	pending    map[int64]chan cdpMessage
	events     chan cdpMessage
	nextID     atomic.Int64
	closeOnce  sync.Once
}

func newCDPClient(ctx context.Context, endpoint string) (*cdpClient, error) {
	connection, _, err := websocket.DefaultDialer.DialContext(ctx, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("connect Chrome DevTools: %w", err)
	}
	client := &cdpClient{
		connection: connection,
		pending:    make(map[int64]chan cdpMessage),
		events:     make(chan cdpMessage, 64),
	}
	go client.readLoop()
	return client, nil
}

func (c *cdpClient) send(ctx context.Context, method string, params any, sessionID string) (json.RawMessage, error) {
	id := c.nextID.Add(1)
	response := make(chan cdpMessage, 1)
	c.pendingMu.Lock()
	c.pending[id] = response
	c.pendingMu.Unlock()
	payload := map[string]any{"id": id, "method": method}
	if params != nil {
		payload["params"] = params
	}
	if sessionID != "" {
		payload["sessionId"] = sessionID
	}
	c.writeMu.Lock()
	err := c.connection.WriteJSON(payload)
	c.writeMu.Unlock()
	if err != nil {
		c.removePending(id)
		return nil, fmt.Errorf("send Chrome DevTools %s: %w", method, err)
	}
	select {
	case <-ctx.Done():
		c.removePending(id)
		return nil, ctx.Err()
	case message, ok := <-response:
		if !ok {
			return nil, fmt.Errorf("Chrome DevTools closed during %s", method)
		}
		if message.Error != nil {
			return nil, fmt.Errorf("Chrome DevTools %s: %s", method, message.Error.Message)
		}
		return message.Result, nil
	}
}

func (c *cdpClient) readLoop() {
	defer c.close()
	for {
		var message cdpMessage
		if err := c.connection.ReadJSON(&message); err != nil {
			return
		}
		if message.ID != 0 {
			c.pendingMu.Lock()
			response := c.pending[message.ID]
			delete(c.pending, message.ID)
			c.pendingMu.Unlock()
			if response != nil {
				response <- message
				close(response)
			}
			continue
		}
		select {
		case c.events <- message:
		default:
		}
	}
}

func (c *cdpClient) removePending(id int64) {
	c.pendingMu.Lock()
	delete(c.pending, id)
	c.pendingMu.Unlock()
}

func (c *cdpClient) close() {
	c.closeOnce.Do(func() {
		_ = c.connection.Close()
		c.pendingMu.Lock()
		for id, response := range c.pending {
			close(response)
			delete(c.pending, id)
		}
		c.pendingMu.Unlock()
		close(c.events)
	})
}

func eventURL(event cdpMessage) string {
	var payload struct {
		URL     string `json:"url"`
		Request *struct {
			URL string `json:"url"`
		} `json:"request"`
		Frame *struct {
			URL string `json:"url"`
		} `json:"frame"`
	}
	if err := json.Unmarshal(event.Params, &payload); err != nil {
		return ""
	}
	if payload.URL != "" {
		return payload.URL
	}
	if payload.Request != nil {
		return payload.Request.URL
	}
	if payload.Frame != nil {
		return payload.Frame.URL
	}
	return ""
}
