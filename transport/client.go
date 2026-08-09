package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPError struct {
	Status int
	Body   []byte
}

func (e *HTTPError) Error() string {
	preview := e.Body
	if len(preview) > 300 {
		preview = preview[:300]
	}
	return fmt.Sprintf("LINE HTTP %d: %q", e.Status, preview)
}

type Client struct {
	host        *url.URL
	application string
	userAgent   string
	language    string
	timeout     time.Duration
	http        *http.Client
}

func New(host, application, userAgent, language string, timeout time.Duration) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimRight(host, "/"))
	if err != nil {
		return nil, fmt.Errorf("LINE host adresi: %w", err)
	}
	if baseURL.Scheme != "https" && baseURL.Scheme != "http" {
		return nil, fmt.Errorf("LINE host scheme must be http or https")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	httpTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   64,
		MaxConnsPerHost:       128,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &Client{
		host:        baseURL,
		application: application,
		userAgent:   userAgent,
		language:    language,
		timeout:     timeout,
		http:        &http.Client{Transport: httpTransport},
	}, nil
}

func (c *Client) Post(ctx context.Context, path string, payload []byte, accessToken string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	isLongPoll := strings.Trim(strings.ToUpper(path), "/") == "SYNC4"
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && c.timeout > 0 && !isLongPoll {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	endpoint := *c.host
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/" + strings.TrimLeft(path, "/")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("LINE request: %w", err)
	}
	request.Header.Set("accept", "application/x-thrift")
	request.Header.Set("content-type", "application/x-thrift; protocol=TCOMPACT")
	request.Header.Set("user-agent", c.userAgent)
	request.Header.Set("x-line-application", c.application)
	request.Header.Set("x-lal", c.language)
	request.Header.Set("x-lpv", "1")
	request.Header.Set("x-lhm", http.MethodPost)
	if accessToken != "" {
		request.Header.Set("x-line-access", accessToken)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("LINE connection error: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("LINE response could not be read: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &HTTPError{Status: response.StatusCode, Body: body}
	}
	return body, nil
}

func (c *Client) CloseIdleConnections() { c.http.CloseIdleConnections() }
