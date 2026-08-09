package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/CyberTKR/line-go/api"
	"github.com/CyberTKR/line-go/config"
	"github.com/CyberTKR/line-go/e2ee"
	"github.com/CyberTKR/line-go/service"
	"github.com/CyberTKR/line-go/storage"
	"github.com/CyberTKR/line-go/transport"
)

type Client struct {
	Config        config.Config
	Session       storage.Session
	Transport     *transport.Client
	Talk          *service.Talk
	E2EE          *e2ee.Manager
	tokenRefresh  *service.AccessTokenRefresh
	store         storage.File
	refreshMu     sync.Mutex
	sessionMu     sync.RWMutex
	syncMu        sync.Mutex
	messageMu     sync.RWMutex
	encrypted     map[string]struct{}
	contactMu     sync.RWMutex
	contacts      map[string]struct{}
	contactsUntil time.Time
}

func Open(configuration config.Config) (*Client, error) {
	store := storage.File{Path: configuration.SessionPath}
	session, err := store.Load()
	if err != nil {
		return nil, err
	}
	if session.AccessToken == "" {
		return nil, fmt.Errorf("no saved session; run 'linego qr' or 'linego register' first")
	}
	if session.Application != "" {
		configuration.Application = session.Application
	}
	if session.UserAgent != "" {
		configuration.UserAgent = session.UserAgent
	}
	httpClient, err := transport.New(configuration.Host, configuration.Application, configuration.UserAgent, configuration.Language, configuration.Timeout)
	if err != nil {
		return nil, err
	}
	client := &Client{
		Config: configuration, Session: session, Transport: httpClient,
		Talk: service.NewTalk(httpClient), tokenRefresh: service.NewAccessTokenRefresh(httpClient), store: store,
		encrypted: make(map[string]struct{}), contacts: make(map[string]struct{}),
	}
	client.Talk.SetAccessToken(session.AccessToken)
	client.Talk.SetTokenRefresher(client.refreshExpiredAccessToken)
	client.E2EE = e2ee.New(session, client.Talk)
	return client, nil
}

func (c *Client) Close() { c.Transport.CloseIdleConnections() }

func (c *Client) accessToken() string {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.Session.AccessToken
}

func (c *Client) RefreshAccessToken(ctx context.Context) error {
	_, err := c.refreshAccessToken(ctx, "", true)
	return err
}

func (c *Client) EnsureAccessToken(ctx context.Context) error {
	c.sessionMu.RLock()
	refreshToken := c.Session.RefreshToken
	refreshAt := c.Session.TokenRefreshAt
	accessToken := c.Session.AccessToken
	c.sessionMu.RUnlock()
	if refreshToken == "" {
		return nil
	}
	now := time.Now()
	due := refreshAt > 0 && !now.Before(time.Unix(refreshAt, 0).Add(-time.Minute))
	if refreshAt == 0 {
		if expiry, ok := jwtExpiry(accessToken); ok {
			due = !now.Before(expiry.Add(-5 * time.Minute))
		}
	}
	if !due {
		return nil
	}
	_, err := c.refreshAccessToken(ctx, accessToken, false)
	return err
}

func (c *Client) refreshExpiredAccessToken(ctx context.Context, failedToken string) (string, error) {
	return c.refreshAccessToken(ctx, failedToken, false)
}

func (c *Client) refreshAccessToken(ctx context.Context, failedToken string, force bool) (string, error) {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	c.sessionMu.RLock()
	currentToken := c.Session.AccessToken
	refreshToken := c.Session.RefreshToken
	mid := c.Session.MID
	c.sessionMu.RUnlock()
	if !force && failedToken != "" && currentToken != failedToken {
		c.debugf("token refresh skipped reason=already_rotated access_fp=%s", tokenFingerprint(currentToken))
		return currentToken, nil
	}
	if refreshToken == "" {
		return "", fmt.Errorf("session does not contain a refresh token")
	}
	started := time.Now()
	c.debugf("token refresh started endpoint=%s mid=%s force=%t access_fp=%s refresh_fp=%s", api.TokenRefreshPath, mid, force, tokenFingerprint(currentToken), tokenFingerprint(refreshToken))
	response, err := c.tokenRefresh.Refresh(ctx, refreshToken, currentToken)
	if err != nil {
		c.debugf("token refresh failed endpoint=%s elapsed_ms=%.1f error=%v", api.TokenRefreshPath, float64(time.Since(started).Microseconds())/1000, err)
		return "", fmt.Errorf("LINE token refresh failed: %w", err)
	}
	issueTime := response.TokenIssueTimeEpochSec
	if issueTime <= 0 {
		issueTime = time.Now().Unix()
	}

	c.sessionMu.Lock()
	c.Session.AccessToken = response.AccessToken
	if response.RefreshToken != "" {
		c.Session.RefreshToken = response.RefreshToken
	}
	if response.DurationUntilRefreshInSec > 0 {
		c.Session.TokenRefreshAt = issueTime + response.DurationUntilRefreshInSec
	} else {
		c.Session.TokenRefreshAt = 0
	}
	refreshAt := c.Session.TokenRefreshAt
	c.Talk.SetAccessToken(response.AccessToken)
	saveErr := c.store.Save(c.Session)
	c.sessionMu.Unlock()
	if saveErr != nil {
		return "", fmt.Errorf("yenilenen token session'a kaydedilemedi: %w", saveErr)
	}
	c.debugf("token refresh completed endpoint=%s elapsed_ms=%.1f access_fp=%s refresh_rotated=%t refresh_at=%d", api.TokenRefreshPath, float64(time.Since(started).Microseconds())/1000, tokenFingerprint(response.AccessToken), response.RefreshToken != "" && response.RefreshToken != refreshToken, refreshAt)
	return response.AccessToken, nil
}

func (c *Client) debugf(format string, arguments ...any) {
	if c.Config.Debug {
		log.Printf("DEBUG linego.client | "+format, arguments...)
	}
}

func tokenFingerprint(token string) string {
	if token == "" {
		return "none"
	}
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("sha256:%x", sum[:4])
}

func jwtExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Expires int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Expires <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Expires, 0), true
}

func (c *Client) BootstrapLatestRevision(ctx context.Context) (int64, int64, error) {
	latest, err := c.Talk.GetLastOpRevision(ctx, c.accessToken())
	if err != nil {
		return c.Session.SyncState.Revision, 0, err
	}
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	previous := c.Session.SyncState.Revision
	if latest > previous {
		c.Session.SyncState.Revision = latest
		if err := c.store.Save(c.Session); err != nil {
			return previous, latest, err
		}
	}
	return previous, latest, nil
}

func (c *Client) GetProfile(ctx context.Context) (service.Profile, error) {
	return c.Talk.GetProfile(ctx, c.accessToken())
}

func (c *Client) SyncE2EESelfKey(ctx context.Context) (bool, error) {
	key, changed, err := c.E2EE.SyncSelfKey(ctx)
	if err != nil || !changed {
		return changed, err
	}
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	c.Session.DeviceKeys = append(c.Session.DeviceKeys, key)
	if err := c.store.Save(c.Session); err != nil {
		return false, fmt.Errorf("new E2EE device key could not be registered: %w", err)
	}
	return true, nil
}

func (c *Client) SyncOnce(ctx context.Context, count int32) ([]Operation, bool, error) {
	if count <= 0 {
		return nil, false, fmt.Errorf("sync count must be positive")
	}
	if err := c.EnsureAccessToken(ctx); err != nil {
		return nil, false, err
	}
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	c.sessionMu.RLock()
	state := c.Session.SyncState
	c.sessionMu.RUnlock()
	result, err := c.Talk.Sync(ctx, c.accessToken(), state.Revision, count, state.GlobalRevision, state.IndividualRevision)
	if err != nil {
		return nil, false, err
	}
	response, ok := result.(map[int16]any)
	if !ok {
		return nil, false, fmt.Errorf("sync: unexpected result %T", result)
	}
	var operations []Operation
	hasMore := false
	if operationResponse, ok := response[1].(map[int16]any); ok {
		rawOperations, _ := operationResponse[1].([]any)
		for _, raw := range rawOperations {
			operation, ok := parseOperation(raw)
			if !ok {
				continue
			}
			if operation.Revision > state.Revision {
				state.Revision = operation.Revision
			}
			operations = append(operations, operation)
		}
		hasMore, _ = operationResponse[2].(bool)
		if events, ok := operationResponse[3].(map[int16]any); ok {
			state.GlobalRevision = int64Field(events, 2)
		}
		if events, ok := operationResponse[4].(map[int16]any); ok {
			state.IndividualRevision = int64Field(events, 2)
		}
	} else if fullSync, ok := response[2].(map[int16]any); ok {
		if revision := int64Field(fullSync, 2); revision > 0 {
			state.Revision = revision
		}
	}
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	c.Session.SyncState = state
	if err := c.store.Save(c.Session); err != nil {
		return nil, false, fmt.Errorf("sync revision kaydedilemedi: %w", err)
	}
	return operations, hasMore, nil
}

type Handler func(context.Context, Operation, *Client) error

type ListenOptions struct {
	Count           int32
	Workers         int
	CriticalWorkers int
	UrgentWorkers   int
	IdleDelay       time.Duration
	RetryDelay      time.Duration
	MaxRetryDelay   time.Duration
	Logger          *log.Logger
}

func (c *Client) Listen(ctx context.Context, handler Handler, options ListenOptions) error {
	if options.Count <= 0 {
		options.Count = 100
	}
	if options.Workers <= 0 {
		options.Workers = 1
	}
	if options.CriticalWorkers <= 0 {
		options.CriticalWorkers = 2
	}
	if options.UrgentWorkers <= 0 {
		options.UrgentWorkers = 2
	}
	if options.IdleDelay <= 0 {
		options.IdleDelay = 100 * time.Millisecond
	}
	if options.RetryDelay <= 0 {
		options.RetryDelay = time.Second
	}
	if options.MaxRetryDelay < options.RetryDelay {
		options.MaxRetryDelay = 30 * time.Second
	}
	if options.Logger == nil {
		options.Logger = log.Default()
	}

	jobs := make(chan Operation, options.Workers*8)
	criticalJobs := make(chan Operation, options.CriticalWorkers*8)
	invitationJobs := make(chan Operation, options.UrgentWorkers*4)
	kickJobs := make(chan Operation, options.UrgentWorkers*4)
	var workers sync.WaitGroup
	startWorkers := func(count int, queue <-chan Operation) {
		for workerID := 0; workerID < count; workerID++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for operation := range queue {
					if err := handler(ctx, operation, c); err != nil {
						options.Logger.Printf("handler error revision=%d op.type=%d: %v", operation.Revision, operation.Type, err)
					}
				}
			}()
		}
	}
	startWorkers(options.Workers, jobs)
	startWorkers(options.CriticalWorkers, criticalJobs)
	startWorkers(options.UrgentWorkers, invitationJobs)
	startWorkers(options.UrgentWorkers, kickJobs)
	defer func() {
		close(jobs)
		close(criticalJobs)
		close(invitationJobs)
		close(kickJobs)
		workers.Wait()
	}()

	retry := options.RetryDelay
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		operations, hasMore, err := c.SyncOnce(ctx, options.Count)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isGracefulGOAWAY(err) {
				c.Transport.CloseIdleConnections()
				reconnectDelay := 150*time.Millisecond + time.Duration(rand.Int63n(int64(350*time.Millisecond)))
				options.Logger.Printf("SYNC4 connection rotated reason=GOAWAY_NO_ERROR revision=%d reconnect_in=%s", c.Session.SyncState.Revision, reconnectDelay)
				retry = options.RetryDelay
				if !wait(ctx, reconnectDelay) {
					return nil
				}
				continue
			}
			var httpError *transport.HTTPError
			if errors.As(err, &httpError) && httpError.Status == 410 {
				options.Logger.Printf("SYNC4 refresh status=410 revision=%d", c.Session.SyncState.Revision)
				retry = options.RetryDelay
				if !wait(ctx, retry) {
					return nil
				}
				continue
			}
			var serviceError *service.Error
			if errors.As(err, &serviceError) {
				return err
			}
			options.Logger.Printf("SYNC4 connection error=%v retry_in=%s", err, retry)
			if !wait(ctx, retry) {
				return nil
			}
			retry *= 2
			if retry > options.MaxRetryDelay {
				retry = options.MaxRetryDelay
			}
			continue
		}
		retry = options.RetryDelay
		for _, operationType := range []int32{133, 124} {
			queue := kickJobs
			if operationType == 124 {
				queue = invitationJobs
			}
			for _, operation := range operations {
				if operation.Type == operationType && !enqueueOperation(ctx, queue, operation) {
					return nil
				}
			}
		}
		for _, operation := range operations {
			if criticalOperation(operation.Type) && !enqueueOperation(ctx, criticalJobs, operation) {
				return nil
			}
		}
		for _, operation := range operations {
			if !urgentOperation(operation.Type) && !criticalOperation(operation.Type) && !enqueueOperation(ctx, jobs, operation) {
				return nil
			}
		}
		if len(operations) == 0 && !hasMore && !wait(ctx, options.IdleDelay) {
			return nil
		}
	}
}

func enqueueOperation(ctx context.Context, queue chan<- Operation, operation Operation) bool {
	select {
	case queue <- operation:
		return true
	case <-ctx.Done():
		return false
	}
}

func urgentOperation(operationType int32) bool {
	return operationType == 124 || operationType == 133
}

func criticalOperation(operationType int32) bool {
	switch operationType {
	case 60, 122, 126:
		return true
	default:
		return false
	}
}

func isGracefulGOAWAY(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "goaway") && strings.Contains(message, "no_error")
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
