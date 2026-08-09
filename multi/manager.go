package multi

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	lineclient "github.com/CyberTKR/line-go/client"
	"github.com/CyberTKR/line-go/config"
)

type Account struct {
	Name        string `json:"name"`
	SessionPath string `json:"session"`
	Workers     int    `json:"workers"`
	Host        string `json:"host,omitempty"`
	AppName     string `json:"appName,omitempty"`
	UserAgent   string `json:"userAgent,omitempty"`
	Role        string `json:"role,omitempty"`
}

type FileConfig struct {
	Accounts []Account `json:"accounts"`
}

type Handler func(context.Context, string, lineclient.Operation, *lineclient.Client) error

type Manager struct {
	Base     config.Config
	Accounts []Account
	Logger   *log.Logger
	OnReady  func(string, *lineclient.Client) error
}

func (m Manager) Check(ctx context.Context) error {
	logger := m.Logger
	if logger == nil {
		logger = log.Default()
	}
	for _, account := range m.Accounts {
		configuration := m.accountConfig(account)
		client, err := lineclient.Open(configuration)
		if err != nil {
			return fmt.Errorf("account %s: %w", account.Name, err)
		}
		if err := client.EnsureAccessToken(ctx); err != nil {
			client.Close()
			return fmt.Errorf("account %s token refresh: %w", account.Name, err)
		}
		profile, profileErr := client.GetProfile(ctx)
		if profileErr == nil && m.OnReady != nil {
			profileErr = m.OnReady(account.Name, client)
		}
		client.Close()
		if profileErr != nil {
			return fmt.Errorf("account %s check: %w", account.Name, profileErr)
		}
		logger.Printf("account=%s profile=%q check=ok", account.Name, profile.DisplayName)
	}
	return nil
}

func Load(path string) (FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FileConfig{}, fmt.Errorf("multi-account config could not be read: %w", err)
	}
	var result FileConfig
	if err := json.Unmarshal(data, &result); err != nil {
		return FileConfig{}, fmt.Errorf("multi-account config is invalid: %w", err)
	}
	if len(result.Accounts) == 0 {
		return FileConfig{}, fmt.Errorf("multi-account config contains no accounts")
	}
	return result, nil
}

func (m Manager) Run(ctx context.Context, handler Handler) error {
	logger := m.Logger
	if logger == nil {
		logger = log.Default()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errors := make(chan error, len(m.Accounts))
	var group sync.WaitGroup
	for _, account := range m.Accounts {
		account := account
		group.Add(1)
		go func() {
			defer group.Done()
			configuration := m.accountConfig(account)
			client, err := lineclient.Open(configuration)
			if err != nil {
				errors <- fmt.Errorf("account %s: %w", account.Name, err)
				return
			}
			defer client.Close()
			if err := client.EnsureAccessToken(ctx); err != nil {
				errors <- fmt.Errorf("account %s token refresh: %w", account.Name, err)
				return
			}
			profile, err := client.GetProfile(ctx)
			if err != nil {
				errors <- fmt.Errorf("account %s getProfile: %w", account.Name, err)
				return
			}
			previousRevision, latestRevision, err := client.BootstrapLatestRevision(ctx)
			if err != nil {
				errors <- fmt.Errorf("account %s revision bootstrap: %w", account.Name, err)
				return
			}
			logger.Printf("account=%s revision bootstrap previous=%d latest=%d skipped=%d", account.Name, previousRevision, latestRevision, max(latestRevision-previousRevision, 0))
			keyChanged, err := client.SyncE2EESelfKey(ctx)
			if err != nil {
				errors <- fmt.Errorf("account %s E2EE self key sync: %w", account.Name, err)
				return
			}
			if keyChanged {
				logger.Printf("account=%s E2EE self key registered and session saved", account.Name)
			}
			if m.OnReady != nil {
				if err := m.OnReady(account.Name, client); err != nil {
					errors <- fmt.Errorf("account %s ready hook: %w", account.Name, err)
					return
				}
			}
			workers := account.Workers
			if workers <= 0 {
				workers = 8
			}
			logger.Printf("account=%s profile=%q workers=%d revision=%d started", account.Name, profile.DisplayName, workers, client.Session.SyncState.Revision)
			err = client.Listen(ctx, func(handlerContext context.Context, operation lineclient.Operation, current *lineclient.Client) error {
				return handler(handlerContext, account.Name, operation, current)
			}, lineclient.ListenOptions{Workers: workers, Count: 100, Logger: logger})
			if err != nil {
				errors <- fmt.Errorf("account %s listener: %w", account.Name, err)
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		group.Wait()
		return nil
	case err := <-errors:
		cancel()
		group.Wait()
		return err
	case <-done:
		return nil
	}
}

func (m Manager) accountConfig(account Account) config.Config {
	configuration := m.Base
	configuration.SessionPath = account.SessionPath
	if account.Host != "" {
		configuration.Host = account.Host
	}
	if account.AppName != "" {
		configuration.Application = account.AppName
	}
	if account.UserAgent != "" {
		configuration.UserAgent = account.UserAgent
	}
	return configuration
}
