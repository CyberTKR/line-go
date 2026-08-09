package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Session struct {
	AccessToken    string      `json:"access_token"`
	RefreshToken   string      `json:"refresh_token,omitempty"`
	Application    string      `json:"application,omitempty"`
	UserAgent      string      `json:"user_agent,omitempty"`
	TokenRefreshAt int64       `json:"token_refresh_at,omitempty"`
	Certificate    string      `json:"certificate,omitempty"`
	MID            string      `json:"mid,omitempty"`
	QRPrivateKey   string      `json:"qr_private_key,omitempty"`
	E2EEMetadata   any         `json:"e2ee_metadata,omitempty"`
	DeviceKeys     []DeviceKey `json:"device_keys,omitempty"`
	SyncState      SyncState   `json:"sync_state"`
}

type DeviceKey struct {
	KeyID      int32  `json:"key_id"`
	Version    int32  `json:"version"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type SyncState struct {
	Revision           int64 `json:"revision"`
	GlobalRevision     int64 `json:"global_revision"`
	IndividualRevision int64 `json:"individual_revision"`
}

type File struct{ Path string }

func (f File) Load() (Session, error) {
	data, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Session{}, nil
	}
	if err != nil {
		return Session{}, fmt.Errorf("session could not be read: %w", err)
	}
	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return Session{}, fmt.Errorf("session JSON is invalid: %w", err)
	}
	return session, nil
}

func (f File) Save(session Session) error {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("session could not be encoded: %w", err)
	}
	directory := filepath.Dir(f.Path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("session directory could not be created: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".session-*.tmp")
	if err != nil {
		return fmt.Errorf("temporary session could not be created: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("session could not be written: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("session could not be synced to disk: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, f.Path); err != nil {
		return fmt.Errorf("session could not be replaced: %w", err)
	}
	return nil
}
