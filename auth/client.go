package auth

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"

	"github.com/CyberTKR/line-go/service"
	"github.com/CyberTKR/line-go/storage"
)

type Event struct {
	Kind  string
	Value string
}

type Credentials struct {
	AccessToken  string
	RefreshToken string
	Certificate  string
	MID          string
	Metadata     any
	PrivateKey   []byte
}

type Client struct {
	qr   *service.QR
	talk *service.Talk
}

func New(qr *service.QR, talk *service.Talk) *Client {
	return &Client{qr: qr, talk: talk}
}

func (c *Client) LoginQR(ctx context.Context, previous storage.Session, emit func(Event)) (Credentials, service.Profile, error) {
	result, err := c.qr.CreateSession(ctx)
	if err != nil {
		return Credentials{}, service.Profile{}, fmt.Errorf("QR session could not be created: %w", err)
	}
	sessionFields, err := structResult("createSession", result)
	if err != nil {
		return Credentials{}, service.Profile{}, err
	}
	sessionID, err := requiredString("createSession", sessionFields, 1)
	if err != nil {
		return Credentials{}, service.Profile{}, err
	}

	result, err = c.qr.CreateSecureCode(ctx, sessionID)
	if err != nil {
		return Credentials{}, service.Profile{}, fmt.Errorf("secure QR could not be created: %w", err)
	}
	qrFields, err := structResult("createQrCodeForSecure", result)
	if err != nil {
		return Credentials{}, service.Profile{}, err
	}
	callback, err := requiredString("createQrCodeForSecure", qrFields, 1)
	if err != nil {
		return Credentials{}, service.Profile{}, err
	}
	nonce, err := requiredString("createQrCodeForSecure", qrFields, 4)
	if err != nil {
		return Credentials{}, service.Profile{}, err
	}

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Credentials{}, service.Profile{}, fmt.Errorf("X25519 key could not be generated: %w", err)
	}
	qrURL, err := secureURL(callback, privateKey.PublicKey().Bytes())
	if err != nil {
		return Credentials{}, service.Profile{}, err
	}
	if emit != nil {
		emit(Event{Kind: "url", Value: qrURL})
	}

	if err := c.qr.CheckCodeVerified(ctx, sessionID); err != nil {
		return Credentials{}, service.Profile{}, fmt.Errorf("QR verification failed: %w", err)
	}

	certificateVerified := false
	err = c.qr.VerifyCertificate(ctx, sessionID, previous.Certificate)
	if err == nil {
		certificateVerified = true
	} else {
		var serviceError *service.Error
		if !errors.As(err, &serviceError) {
			return Credentials{}, service.Profile{}, fmt.Errorf("certificate verification: %w", err)
		}
		code, ok := serviceError.Code()
		if !ok || code != 2 {
			return Credentials{}, service.Profile{}, fmt.Errorf("certificate verification: %w", err)
		}
	}

	if !certificateVerified {
		result, err = c.qr.CreatePIN(ctx, sessionID)
		if err != nil {
			return Credentials{}, service.Profile{}, fmt.Errorf("PIN could not be created: %w", err)
		}
		pinFields, err := structResult("createPinCode", result)
		if err != nil {
			return Credentials{}, service.Profile{}, err
		}
		pin, err := requiredString("createPinCode", pinFields, 1)
		if err != nil {
			return Credentials{}, service.Profile{}, err
		}
		if emit != nil {
			emit(Event{Kind: "pin", Value: pin})
		}
		if err := c.qr.CheckPINVerified(ctx, sessionID); err != nil {
			return Credentials{}, service.Profile{}, fmt.Errorf("PIN verification failed: %w", err)
		}
	}

	result, err = c.qr.LoginV2(ctx, sessionID, "lineapi-go", "Go", nonce)
	if err != nil {
		return Credentials{}, service.Profile{}, fmt.Errorf("QR login could not be completed: %w", err)
	}
	loginFields, err := structResult("qrCodeLoginV2ForSecure", result)
	if err != nil {
		return Credentials{}, service.Profile{}, err
	}
	tokenFields, _ := loginFields[3].(map[int16]any)
	accessToken := optionalString(tokenFields, 1)
	if accessToken == "" {
		accessToken = optionalString(loginFields, 2)
	}
	if accessToken == "" {
		return Credentials{}, service.Profile{}, fmt.Errorf("QR login did not return an access token")
	}
	credentials := Credentials{
		AccessToken:  accessToken,
		RefreshToken: optionalString(tokenFields, 2),
		Certificate:  optionalString(loginFields, 1),
		MID:          optionalString(loginFields, 4),
		Metadata:     normalizeJSON(loginFields[10]),
		PrivateKey:   append([]byte(nil), privateKey.Bytes()...),
	}
	profile, err := c.talk.GetProfile(ctx, accessToken)
	if err != nil {
		return Credentials{}, service.Profile{}, fmt.Errorf("QR token could not be verified with getProfile: %w", err)
	}
	if credentials.MID == "" {
		credentials.MID = profile.MID
	}
	if emit != nil {
		emit(Event{Kind: "authenticated", Value: "ok"})
	}
	return credentials, profile, nil
}

func (c Credentials) Session() storage.Session {
	return storage.Session{
		AccessToken:  c.AccessToken,
		RefreshToken: c.RefreshToken,
		Certificate:  c.Certificate,
		MID:          c.MID,
		QRPrivateKey: hex.EncodeToString(c.PrivateKey),
		E2EEMetadata: c.Metadata,
	}
}

func secureURL(callback string, publicKey []byte) (string, error) {
	parsed, err := url.Parse(callback)
	if err != nil {
		return "", fmt.Errorf("QR callback URL is invalid: %w", err)
	}
	query := parsed.Query()
	query.Set("secret", base64.StdEncoding.EncodeToString(publicKey))
	query.Set("e2eeVersion", "1")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func structResult(method string, value any) (map[int16]any, error) {
	fields, ok := value.(map[int16]any)
	if !ok {
		return nil, fmt.Errorf("%s: unexpected result %T", method, value)
	}
	return fields, nil
}

func requiredString(method string, fields map[int16]any, id int16) (string, error) {
	value := optionalString(fields, id)
	if value == "" {
		return "", fmt.Errorf("%s: required field %d is missing", method, id)
	}
	return value, nil
}

func optionalString(fields map[int16]any, id int16) string {
	if fields == nil {
		return ""
	}
	value, _ := fields[id].(string)
	return value
}

func normalizeJSON(value any) any {
	switch typed := value.(type) {
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[fmt.Sprint(key)] = normalizeJSON(item)
		}
		return result
	case map[int16]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[fmt.Sprint(key)] = normalizeJSON(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = normalizeJSON(item)
		}
		return result
	default:
		return value
	}
}
