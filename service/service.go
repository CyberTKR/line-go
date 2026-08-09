package service

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/CyberTKR/line-go/protocol"
	"github.com/CyberTKR/line-go/transport"
)

type Error struct {
	Method  string
	Details any
}

func (e *Error) Error() string {
	if code, ok := e.Code(); ok {
		if code == 8 && e.Reason() == "V3_TOKEN_CLIENT_LOGGED_OUT" {
			return fmt.Sprintf("%s: LINE session was closed code=8 reason=V3_TOKEN_CLIENT_LOGGED_OUT; QR login is required", e.Method)
		}
		if e.Method == "refresh" && code == 1000 {
			return fmt.Sprintf("refresh: LINE rejected the refresh token code=1000 reason=%v; QR login is required", detailField(e.Details, 2))
		}
	}
	return fmt.Sprintf("%s: LINE service exception: %#v", e.Method, e.Details)
}

func detailField(details any, id int16) any {
	fields, _ := details.(map[int16]any)
	return fields[id]
}

func (e *Error) Code() (int64, bool) {
	details, ok := e.Details.(map[int16]any)
	if !ok {
		return 0, false
	}
	code, ok := details[1].(int64)
	return code, ok
}

func (e *Error) Reason() string {
	details, ok := e.Details.(map[int16]any)
	if !ok {
		return ""
	}
	reason, _ := details[2].(string)
	return reason
}

type Service struct {
	transport *transport.Client
	path      string
	sequence  atomic.Uint64
	access    atomic.Value
	refresh   func(context.Context, string) (string, error)
}

func New(client *transport.Client, path string) *Service {
	return &Service{transport: client, path: path}
}

func (s *Service) Call(ctx context.Context, method string, fields []protocol.Field, accessToken string) (any, error) {
	return s.call(ctx, method, fields, accessToken, false)
}

func (s *Service) SetAccessToken(token string) {
	if token != "" {
		s.access.Store(token)
	}
}

func (s *Service) SetTokenRefresher(refresh func(context.Context, string) (string, error)) {
	s.refresh = refresh
}

func (s *Service) call(ctx context.Context, method string, fields []protocol.Field, accessToken string, retried bool) (any, error) {
	if current, ok := s.access.Load().(string); ok && current != "" {
		accessToken = current
	}
	sequenceID := s.sequence.Add(1)
	payload, err := protocol.EncodeCall(method, fields, sequenceID)
	if err != nil {
		return nil, fmt.Errorf("%s request could not be encoded: %w", method, err)
	}
	body, err := s.transport.Post(ctx, s.path, payload, accessToken)
	if err != nil {
		if !retried && s.refresh != nil && refreshableHTTPError(err) {
			newToken, refreshErr := s.refresh(ctx, accessToken)
			if refreshErr != nil {
				return nil, fmt.Errorf("%s access token yenileme: %w", method, refreshErr)
			}
			s.SetAccessToken(newToken)
			return s.call(ctx, method, fields, newToken, true)
		}
		return nil, err
	}
	message, err := protocol.DecodeMessage(body)
	if err != nil {
		return nil, fmt.Errorf("%s response could not be decoded: %w", method, err)
	}
	if message.Type == 3 {
		return nil, fmt.Errorf("%s: thrift application exception: %#v", method, message.Fields)
	}
	if message.Type != 2 {
		return nil, fmt.Errorf("%s: unexpected Thrift message type %d", method, message.Type)
	}
	if message.Name != method || message.SequenceID != sequenceID {
		return nil, fmt.Errorf("%s: mismatched thrift response (%q, seq=%d)", method, message.Name, message.SequenceID)
	}
	if result, ok := message.Fields[0]; ok {
		return result, nil
	}
	if details, ok := message.Fields[1]; ok {
		serviceErr := &Error{Method: method, Details: details}
		if !retried && s.refresh != nil && refreshableServiceError(serviceErr) {
			newToken, refreshErr := s.refresh(ctx, accessToken)
			if refreshErr != nil {
				return nil, fmt.Errorf("%s access token yenileme: %w", method, refreshErr)
			}
			s.SetAccessToken(newToken)
			return s.call(ctx, method, fields, newToken, true)
		}
		return nil, serviceErr
	}
	if len(message.Fields) == 0 {
		return nil, nil
	}
	return nil, fmt.Errorf("%s: result field is missing: %#v", method, message.Fields)
}

func refreshableServiceError(err *Error) bool {
	code, ok := err.Code()
	if !ok {
		return false
	}
	return code == 119
}

func refreshableHTTPError(err error) bool {
	var httpErr *transport.HTTPError
	return errors.As(err, &httpErr) && httpErr.Status == 401
}
