package registration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CyberTKR/line-go/protocol"
)

func temporaryServiceError(method string) error {
	return &ServiceError{
		Method: method,
		Details: map[int16]any{
			1: int32(0),
			2: "サーバーエラーが発生しました。\n再度お試しください。",
		},
	}
}

func TestJapaneseCodeZeroIsTemporaryAndReadable(t *testing.T) {
	err := temporaryServiceError("getCountryInfo").(*ServiceError)
	if !err.Temporary() {
		t.Fatal("expected code=0 server error to be temporary")
	}
	if message := err.Error(); !strings.Contains(message, "temporary server error") {
		t.Fatalf("unexpected error: %s", message)
	}
}

func TestTransientRetrySucceedsWithoutOpeningANewSession(t *testing.T) {
	calls := 0
	result, err := callWithTransientRetry(
		context.Background(),
		func() (any, error) {
			calls++
			if calls < 3 {
				return nil, temporaryServiceError("getCountryInfo")
			}
			return "ok", nil
		},
		[]time.Duration{0, 0},
		nil,
	)
	if err != nil || result != "ok" || calls != 3 {
		t.Fatalf("result=%v err=%v calls=%d", result, err, calls)
	}
}

func TestTransientRetryDoesNotRetryPermanentErrors(t *testing.T) {
	calls := 0
	permanent := errors.New("permanent")
	_, err := callWithTransientRetry(
		context.Background(),
		func() (any, error) {
			calls++
			return nil, permanent
		},
		[]time.Duration{0, 0},
		nil,
	)
	if !errors.Is(err, permanent) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestCountryInfoOmitsIncompleteSIMProfile(t *testing.T) {
	encoded, err := protocol.EncodeBinaryCall(
		"getCountryInfo",
		buildCountryInfoFields("session", "TW", "", ""),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	message, err := protocol.DecodeBinaryMessage(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := message.Fields[11]; exists {
		t.Fatal("simCard must be omitted when no complete SIM profile is configured")
	}
	if message.Fields[1] != "session" {
		t.Fatalf("unexpected auth session: %#v", message.Fields[1])
	}
}

func TestCountryInfoIncludesCompleteSIMProfile(t *testing.T) {
	encoded, err := protocol.EncodeBinaryCall(
		"getCountryInfo",
		buildCountryInfoFields("session", "TW", "46692", "Chunghwa"),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	message, err := protocol.DecodeBinaryMessage(encoded)
	if err != nil {
		t.Fatal(err)
	}
	simCard, ok := message.Fields[11].(map[int16]any)
	if !ok {
		t.Fatalf("unexpected simCard: %#v", message.Fields[11])
	}
	if simCard[1] != "TW" || simCard[2] != "46692" || simCard[3] != "Chunghwa" {
		t.Fatalf("unexpected simCard fields: %#v", simCard)
	}
}
