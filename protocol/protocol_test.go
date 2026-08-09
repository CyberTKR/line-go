package protocol

import "testing"

func TestCompactCallRoundTrip(t *testing.T) {
	encoded, err := EncodeCall("sync", []Field{
		F(1, String, "chat"),
		F(2, I64, int64(42)),
		F(3, Bool, true),
	}, 7)
	if err != nil {
		t.Fatalf("encode compact call: %v", err)
	}
	message, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("decode compact call: %v", err)
	}
	if message.Name != "sync" || message.SequenceID != 7 {
		t.Fatalf("unexpected message: %#v", message)
	}
	if message.Fields[1] != "chat" || message.Fields[2] != int64(42) || message.Fields[3] != true {
		t.Fatalf("unexpected fields: %#v", message.Fields)
	}
}

func TestBinaryCallRoundTrip(t *testing.T) {
	encoded, err := EncodeBinaryCall("getProfile", []Field{
		F(1, String, "account"),
		F(2, I32, int32(26)),
	}, 9)
	if err != nil {
		t.Fatalf("encode binary call: %v", err)
	}
	message, err := DecodeBinaryMessage(encoded)
	if err != nil {
		t.Fatalf("decode binary call: %v", err)
	}
	if message.Name != "getProfile" || message.SequenceID != 9 {
		t.Fatalf("unexpected message: %#v", message)
	}
	if message.Fields[1] != "account" || message.Fields[2] != int32(26) {
		t.Fatalf("unexpected fields: %#v", message.Fields)
	}
}
