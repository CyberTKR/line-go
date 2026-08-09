package storage

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFileSaveLoadAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "session.json")
	want := Session{
		AccessToken:  "access",
		RefreshToken: "refresh",
		MID:          "u0123456789abcdef",
		SyncState: SyncState{
			Revision:           11,
			GlobalRevision:     12,
			IndividualRevision: 13,
		},
	}
	file := File{Path: path}
	if err := file.Save(want); err != nil {
		t.Fatalf("save session: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat session: %v", err)
	}
	if permission := info.Mode().Perm(); permission != 0o600 {
		t.Fatalf("session permission = %o, want 600", permission)
	}
	got, err := file.Load()
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded session differs: got %#v want %#v", got, want)
	}
}

func TestFileLoadMissing(t *testing.T) {
	got, err := (File{Path: filepath.Join(t.TempDir(), "missing.json")}).Load()
	if err != nil {
		t.Fatalf("load missing session: %v", err)
	}
	if !reflect.DeepEqual(got, Session{}) {
		t.Fatalf("missing session = %#v, want zero value", got)
	}
}
