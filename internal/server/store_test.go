package server

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNewStore(t *testing.T) {
	dir := t.TempDir()

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if store == nil {
		t.Fatal("NewStore returned nil store")
	}

	// keys.json may not exist yet; store should be usable
	if keys := store.ListUsernames(); len(keys) != 0 {
		t.Errorf("fresh store should have no users, got %v", keys)
	}
}

func TestNewStore_createsOfflineDir(t *testing.T) {
	dir := t.TempDir()

	_, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	offlineDir := filepath.Join(dir, "offline")
	if _, err := os.Stat(offlineDir); os.IsNotExist(err) {
		t.Errorf("NewStore should create offline dir at %s", offlineDir)
	}
}

func TestStore_Register_GetPubKey_ListUsernames(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := store.Register("alice", "pk-alice"); err != nil {
		t.Fatalf("Register alice: %v", err)
	}

	pk, ok := store.GetPubKey("alice")
	if !ok {
		t.Fatal("GetPubKey alice: not found")
	}
	if pk != "pk-alice" {
		t.Errorf("GetPubKey alice: got %q", pk)
	}

	names := store.ListUsernames()
	if want := []string{"alice"}; !reflect.DeepEqual(names, want) {
		t.Errorf("ListUsernames: got %v", names)
	}

	// second user
	if err := store.Register("bob", "pk-bob"); err != nil {
		t.Fatalf("Register bob: %v", err)
	}
	pk, ok = store.GetPubKey("bob")
	if !ok || pk != "pk-bob" {
		t.Errorf("GetPubKey bob: ok=%v pk=%q", ok, pk)
	}
	names = store.ListUsernames()
	if len(names) != 2 {
		t.Errorf("ListUsernames: got %v", names)
	}
}

func TestStore_Register_sameKeyIdempotent(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := store.Register("alice", "pk-alice"); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := store.Register("alice", "pk-alice"); err != nil {
		t.Fatalf("second Register same key: %v", err)
	}

	pk, ok := store.GetPubKey("alice")
	if !ok || pk != "pk-alice" {
		t.Errorf("GetPubKey: ok=%v pk=%q", ok, pk)
	}
}

func TestStore_Register_duplicateKeyReturnsError(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := store.Register("alice", "pk-alice"); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	err = store.Register("alice", "pk-alice-different")
	if err == nil {
		t.Fatal("Register with different key should fail")
	}
	if !errors.Is(err, ErrDuplicateUsername) {
		t.Errorf("expected ErrDuplicateUsername, got %v", err)
	}

	// key should be unchanged
	pk, ok := store.GetPubKey("alice")
	if !ok || pk != "pk-alice" {
		t.Errorf("key should be unchanged: ok=%v pk=%q", ok, pk)
	}
}

func TestStore_GetPubKeys(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	_ = store.Register("a", "pk-a")
	_ = store.Register("b", "pk-b")
	_ = store.Register("c", "pk-c")

	got := store.GetPubKeys([]string{"a", "missing", "b", "also-missing", "c"})
	want := map[string]string{"a": "pk-a", "b": "pk-b", "c": "pk-c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetPubKeys: got %v", got)
	}
}

func TestStore_GetPubKeys_emptyInput(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	got := store.GetPubKeys(nil)
	if len(got) != 0 {
		t.Errorf("GetPubKeys(nil): got %v", got)
	}
	got = store.GetPubKeys([]string{})
	if len(got) != 0 {
		t.Errorf("GetPubKeys([]): got %v", got)
	}
}

func TestStore_QueueOffline_GetOffline_DeleteOffline(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	recipient := "bob"
	if err := store.QueueOffline(recipient, "msg1", "alice", "payload1", "nonce1", 1000); err != nil {
		t.Fatalf("QueueOffline: %v", err)
	}
	if err := store.QueueOffline(recipient, "msg2", "alice", "payload2", "nonce2", 1001); err != nil {
		t.Fatalf("QueueOffline: %v", err)
	}

	msgs, err := store.GetOffline(recipient)
	if err != nil {
		t.Fatalf("GetOffline: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("GetOffline: got %d messages", len(msgs))
	}

	// order may vary; check ids
	ids := make(map[string]bool)
	for _, m := range msgs {
		if id, ok := m["id"].(string); ok {
			ids[id] = true
		}
	}
	if !ids["msg1"] || !ids["msg2"] {
		t.Errorf("GetOffline: expected msg1 and msg2, got %v", ids)
	}

	if err := store.DeleteOffline(recipient, []string{"msg1", "msg2"}); err != nil {
		t.Fatalf("DeleteOffline: %v", err)
	}

	msgs, err = store.GetOffline(recipient)
	if err != nil {
		t.Fatalf("GetOffline after delete: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("GetOffline after delete: got %d messages", len(msgs))
	}
}

func TestStore_GetOffline_noDirReturnsNil(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	msgs, err := store.GetOffline("nonexistent")
	if err != nil {
		t.Fatalf("GetOffline: %v", err)
	}
	if msgs != nil {
		t.Errorf("GetOffline(nonexistent): expected nil, got %v", msgs)
	}
}

func TestStore_pathValidation(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Invalid recipient or msgID rejected by QueueOffline
	if err := store.QueueOffline("bad/recipient", "msg1", "a", "p", "n", 0); err == nil {
		t.Error("QueueOffline with path sep in recipient should fail")
	}
	if err := store.QueueOffline("bob", "bad/id", "a", "p", "n", 0); err == nil {
		t.Error("QueueOffline with path sep in msgID should fail")
	}

	// Invalid recipient returns nil from GetOffline
	msgs, err := store.GetOffline("bad..recipient")
	if err != nil {
		t.Fatalf("GetOffline: %v", err)
	}
	if msgs != nil {
		t.Errorf("GetOffline(invalid recipient): expected nil, got %v", msgs)
	}
}
