package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestNewStore_createsGroupsDir(t *testing.T) {
	dir := t.TempDir()

	_, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	groupsDir := filepath.Join(dir, "groups")
	if _, err := os.Stat(groupsDir); os.IsNotExist(err) {
		t.Errorf("NewStore should create groups dir at %s", groupsDir)
	}
}

func TestStore_CreateGroup_GetGroup_UpdateGroupMembers_ListGroupsForUser_DeleteGroup(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := store.CreateGroup("g1", "Team", []string{"alice", "bob"}, "alice"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	g, err := store.GetGroup("g1")
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if g == nil {
		t.Fatal("GetGroup: expected group, got nil")
	}
	if g.ID != "g1" || g.Name != "Team" || g.CreatedBy != "alice" {
		t.Errorf("GetGroup: got %+v", g)
	}
	if !reflect.DeepEqual(g.Members, []string{"alice", "bob"}) {
		t.Errorf("GetGroup Members: got %v", g.Members)
	}

	list, err := store.ListGroupsForUser("alice")
	if err != nil {
		t.Fatalf("ListGroupsForUser: %v", err)
	}
	if len(list) != 1 || list[0].ID != "g1" {
		t.Errorf("ListGroupsForUser(alice): got %v", list)
	}
	list, _ = store.ListGroupsForUser("bob")
	if len(list) != 1 {
		t.Errorf("ListGroupsForUser(bob): got %v", list)
	}
	list, _ = store.ListGroupsForUser("charlie")
	if len(list) != 0 {
		t.Errorf("ListGroupsForUser(charlie): expected empty, got %v", list)
	}

	if err := store.UpdateGroupMembers("g1", []string{"alice", "bob", "charlie"}); err != nil {
		t.Fatalf("UpdateGroupMembers: %v", err)
	}
	g, _ = store.GetGroup("g1")
	if len(g.Members) != 3 {
		t.Errorf("after UpdateGroupMembers: got %v", g.Members)
	}

	if err := store.DeleteGroup("g1"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	g, err = store.GetGroup("g1")
	if err != nil {
		t.Fatalf("GetGroup after delete: %v", err)
	}
	if g != nil {
		t.Errorf("GetGroup after DeleteGroup: expected nil, got %+v", g)
	}
}

func TestStore_CreateGroup_duplicateFails(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := store.CreateGroup("g1", "A", []string{"alice"}, "alice"); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	err = store.CreateGroup("g1", "B", []string{"bob"}, "bob")
	if err == nil {
		t.Fatal("second CreateGroup with same id should fail")
	}
}

func TestStore_UpdateGroupMembers_emptyRemovesGroup(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	_ = store.CreateGroup("g1", "A", []string{"alice"}, "alice")
	if err := store.UpdateGroupMembers("g1", []string{}); err != nil {
		t.Fatalf("UpdateGroupMembers empty: %v", err)
	}
	g, err := store.GetGroup("g1")
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if g != nil {
		t.Errorf("after UpdateGroupMembers empty: expected nil, got %+v", g)
	}
}

func TestStore_RegistrationRequests(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Create a request
	req, err := store.CreateRegistrationRequest("alice", "pk-alice", "Hello, I'm Alice")
	if err != nil {
		t.Fatalf("CreateRegistrationRequest: %v", err)
	}
	if req.Status != "pending" {
		t.Errorf("expected pending, got %q", req.Status)
	}

	// List pending
	pending := store.ListPendingRequests()
	if len(pending) != 1 {
		t.Fatalf("ListPendingRequests: expected 1, got %d", len(pending))
	}
	if pending[0].Username != "alice" || pending[0].Intro != "Hello, I'm Alice" {
		t.Errorf("unexpected request: %+v", pending[0])
	}

	// Duplicate request with same key returns existing
	req2, err := store.CreateRegistrationRequest("alice", "pk-alice", "different intro")
	if err != nil {
		t.Fatalf("CreateRegistrationRequest duplicate: %v", err)
	}
	if req2.Intro != "Hello, I'm Alice" {
		t.Errorf("expected original intro, got %q", req2.Intro)
	}

	// Duplicate request with different key → error
	_, err = store.CreateRegistrationRequest("alice", "pk-other", "hi")
	if err == nil {
		t.Fatal("expected error for different key on pending username")
	}
}

func TestStore_ApproveRequest(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if _, err := store.CreateRegistrationRequest("alice", "pk-alice", "hi"); err != nil {
		t.Fatalf("CreateRegistrationRequest: %v", err)
	}

	if err := store.ApproveRequest("alice"); err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}

	// User should now be in keys
	pk, ok := store.GetPubKey("alice")
	if !ok || pk != "pk-alice" {
		t.Errorf("after approve: expected pk-alice, got %q ok=%v", pk, ok)
	}

	// Request should be approved
	req := store.GetRegistrationRequest("alice")
	if req == nil || req.Status != "approved" {
		t.Errorf("expected approved status, got %+v", req)
	}
}

func TestStore_DenyRequest(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if _, err := store.CreateRegistrationRequest("bob", "pk-bob", "hi"); err != nil {
		t.Fatalf("CreateRegistrationRequest: %v", err)
	}

	if err := store.DenyRequest("bob"); err != nil {
		t.Fatalf("DenyRequest: %v", err)
	}

	req := store.GetRegistrationRequest("bob")
	if req == nil || req.Status != "denied" {
		t.Errorf("expected denied status, got %+v", req)
	}

	// User should NOT be in keys
	if _, ok := store.GetPubKey("bob"); ok {
		t.Error("denied user should not be in keys")
	}

	// Re-request after denial should work
	req2, err := store.CreateRegistrationRequest("bob", "pk-bob", "please reconsider")
	if err != nil {
		t.Fatalf("re-request after denial: %v", err)
	}
	if req2.Status != "pending" || req2.Intro != "please reconsider" {
		t.Errorf("re-request: expected pending with new intro, got %+v", req2)
	}
}

func TestStore_ResetRequests(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if _, err := store.CreateRegistrationRequest("alice", "pk-alice", "hi"); err != nil {
		t.Fatalf("CreateRegistrationRequest: %v", err)
	}
	if _, err := store.CreateRegistrationRequest("bob", "pk-bob", "hi"); err != nil {
		t.Fatalf("CreateRegistrationRequest: %v", err)
	}

	if err := store.ResetRequests(); err != nil {
		t.Fatalf("ResetRequests: %v", err)
	}
	if pending := store.ListPendingRequests(); len(pending) != 0 {
		t.Errorf("after ResetRequests: expected 0, got %d", len(pending))
	}
}

func TestRegister_ApprovalRequired(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	s := &Server{store: store, requireApproval: true}

	// Register → 202 pending
	body := `{"username":"alice","pubkey":"pk-alice","intro":"Hi there"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleRegister(w, req)
	if w.Code != http.StatusAccepted {
		t.Errorf("first register: expected 202, got %d: %s", w.Code, w.Body.String())
	}

	// Poll again → still 202
	body = `{"username":"alice","pubkey":"pk-alice"}`
	req = httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.handleRegister(w, req)
	if w.Code != http.StatusAccepted {
		t.Errorf("poll pending: expected 202, got %d: %s", w.Code, w.Body.String())
	}

	// Admin approves
	if err := store.ApproveRequest("alice"); err != nil {
		t.Fatalf("ApproveRequest: %v", err)
	}

	// Poll again → 200 (re-registration shortcut)
	body = `{"username":"alice","pubkey":"pk-alice"}`
	req = httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.handleRegister(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("after approve: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Different user, same username → 409
	body = `{"username":"alice","pubkey":"pk-other","intro":"I want alice"}`
	req = httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.handleRegister(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("different key same username: expected 409, got %d", w.Code)
	}
}

func TestRegister_DeniedThenReRequest(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	s := &Server{store: store, requireApproval: true}

	// Register → 202
	body := `{"username":"bob","pubkey":"pk-bob","intro":"First try"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleRegister(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("first register: expected 202, got %d", w.Code)
	}

	// Admin denies
	if err := store.DenyRequest("bob"); err != nil {
		t.Fatalf("DenyRequest: %v", err)
	}

	// Poll without intro → 403
	body = `{"username":"bob","pubkey":"pk-bob"}`
	req = httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.handleRegister(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("denied poll: expected 403, got %d: %s", w.Code, w.Body.String())
	}

	// Re-request with new intro → 202
	body = `{"username":"bob","pubkey":"pk-bob","intro":"Please reconsider"}`
	req = httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.handleRegister(w, req)
	if w.Code != http.StatusAccepted {
		t.Errorf("re-request: expected 202, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStore_QueueOfflineWithMeta_GetOffline_returnsMeta(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	meta := map[string]interface{}{"type": "group_invite", "groupId": "g1"}
	if err := store.QueueOfflineWithMeta("bob", "inv1", "alice", "payload", "nonce", 1000, meta); err != nil {
		t.Fatalf("QueueOfflineWithMeta: %v", err)
	}

	msgs, err := store.GetOffline("bob")
	if err != nil {
		t.Fatalf("GetOffline: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("GetOffline: got %d messages", len(msgs))
	}
	m := msgs[0]
	if m["type"] != "group_invite" || m["groupId"] != "g1" {
		t.Errorf("GetOffline meta: got type=%v groupId=%v", m["type"], m["groupId"])
	}
}
