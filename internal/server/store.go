package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var ErrDuplicateUsername = errors.New("username already taken with a different key")

// CallRoom is a shareable meeting room with a 24-hour TTL.
type CallRoom struct {
	Token     string `json:"token"`
	CreatedBy string `json:"createdBy"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
}

// GuestKnock is an in-memory pending/admitted guest. Not persisted.
type GuestKnock struct {
	KnockID     string
	RoomToken   string
	DisplayName string
	CreatedAt   int64
	Admitted    bool
	Denied      bool
}

// RegistrationRequest is a pending/processed registration request.
type RegistrationRequest struct {
	Username  string `json:"username"`
	PubKey    string `json:"pubkey"`
	Intro     string `json:"intro"`
	Status    string `json:"status"` // "pending", "approved", "denied"
	CreatedAt int64  `json:"createdAt"`
}

// Group holds group metadata (no keys).
type Group struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Members   []string `json:"members"`
	CreatedBy string   `json:"createdBy"`
	CreatedAt int64    `json:"createdAt"`
}

// safePathComponent returns false if name could be used for path traversal.
func safePathComponent(name string) bool {
	if name == "" {
		return false
	}
	return !strings.Contains(name, "/") &&
		!strings.Contains(name, "\\") &&
		!strings.Contains(name, "..")
}

// AdminCredentials holds the admin username and bcrypt password hash.
type AdminCredentials struct {
	Username string `json:"username"`
	PassHash string `json:"passHash"`
}

type Store struct {
	mu           sync.RWMutex
	keysPath     string
	offlineDir   string
	groupsDir    string
	requestsPath string
	roomsPath    string
	adminPath    string
	keys         map[string]string
	requests     map[string]*RegistrationRequest
	rooms        map[string]*CallRoom
	knocks       map[string]*GuestKnock
	adminCreds   *AdminCredentials
}

func NewStore(dataDir string) (*Store, error) {
	keysPath := filepath.Join(dataDir, "keys.json")
	offlineDir := filepath.Join(dataDir, "offline")
	groupsDir := filepath.Join(dataDir, "groups")
	requestsPath := filepath.Join(dataDir, "requests.json")
	roomsPath := filepath.Join(dataDir, "rooms.json")
	adminPath := filepath.Join(dataDir, "admin.json")

	if err := os.MkdirAll(offlineDir, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(groupsDir, 0755); err != nil {
		return nil, err
	}

	s := &Store{
		keysPath:     keysPath,
		offlineDir:   offlineDir,
		groupsDir:    groupsDir,
		requestsPath: requestsPath,
		roomsPath:    roomsPath,
		adminPath:    adminPath,
		keys:         make(map[string]string),
		requests:     make(map[string]*RegistrationRequest),
		rooms:        make(map[string]*CallRoom),
		knocks:       make(map[string]*GuestKnock),
	}

	if err := s.loadKeys(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := s.loadRequests(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := s.loadRooms(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := s.loadAdmin(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return s, nil
}

func (s *Store) loadKeys() error {
	data, err := os.ReadFile(s.keysPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.keys)
}

func (s *Store) saveKeys() error {
	data, err := json.MarshalIndent(s.keys, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.keysPath, data, 0600)
}

func (s *Store) Register(username, pubkey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.keys[username]; ok && existing != pubkey {
		return ErrDuplicateUsername
	}
	s.keys[username] = pubkey
	return s.saveKeys()
}

// Deregister removes a user from the server so the username can be used again.
func (s *Store) Deregister(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, username)
	return s.saveKeys()
}

func (s *Store) GetPubKey(username string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pk, ok := s.keys[username]
	return pk, ok
}

func (s *Store) ListUsernames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.keys))
	for u := range s.keys {
		names = append(names, u)
	}
	return names
}

func (s *Store) GetPubKeys(usernames []string) map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]string)
	for _, u := range usernames {
		if pk, ok := s.keys[u]; ok {
			result[u] = pk
		}
	}
	return result
}

// CreateGroup stores a new group. ID must be safe for use as filename.
func (s *Store) CreateGroup(id, name string, members []string, createdBy string) error {
	if !safePathComponent(id) {
		return errors.New("invalid group id")
	}
	safeID := id
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.groupsDir, safeID+".json")
	if _, err := os.Stat(path); err == nil {
		return errors.New("group already exists")
	}

	g := Group{
		ID:        id,
		Name:      name,
		Members:   members,
		CreatedBy: createdBy,
		CreatedAt: time.Now().UnixMilli(),
	}
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// GetGroup returns a group by id.
func (s *Store) GetGroup(id string) (*Group, error) {
	if !safePathComponent(id) {
		return nil, errors.New("invalid group id")
	}
	safeID := id
	s.mu.RLock()
	path := filepath.Join(s.groupsDir, safeID+".json")
	s.mu.RUnlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var g Group
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// UpdateGroupMembers updates the members list of a group.
func (s *Store) UpdateGroupMembers(id string, members []string) error {
	if !safePathComponent(id) {
		return errors.New("invalid group id")
	}
	safeID := id
	g, err := s.GetGroup(id)
	if err != nil || g == nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	g.Members = members
	if len(members) == 0 {
		path := filepath.Join(s.groupsDir, safeID+".json")
		return os.Remove(path)
	}
	path := filepath.Join(s.groupsDir, safeID+".json")
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// ListGroupsForUser returns all groups that include the given username.
func (s *Store) ListGroupsForUser(username string) ([]*Group, error) {
	s.mu.RLock()
	dir := s.groupsDir
	s.mu.RUnlock()

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var out []*Group
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if !safePathComponent(id) {
			continue
		}
		g, err := s.GetGroup(id)
		if err != nil || g == nil {
			continue
		}
		for _, m := range g.Members {
			if m == username {
				out = append(out, g)
				break
			}
		}
	}
	return out, nil
}

// DeleteGroup removes a group by id.
func (s *Store) DeleteGroup(id string) error {
	if !safePathComponent(id) {
		return errors.New("invalid group id")
	}
	safeID := id
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.groupsDir, safeID+".json")
	return os.Remove(path)
}

func (s *Store) loadRequests() error {
	data, err := os.ReadFile(s.requestsPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.requests)
}

func (s *Store) saveRequests() error {
	data, err := json.MarshalIndent(s.requests, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.requestsPath, data, 0600)
}

// CreateRegistrationRequest stores a pending registration request keyed by username.
// If a denied request already exists for this username, it is overwritten.
func (s *Store) CreateRegistrationRequest(username, pubkey, intro string) (*RegistrationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.keys[username]; ok && existing != pubkey {
		return nil, ErrDuplicateUsername
	}

	if req, ok := s.requests[username]; ok && req.Status == "pending" {
		if req.PubKey == pubkey {
			return req, nil
		}
		return nil, ErrDuplicateUsername
	}

	req := &RegistrationRequest{
		Username:  username,
		PubKey:    pubkey,
		Intro:     intro,
		Status:    "pending",
		CreatedAt: time.Now().UnixMilli(),
	}
	s.requests[username] = req
	return req, s.saveRequests()
}

// GetRegistrationRequest returns the request for the given username, or nil.
func (s *Store) GetRegistrationRequest(username string) *RegistrationRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.requests[username]
}

// ListPendingRequests returns all requests with status "pending".
func (s *Store) ListPendingRequests() []*RegistrationRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*RegistrationRequest
	for _, req := range s.requests {
		if req.Status == "pending" {
			cp := *req
			out = append(out, &cp)
		}
	}
	return out
}

// ApproveRequest marks a pending request as approved and registers the user in keys.json.
func (s *Store) ApproveRequest(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[username]
	if !ok || req.Status != "pending" {
		return errors.New("no pending request for this user")
	}

	if existing, ok := s.keys[username]; ok && existing != req.PubKey {
		return ErrDuplicateUsername
	}
	s.keys[username] = req.PubKey
	if err := s.saveKeys(); err != nil {
		return err
	}

	req.Status = "approved"
	return s.saveRequests()
}

// DenyRequest marks a pending request as denied.
func (s *Store) DenyRequest(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[username]
	if !ok || req.Status != "pending" {
		return errors.New("no pending request for this user")
	}

	req.Status = "denied"
	return s.saveRequests()
}

// ResetRequests clears all registration requests.
func (s *Store) ResetRequests() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = make(map[string]*RegistrationRequest)
	return s.saveRequests()
}

func (s *Store) QueueOffline(recipient, msgID, from, payload, nonce string, ts int64) error {
	return s.QueueOfflineWithMeta(recipient, msgID, from, payload, nonce, ts, nil)
}

// QueueOfflineWithMeta queues a message for offline delivery. If meta is non-nil, its keys
// (e.g. "type", "groupId") are stored and returned by GetOffline for the client.
func (s *Store) QueueOfflineWithMeta(recipient, msgID, from, payload, nonce string, ts int64, meta map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !safePathComponent(recipient) || !safePathComponent(msgID) {
		return errors.New("invalid recipient or message id")
	}
	safeRecipient, safeMsgID := recipient, msgID

	dir := filepath.Join(s.offlineDir, safeRecipient)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	msg := map[string]interface{}{
		"id":      msgID,
		"from":    from,
		"payload": payload,
		"nonce":   nonce,
		"ts":      ts,
	}
	for k, v := range meta {
		msg[k] = v
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	path := filepath.Join(dir, safeMsgID+".json")
	return os.WriteFile(path, data, 0600)
}

func (s *Store) GetOffline(recipient string) ([]map[string]interface{}, error) {
	if !safePathComponent(recipient) {
		return nil, nil
	}
	safeRecipient := recipient
	s.mu.RLock()
	dir := filepath.Join(s.offlineDir, safeRecipient)
	s.mu.RUnlock()

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var msgs []map[string]interface{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		base := e.Name()
		nameNoExt := strings.TrimSuffix(base, ".json")
		if !safePathComponent(nameNoExt) {
			continue
		}
		path := filepath.Join(dir, nameNoExt+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var m map[string]interface{}
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		msgs = append(msgs, m)
	}
	return msgs, nil
}

func (s *Store) DeleteOffline(recipient string, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !safePathComponent(recipient) {
		return errors.New("invalid recipient")
	}
	safeRecipient := recipient
	dir := filepath.Join(s.offlineDir, safeRecipient)
	for _, id := range ids {
		if !safePathComponent(id) {
			continue
		}
		safeID := id
		path := filepath.Join(dir, safeID+".json")
		_ = os.Remove(path)
	}
	return nil
}

// ResetUsers clears all registered users (keys.json).
func (s *Store) ResetUsers() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = make(map[string]string)
	return s.saveKeys()
}

// ResetOffline removes all queued offline messages.
func (s *Store) ResetOffline() error {
	s.mu.RLock()
	dir := s.offlineDir
	s.mu.RUnlock()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if !e.IsDir() || !safePathComponent(e.Name()) {
			continue
		}
		sub := filepath.Join(dir, e.Name())
		subEntries, _ := os.ReadDir(sub)
		for _, f := range subEntries {
			if f.IsDir() || !safePathComponent(f.Name()) {
				continue
			}
			_ = os.Remove(filepath.Join(sub, f.Name()))
		}
		_ = os.Remove(sub)
	}
	return nil
}

// --- CallRoom methods ---

func (s *Store) loadRooms() error {
	data, err := os.ReadFile(s.roomsPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.rooms)
}

func (s *Store) saveRooms() error {
	data, err := json.MarshalIndent(s.rooms, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.roomsPath, data, 0600)
}

// CreateCallRoom generates a random room token with a 24h TTL.
func (s *Store) CreateCallRoom(createdBy string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rooms[token] = &CallRoom{
		Token:     token,
		CreatedBy: createdBy,
		CreatedAt: now.UnixMilli(),
		ExpiresAt: now.Add(24 * time.Hour).UnixMilli(),
	}
	return token, s.saveRooms()
}

// GetCallRoom returns the room for the given token, or nil if missing or expired.
func (s *Store) GetCallRoom(token string) *CallRoom {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rooms[token]
	if !ok || time.Now().UnixMilli() > r.ExpiresAt {
		return nil
	}
	return r
}

// PruneExpiredRooms removes rooms past their ExpiresAt, saving if any were deleted.
func (s *Store) PruneExpiredRooms() error {
	now := time.Now().UnixMilli()
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for token, r := range s.rooms {
		if now > r.ExpiresAt {
			delete(s.rooms, token)
			changed = true
		}
	}
	if changed {
		return s.saveRooms()
	}
	return nil
}

// --- GuestKnock methods (in-memory only) ---

func (s *Store) CreateKnock(roomToken, displayName string) *GuestKnock {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	knock := &GuestKnock{
		KnockID:     hex.EncodeToString(b),
		RoomToken:   roomToken,
		DisplayName: displayName,
		CreatedAt:   time.Now().UnixMilli(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.knocks[knock.KnockID] = knock
	return knock
}

func (s *Store) GetKnock(knockID string) *GuestKnock {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.knocks[knockID]
}

func (s *Store) GetAdmittedKnock(roomToken, knockID string) *GuestKnock {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.knocks[knockID]
	if !ok || k.RoomToken != roomToken || !k.Admitted {
		return nil
	}
	return k
}

func (s *Store) ListPendingKnocks(roomToken string) []*GuestKnock {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*GuestKnock
	for _, k := range s.knocks {
		if k.RoomToken == roomToken && !k.Admitted && !k.Denied {
			out = append(out, k)
		}
	}
	return out
}

func (s *Store) AdmitKnock(knockID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.knocks[knockID]; ok {
		k.Admitted = true
		return true
	}
	return false
}

func (s *Store) DenyKnock(knockID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.knocks[knockID]; ok {
		k.Denied = true
		return true
	}
	return false
}

// --- Admin credential methods ---

func (s *Store) loadAdmin() error {
	data, err := os.ReadFile(s.adminPath)
	if err != nil {
		return err
	}
	var creds AdminCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return err
	}
	s.adminCreds = &creds
	return nil
}

// AdminConfigured returns true if an admin password has been set.
func (s *Store) AdminConfigured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.adminCreds != nil
}

// SetAdminCredentials hashes the password with bcrypt and persists the credentials.
func (s *Store) SetAdminCredentials(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adminCreds = &AdminCredentials{
		Username: username,
		PassHash: string(hash),
	}
	data, err := json.MarshalIndent(s.adminCreds, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.adminPath, data, 0600)
}

// CheckAdminCredentials validates the given username/password against stored credentials.
func (s *Store) CheckAdminCredentials(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.adminCreds == nil {
		return false
	}
	if s.adminCreds.Username != username {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(s.adminCreds.PassHash), []byte(password)) == nil
}

// ResetGroups removes all group files.
func (s *Store) ResetGroups() error {
	s.mu.RLock()
	dir := s.groupsDir
	s.mu.RUnlock()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		// Only remove paths under dir; reject names that could traverse
		if !safePathComponent(e.Name()) {
			continue
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	return nil
}
