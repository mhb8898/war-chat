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
)

var ErrDuplicateUsername = errors.New("username already taken with a different key")

// InviteToken is a single-use registration token.
type InviteToken struct {
	Token     string `json:"token"`
	Used      bool   `json:"used"`
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

type Store struct {
	mu          sync.RWMutex
	keysPath    string
	offlineDir  string
	groupsDir   string
	invitesPath string
	keys        map[string]string
	invites     map[string]*InviteToken
}

func NewStore(dataDir string) (*Store, error) {
	keysPath := filepath.Join(dataDir, "keys.json")
	offlineDir := filepath.Join(dataDir, "offline")
	groupsDir := filepath.Join(dataDir, "groups")
	invitesPath := filepath.Join(dataDir, "invites.json")

	if err := os.MkdirAll(offlineDir, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(groupsDir, 0755); err != nil {
		return nil, err
	}

	s := &Store{
		keysPath:    keysPath,
		offlineDir:  offlineDir,
		groupsDir:   groupsDir,
		invitesPath: invitesPath,
		keys:        make(map[string]string),
		invites:     make(map[string]*InviteToken),
	}

	if err := s.loadKeys(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := s.loadInvites(); err != nil && !os.IsNotExist(err) {
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

func (s *Store) loadInvites() error {
	data, err := os.ReadFile(s.invitesPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.invites)
}

func (s *Store) saveInvites() error {
	data, err := json.MarshalIndent(s.invites, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.invitesPath, data, 0600)
}

// CreateInviteToken generates a random single-use invite token and persists it.
func (s *Store) CreateInviteToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invites[token] = &InviteToken{
		Token:     token,
		Used:      false,
		CreatedAt: time.Now().UnixMilli(),
	}
	return token, s.saveInvites()
}

// ValidateAndConsumeToken marks a token used and returns true, or returns false if invalid/used.
func (s *Store) ValidateAndConsumeToken(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invites[token]
	if !ok || inv.Used {
		return false
	}
	inv.Used = true
	_ = s.saveInvites()
	return true
}

// ListInviteTokens returns a snapshot of all invite tokens.
func (s *Store) ListInviteTokens() []*InviteToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*InviteToken, 0, len(s.invites))
	for _, inv := range s.invites {
		cp := *inv
		out = append(out, &cp)
	}
	return out
}

// ResetInvites clears all invite tokens.
func (s *Store) ResetInvites() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invites = make(map[string]*InviteToken)
	return s.saveInvites()
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
