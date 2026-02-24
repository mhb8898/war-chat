package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrDuplicateUsername = errors.New("username already taken with a different key")

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
	mu         sync.RWMutex
	keysPath   string
	offlineDir string
	groupsDir  string
	keys       map[string]string
}

func NewStore(dataDir string) (*Store, error) {
	keysPath := filepath.Join(dataDir, "keys.json")
	offlineDir := filepath.Join(dataDir, "offline")
	groupsDir := filepath.Join(dataDir, "groups")

	if err := os.MkdirAll(offlineDir, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(groupsDir, 0755); err != nil {
		return nil, err
	}

	s := &Store{
		keysPath:   keysPath,
		offlineDir: offlineDir,
		groupsDir:  groupsDir,
		keys:       make(map[string]string),
	}

	if err := s.loadKeys(); err != nil && !os.IsNotExist(err) {
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
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.groupsDir, id+".json")
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
	s.mu.RLock()
	path := filepath.Join(s.groupsDir, id+".json")
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
	g, err := s.GetGroup(id)
	if err != nil || g == nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	g.Members = members
	if len(members) == 0 {
		path := filepath.Join(s.groupsDir, id+".json")
		return os.Remove(path)
	}
	path := filepath.Join(s.groupsDir, id+".json")
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
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.groupsDir, id+".json")
	return os.Remove(path)
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

	dir := filepath.Join(s.offlineDir, recipient)
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

	path := filepath.Join(dir, msgID+".json")
	return os.WriteFile(path, data, 0600)
}

func (s *Store) GetOffline(recipient string) ([]map[string]interface{}, error) {
	if !safePathComponent(recipient) {
		return nil, nil
	}
	s.mu.RLock()
	dir := filepath.Join(s.offlineDir, recipient)
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
		if !safePathComponent(strings.TrimSuffix(base, ".json")) {
			continue
		}
		path := filepath.Join(dir, base)
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
	dir := filepath.Join(s.offlineDir, recipient)
	for _, id := range ids {
		if !safePathComponent(id) {
			continue
		}
		path := filepath.Join(dir, id+".json")
		_ = os.Remove(path)
	}
	return nil
}
