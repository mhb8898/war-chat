package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

var ErrDuplicateUsername = errors.New("username already taken with a different key")

type Store struct {
	mu        sync.RWMutex
	keysPath  string
	offlineDir string
	keys      map[string]string
}

func NewStore(dataDir string) (*Store, error) {
	keysPath := filepath.Join(dataDir, "keys.json")
	offlineDir := filepath.Join(dataDir, "offline")

	if err := os.MkdirAll(offlineDir, 0755); err != nil {
		return nil, err
	}

	s := &Store{
		keysPath:   keysPath,
		offlineDir: offlineDir,
		keys:      make(map[string]string),
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

func (s *Store) QueueOffline(recipient, msgID, from, payload, nonce string, ts int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	path := filepath.Join(dir, msgID+".json")
	return os.WriteFile(path, data, 0600)
}

func (s *Store) GetOffline(recipient string) ([]map[string]interface{}, error) {
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
		path := filepath.Join(dir, e.Name())
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

	dir := filepath.Join(s.offlineDir, recipient)
	for _, id := range ids {
		path := filepath.Join(dir, id+".json")
		_ = os.Remove(path)
	}
	return nil
}
