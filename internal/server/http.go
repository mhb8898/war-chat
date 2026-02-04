package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

func (s *Server) setupRoutes() {
	http.HandleFunc("/health", s.handleHealth)
	http.HandleFunc("/register", s.handleRegister)
	http.HandleFunc("/users", s.handleUsers)
	http.HandleFunc("/keys/", s.handleKeys)
	http.HandleFunc("/ws", s.handleWebSocket)
	http.HandleFunc("/u/", s.handleShareableLink)
	http.Handle("/", s.handleStatic())
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		PubKey   string `json:"pubkey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.PubKey == "" {
		http.Error(w, "username and pubkey required", http.StatusBadRequest)
		return
	}

	if err := s.store.Register(req.Username, req.PubKey); err != nil {
		if errors.Is(err, ErrDuplicateUsername) {
			http.Error(w, "Username already taken. Choose another name.", http.StatusConflict)
			return
		}
		http.Error(w, "Registration failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	users := s.store.ListUsernames()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"users": users})
}

func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/keys/")
	path = strings.TrimSuffix(path, "/")
	username := strings.TrimSpace(path)

	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	pubkey, ok := s.store.GetPubKey(username)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"username": username, "pubkey": pubkey})
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	s.hub.ServeWS(w, r, s.store)
}

func (s *Server) handleShareableLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/u/")
	path = strings.TrimSuffix(path, "/")
	username := strings.TrimSpace(path)

	if username == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Redirect with both query and hash so username is preserved if hash is stripped
	http.Redirect(w, r, "/?u="+username+"#chat/"+username, http.StatusFound)
}
