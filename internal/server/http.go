package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// escapeJSString escapes s for safe use inside a JavaScript double-quoted string.
func escapeJSString(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (s *Server) setupRoutes() {
	http.HandleFunc("/health", s.handleHealth)
	http.HandleFunc("/version", s.handleVersion)
	http.HandleFunc("/register", s.handleRegister)
	http.HandleFunc("/deregister", s.handleDeregister)
	http.HandleFunc("/users", s.handleUsers)
	http.HandleFunc("/keys/", s.handleKeys)
	http.HandleFunc("/ws", s.handleWebSocket)
	http.HandleFunc("/u/", s.handleShareableLink)
	http.HandleFunc("/admin/", s.handleAdmin)
	http.Handle("/", s.handleStatic())
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"version": s.version})
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
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleDeregister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	if err := s.store.Deregister(req.Username); err != nil {
		http.Error(w, "Deregistration failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	users := s.store.ListUsernames()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"users": users})
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
	_ = json.NewEncoder(w).Encode(map[string]string{"username": username, "pubkey": pubkey})
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

// handleAdmin serves the admin panel and handles reset actions. Path: /admin/<token> or /admin/<token>/<action>.
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin")
	path = strings.Trim(path, "/")
	parts := strings.SplitN(path, "/", 2)
	token := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	if token != s.adminToken {
		http.NotFound(w, r)
		return
	}
	if action == "" {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.serveAdminPage(w, token)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch action {
	case "reset-users":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.store.ResetUsers(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "action": "reset-users"})
	case "reset-offline":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.store.ResetOffline(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "action": "reset-offline"})
	case "reset-groups":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.store.ResetGroups(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "action": "reset-groups"})
	case "reset-all":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = s.store.ResetUsers()
		_ = s.store.ResetOffline()
		_ = s.store.ResetGroups()
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "action": "reset-all"})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveAdminPage(w http.ResponseWriter, token string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	base := "/admin/" + token
	baseEscaped := escapeJSString(base)
	html := `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>War Chat Admin</title>
<style>body{font-family:system-ui;max-width:480px;margin:2rem auto;padding:1rem;background:#1a1a2e;color:#eee;}
h1{font-size:1.25rem;} button{padding:0.75rem 1rem;margin:0.5rem 0;cursor:pointer;background:#e94560;border:none;border-radius:6px;color:#fff;font-weight:600;display:block;width:100%;}
button:hover{background:#ff6b6b;} button.danger{background:#0f3460;} #msg{margin-top:1rem;min-height:1.5rem;}</style></head>
<body>
<h1>War Chat Admin</h1>
<p>Reset server data. This cannot be undone.</p>
<button data-action="reset-users">Reset all users</button>
<button data-action="reset-offline">Clear offline messages</button>
<button data-action="reset-groups">Clear groups</button>
<button data-action="reset-all" class="danger">Reset all (users + offline + groups)</button>
<div id="msg"></div>
<script>
const base = "` + baseEscaped + `";
document.querySelectorAll("button[data-action]").forEach(btn => {
  btn.onclick = async () => {
    const action = btn.dataset.action;
    if (action === "reset-all" && !confirm("Reset all users, offline messages, and groups?")) return;
    const msg = document.getElementById("msg");
    msg.textContent = "Running...";
    try {
      const r = await fetch(base + "/" + action, { method: "POST" });
      const j = await r.json().catch(() => ({}));
      msg.textContent = r.ok ? "Done: " + (j.action || action) : "Error: " + r.status;
    } catch (e) {
      msg.textContent = "Error: " + e.message;
    }
  };
});
</script>
</body>
</html>`
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}
