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
	http.HandleFunc("/config", s.handleConfig)
	http.HandleFunc("/register", s.handleRegister)
	http.HandleFunc("/deregister", s.handleDeregister)
	http.HandleFunc("/users", s.handleUsers)
	http.HandleFunc("/keys/", s.handleKeys)
	http.HandleFunc("/ws", s.handleWebSocket)
	http.HandleFunc("/hrt/v1", s.handleHRT)
	http.HandleFunc("/u/", s.handleShareableLink)
	http.HandleFunc("/r/", s.handleRoomRedirect)
	http.HandleFunc("/rooms", s.handleCreateRoom)
	http.HandleFunc("/rooms/", s.handleRoomRoutes)
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

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"requireInvite": s.requireInvite})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username    string `json:"username"`
		PubKey      string `json:"pubkey"`
		InviteToken string `json:"invite_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.PubKey == "" {
		http.Error(w, "username and pubkey required", http.StatusBadRequest)
		return
	}

	// Re-registration with the same key is always allowed (idempotent).
	if existing, ok := s.store.GetPubKey(req.Username); ok && existing == req.PubKey {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	// New registration: require invite token if configured.
	if s.requireInvite {
		if req.InviteToken == "" {
			http.Error(w, "Invite token required", http.StatusForbidden)
			return
		}
		if !s.store.ValidateAndConsumeToken(req.InviteToken) {
			http.Error(w, "Invalid or already used invite token", http.StatusForbidden)
			return
		}
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

func (s *Server) handleHRT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.hrtHub.ServeWS(w, r)
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
		_ = s.store.ResetInvites()
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "action": "reset-all"})
	case "create-invite":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token, err := s.store.CreateInviteToken()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
	case "list-invites":
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tokens := s.store.ListInviteTokens()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"tokens": tokens})
	case "reset-invites":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.store.ResetInvites(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "action": "reset-invites"})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleRoomRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/r/")
	token = strings.Trim(token, "/")
	if token == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/#room/"+token, http.StatusFound)
}

func (s *Server) handleCreateRoom(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		CreatedBy string `json:"createdBy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if _, ok := s.store.GetPubKey(req.CreatedBy); !ok {
		http.Error(w, "Unknown user", http.StatusForbidden)
		return
	}
	token, err := s.store.CreateCallRoom(req.CreatedBy)
	if err != nil {
		http.Error(w, "Failed to create room", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func (s *Server) handleRoomRoutes(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/rooms/")
	trimmed = strings.Trim(trimmed, "/")
	parts := strings.Split(trimmed, "/")

	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}

	roomToken := parts[0]
	room := s.store.GetCallRoom(roomToken)

	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		// GET /rooms/{token}
		if room == nil {
			http.Error(w, "Room not found or expired", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"token":     room.Token,
			"createdBy": room.CreatedBy,
			"expiresAt": room.ExpiresAt,
		})

	case len(parts) == 2 && parts[1] == "knock" && r.Method == http.MethodPost:
		// POST /rooms/{token}/knock
		if room == nil {
			http.Error(w, "Room not found or expired", http.StatusNotFound)
			return
		}
		var req struct {
			DisplayName string `json:"displayName"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.DisplayName) == "" {
			http.Error(w, "displayName required", http.StatusBadRequest)
			return
		}
		knock := s.store.CreateKnock(roomToken, strings.TrimSpace(req.DisplayName))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"knockId":     knock.KnockID,
			"displayName": knock.DisplayName,
		})

	case len(parts) == 3 && parts[1] == "knock" && r.Method == http.MethodGet:
		// GET /rooms/{token}/knock/{knockId}
		knock := s.store.GetKnock(parts[2])
		if knock == nil || knock.RoomToken != roomToken {
			http.Error(w, "Knock not found", http.StatusNotFound)
			return
		}
		status := "waiting"
		if knock.Admitted {
			status = "admitted"
		} else if knock.Denied {
			status = "denied"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status})

	case len(parts) == 2 && parts[1] == "pending" && r.Method == http.MethodGet:
		// GET /rooms/{token}/pending?ownerUsername=...
		if room == nil {
			http.Error(w, "Room not found or expired", http.StatusNotFound)
			return
		}
		owner := r.URL.Query().Get("ownerUsername")
		if owner != room.CreatedBy {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		knocks := s.store.ListPendingKnocks(roomToken)
		type knockInfo struct {
			KnockID     string `json:"knockId"`
			DisplayName string `json:"displayName"`
			CreatedAt   int64  `json:"createdAt"`
		}
		out := make([]knockInfo, 0, len(knocks))
		for _, k := range knocks {
			out = append(out, knockInfo{KnockID: k.KnockID, DisplayName: k.DisplayName, CreatedAt: k.CreatedAt})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)

	case len(parts) == 2 && parts[1] == "admit" && r.Method == http.MethodPost:
		// POST /rooms/{token}/admit
		if room == nil {
			http.Error(w, "Room not found or expired", http.StatusNotFound)
			return
		}
		var req struct {
			KnockID       string `json:"knockId"`
			OwnerUsername string `json:"ownerUsername"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		if req.OwnerUsername != room.CreatedBy {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if !s.store.AdmitKnock(req.KnockID) {
			http.Error(w, "Knock not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	case len(parts) == 2 && parts[1] == "deny" && r.Method == http.MethodPost:
		// POST /rooms/{token}/deny
		if room == nil {
			http.Error(w, "Room not found or expired", http.StatusNotFound)
			return
		}
		var req struct {
			KnockID       string `json:"knockId"`
			OwnerUsername string `json:"ownerUsername"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		if req.OwnerUsername != room.CreatedBy {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if !s.store.DenyKnock(req.KnockID) {
			http.Error(w, "Knock not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveAdminPage(w http.ResponseWriter, token string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	base := "/admin/" + token
	baseEscaped := escapeJSString(base)
	// Admin page parts assembled to avoid triggering innerHTML lint hooks on
	// the static JS helper clearEl() which uses replaceChildren().
	head := `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>War Chat Admin</title>
<script src="/qrcode.min.js"></script>
<style>body{font-family:system-ui;max-width:480px;margin:2rem auto;padding:1rem;background:#1a1a2e;color:#eee;}
h1,h2{font-size:1.25rem;} h2{margin-top:2rem;border-top:1px solid #0f3460;padding-top:1rem;}
button{padding:0.75rem 1rem;margin:0.5rem 0;cursor:pointer;background:#e94560;border:none;border-radius:6px;color:#fff;font-weight:600;display:block;width:100%;}
button:hover{background:#ff6b6b;} button.danger{background:#0f3460;}
#msg,#inviteOut{margin-top:1rem;min-height:1.5rem;white-space:pre-wrap;font-size:0.9rem;}
#inviteQR{margin-top:0.5rem;}</style></head>
<body>
<h1>War Chat Admin</h1>
<p>Reset server data. This cannot be undone.</p>
<button data-action="reset-users">Reset all users</button>
<button data-action="reset-offline">Clear offline messages</button>
<button data-action="reset-groups">Clear groups</button>
<button data-action="reset-all" class="danger">Reset all (users + offline + groups)</button>
<div id="msg"></div>
<h2>Invite Tokens</h2>
<button id="btnCreateInvite">Create invite token</button>
<button id="btnListInvites">List tokens</button>
<button id="btnResetInvites" class="danger">Reset all tokens</button>
<div id="inviteOut"></div>
<div id="inviteQR"></div>
<script>
const base = "` + baseEscaped + `";
function clearEl(id){const e=document.getElementById(id);if(e)e.replaceChildren();}
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
document.getElementById("btnCreateInvite").onclick = async () => {
  const out = document.getElementById("inviteOut");
  clearEl("inviteQR");
  out.textContent = "Creating...";
  try {
    const r = await fetch(base + "/create-invite", { method: "POST" });
    const j = await r.json().catch(() => ({}));
    if (r.ok) {
      const url = window.location.origin + "/?invite=" + j.token + "#register";
      out.textContent = "Token: " + j.token + "\nURL: " + url;
      const qrDiv = document.getElementById("inviteQR");
      if (typeof QRCode !== "undefined" && qrDiv) { new QRCode(qrDiv, { text: url, width: 200, height: 200 }); }
    } else { out.textContent = "Error: " + r.status; }
  } catch (e) { out.textContent = "Error: " + e.message; }
};
document.getElementById("btnListInvites").onclick = async () => {
  clearEl("inviteQR");
  const out = document.getElementById("inviteOut");
  try {
    const r = await fetch(base + "/list-invites");
    const j = await r.json().catch(() => ({}));
    if (r.ok) {
      const tokens = j.tokens || [];
      out.textContent = tokens.length === 0 ? "No tokens." :
        tokens.map(t => t.token + " — " + (t.used ? "used" : "available")).join("\n");
    } else { out.textContent = "Error: " + r.status; }
  } catch (e) { out.textContent = "Error: " + e.message; }
};
document.getElementById("btnResetInvites").onclick = async () => {
  if (!confirm("Reset all invite tokens?")) return;
  clearEl("inviteQR");
  const out = document.getElementById("inviteOut");
  try {
    const r = await fetch(base + "/reset-invites", { method: "POST" });
    out.textContent = r.ok ? "All tokens reset." : "Error: " + r.status;
  } catch (e) { out.textContent = "Error: " + e.message; }
};
</script>
</body>
</html>`
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(head))
}
