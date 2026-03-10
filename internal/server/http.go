package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

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
	http.HandleFunc("/admin", s.handleAdmin)
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

// handleAdmin serves the admin panel with Basic Auth, or the setup page on first run.
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin")
	path = strings.Trim(path, "/")

	// First-run setup: no password configured yet.
	if !s.store.AdminConfigured() {
		if path == "setup" && r.Method == http.MethodPost {
			s.handleAdminSetup(w, r)
			return
		}
		// Show setup page for any /admin request when not configured.
		if r.Method == http.MethodGet {
			s.serveAdminSetupPage(w)
			return
		}
		http.Error(w, "Admin not configured", http.StatusForbidden)
		return
	}

	// Require Basic Auth.
	user, pass, ok := r.BasicAuth()
	if !ok || !s.store.CheckAdminCredentials(user, pass) {
		w.Header().Set("WWW-Authenticate", `Basic realm="War Chat Admin"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if path == "" || path == "setup" {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.serveAdminPage(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	switch path {
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

// handleAdminSetup processes the initial password setup form.
func (s *Server) handleAdminSetup(w http.ResponseWriter, r *http.Request) {
	if s.store.AdminConfigured() {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)
	if req.Username == "" || len(req.Password) < 8 {
		http.Error(w, "Username required and password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	if err := s.store.SetAdminCredentials(req.Username, req.Password); err != nil {
		http.Error(w, "Failed to save credentials", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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

func (s *Server) serveAdminSetupPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	const page = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>War Chat Setup</title>
<script>(function(){var t=localStorage.getItem('war-chat-theme')||(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');document.documentElement.setAttribute('data-theme',t)})();</script>
<style>
:root{--bg:#08080f;--surface:#10101c;--surface-2:#181828;--border:#23233a;--accent:#7c6af6;--accent-hover:#6659e3;--danger:#ef4444;--text:#f0f0fa;--text-2:#8b8bab;color-scheme:dark}
html[data-theme=light]{--bg:#f4f4f8;--surface:#ffffff;--surface-2:#eaeaf3;--border:#d8d8ec;--text:#0d0d1a;--text-2:#626286;color-scheme:light}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
.setup-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:2rem;width:100%;max-width:400px;margin:1rem}
.setup-card h1{font-size:1.25rem;font-weight:700;margin-bottom:0.25rem;letter-spacing:-0.01em}
.setup-card p{font-size:0.8125rem;color:var(--text-2);margin-bottom:1.5rem}
label{display:block;font-size:0.8125rem;font-weight:600;margin-bottom:0.375rem;color:var(--text-2)}
input{width:100%;padding:0.625rem 0.875rem;border:1px solid var(--border);border-radius:10px;background:var(--surface-2);color:var(--text);font-size:0.9375rem;font-family:inherit;margin-bottom:1rem;outline:none;transition:border-color .15s}
input:focus{border-color:var(--accent)}
button{padding:0.625rem 1.125rem;border:none;border-radius:10px;background:var(--accent);color:#fff;font-size:0.9375rem;font-family:inherit;font-weight:600;cursor:pointer;transition:background .15s,transform .1s;width:100%}
button:hover{background:var(--accent-hover)}
button:active{transform:scale(.98)}
button:disabled{opacity:.45;cursor:not-allowed;transform:none}
#err{font-size:0.8125rem;color:var(--danger);margin-bottom:1rem;display:none}
</style>
</head>
<body>
<div class="setup-card">
  <h1>Welcome to War Chat</h1>
  <p>Create an admin account to get started.</p>
  <form id="setupForm">
    <label for="username">Username</label>
    <input id="username" name="username" type="text" autocomplete="username" required value="admin">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="new-password" required minlength="8" placeholder="Min 8 characters">
    <label for="confirm">Confirm password</label>
    <input id="confirm" name="confirm" type="password" autocomplete="new-password" required minlength="8">
    <div id="err"></div>
    <button type="submit">Create admin account</button>
  </form>
</div>
<script>
document.getElementById('setupForm').onsubmit=async function(e){
  e.preventDefault();
  var err=document.getElementById('err');
  var user=document.getElementById('username').value.trim();
  var pass=document.getElementById('password').value;
  var conf=document.getElementById('confirm').value;
  err.style.display='none';
  if(pass!==conf){err.textContent='Passwords do not match';err.style.display='block';return;}
  if(pass.length<8){err.textContent='Password must be at least 8 characters';err.style.display='block';return;}
  var btn=this.querySelector('button');
  btn.disabled=true;btn.textContent='Setting up…';
  try{
    var r=await fetch('/admin/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
    if(r.ok){window.location.href='/admin';}
    else{var t=await r.text();err.textContent=t||'Setup failed';err.style.display='block';}
  }catch(ex){err.textContent='Network error';err.style.display='block';}
  btn.disabled=false;btn.textContent='Create admin account';
};
</script>
</body>
</html>`
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}

func (s *Server) serveAdminPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	const page = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Personal Chat Admin</title>
<script src="/qrcode.min.js"></script>
<script>(function(){var t=localStorage.getItem('war-chat-theme')||(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');document.documentElement.setAttribute('data-theme',t)})();</script>
<style>
:root{--bg:#08080f;--surface:#10101c;--surface-2:#181828;--border:#23233a;--accent:#7c6af6;--accent-hover:#6659e3;--danger:#ef4444;--danger-hover:#dc2626;--text:#f0f0fa;--text-2:#8b8bab;color-scheme:dark}
html[data-theme=light]{--bg:#f4f4f8;--surface:#ffffff;--surface-2:#eaeaf3;--border:#d8d8ec;--text:#0d0d1a;--text-2:#626286;color-scheme:light}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.admin-header{background:var(--surface);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10}
.admin-header-inner{max-width:560px;margin:0 auto;padding:0 1.5rem;height:56px;display:flex;align-items:center;justify-content:space-between}
.admin-brand{display:flex;align-items:center;gap:0.625rem;font-weight:700;font-size:1.0625rem;letter-spacing:-0.01em}
.brand-icon{color:var(--accent);flex-shrink:0}
.btn-icon{background:none;border:none;color:var(--text-2);cursor:pointer;padding:0.5rem;border-radius:8px;display:flex;align-items:center;transition:color .15s,background .15s}
.btn-icon:hover{color:var(--text);background:var(--surface-2)}
.admin-main{max-width:560px;margin:0 auto;padding:2rem 1.5rem;display:flex;flex-direction:column;gap:1.25rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;overflow:hidden}
.card-header{padding:1.25rem 1.5rem 0}
.card-header h2{font-size:0.9375rem;font-weight:700;margin-bottom:0.25rem;letter-spacing:-0.01em}
.card-header p{font-size:0.8125rem;color:var(--text-2);margin:0.25rem 0 1.25rem}
.card-body{padding:0 1.5rem 1.25rem;display:flex;flex-direction:column;gap:0.5rem}
.danger-zone{padding:1rem 1.5rem;background:rgba(239,68,68,.05);border-top:1px solid rgba(239,68,68,.15);display:flex;align-items:flex-start;gap:1rem;flex-wrap:wrap}
.danger-zone p{font-size:0.8125rem;color:var(--text-2);flex:1;min-width:160px;padding-top:0.25rem}
button{padding:0.625rem 1.125rem;border:none;border-radius:10px;background:var(--accent);color:#fff;font-size:0.9375rem;font-family:inherit;font-weight:600;cursor:pointer;transition:background .15s,transform .1s;width:100%}
button:hover{background:var(--accent-hover)}
button:active{transform:scale(.98)}
button:disabled{opacity:.45;cursor:not-allowed;transform:none}
.btn-ghost{background:var(--surface-2);color:var(--text);border:1px solid var(--border)}
.btn-ghost:hover{background:var(--border)!important}
.btn-danger{background:var(--danger);width:auto;flex-shrink:0}
.btn-danger:hover{background:var(--danger-hover)!important}
#msg{font-size:0.875rem;white-space:pre-wrap;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:0.875rem 1rem}
#msg:empty{display:none}
#msg.error{border-color:rgba(239,68,68,.4);background:rgba(239,68,68,.08);color:#f87171}
#msg.success{border-color:rgba(124,106,246,.35);background:rgba(124,106,246,.08);color:#a89bf8}
.invite-out{font-size:0.8125rem;color:var(--text-2);background:var(--surface-2);border:1px solid var(--border);border-radius:8px;padding:0.75rem;white-space:pre-wrap;word-break:break-all;font-family:ui-monospace,monospace}
.invite-out:empty{display:none}
#inviteQR{margin-top:0.75rem}
#inviteQR:empty{display:none}
</style>
</head>
<body>
<div class="admin-header">
  <div class="admin-header-inner">
    <div class="admin-brand">
      <svg class="brand-icon" width="20" height="20" viewBox="0 0 20 20" fill="none">
        <rect x="3" y="9" width="14" height="10" rx="2" stroke="currentColor" stroke-width="1.5"/>
        <path d="M6.5 9V6a3.5 3.5 0 0 1 7 0v3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
      Personal Chat Admin
    </div>
    <button id="btnThemeToggle" class="btn-icon" title="Toggle theme"></button>
  </div>
</div>
<main class="admin-main">
  <div id="msg"></div>
  <div class="card">
    <div class="card-header">
      <h2>Data</h2>
      <p>Reset server state. These actions cannot be undone.</p>
    </div>
    <div class="card-body">
      <button data-action="reset-users">Reset all users</button>
      <button data-action="reset-offline">Clear offline messages</button>
      <button data-action="reset-groups">Clear groups</button>
    </div>
    <div class="danger-zone">
      <button data-action="reset-all" class="btn-danger">Reset everything</button>
      <p>Clears users, offline messages, groups, and invites.</p>
    </div>
  </div>
  <div class="card">
    <div class="card-header">
      <h2>Invite tokens</h2>
      <p>When tokens exist, users must supply one to register.</p>
    </div>
    <div class="card-body">
      <button id="btnCreateInvite">Create token</button>
      <button id="btnListInvites" class="btn-ghost">List tokens</button>
      <div id="inviteOut" class="invite-out"></div>
      <div id="inviteQR"></div>
    </div>
    <div class="danger-zone">
      <button id="btnResetInvites" class="btn-danger">Reset all tokens</button>
      <p>Removes all invite tokens from the server.</p>
    </div>
  </div>
</main>
<script>
const base = "/admin";
const SVG_SUN = '<svg width="18" height="18" viewBox="0 0 18 18" fill="none"><circle cx="9" cy="9" r="3.25" stroke="currentColor" stroke-width="1.5"/><path d="M9 1.5V3M9 15v1.5M1.5 9H3M15 9h1.5M3.4 3.4l1.06 1.06M13.54 13.54l1.06 1.06M3.4 14.6l1.06-1.06M13.54 4.46l1.06-1.06" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';
const SVG_MOON = '<svg width="18" height="18" viewBox="0 0 18 18" fill="none"><path d="M15 11.5A7 7 0 0 1 6.5 3a7 7 0 1 0 8.5 8.5z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
function applyTheme(t){
  document.documentElement.setAttribute('data-theme',t);
  const btn=document.getElementById('btnThemeToggle');
  if(btn){btn.innerHTML=t==='dark'?SVG_SUN:SVG_MOON;btn.title=t==='dark'?'Switch to light mode':'Switch to dark mode';}
}
applyTheme(document.documentElement.getAttribute('data-theme')||'dark');
document.getElementById('btnThemeToggle').addEventListener('click',function(){
  const next=document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';
  localStorage.setItem('war-chat-theme',next);applyTheme(next);
});
function clearEl(id){const e=document.getElementById(id);if(e)e.replaceChildren();}
function showMsg(text,isError){
  const el=document.getElementById('msg');
  if(!el)return;
  el.textContent=text;
  el.className=isError?'error':text?'success':'';
}
document.querySelectorAll('button[data-action]').forEach(function(btn){
  btn.onclick=async function(){
    const action=btn.dataset.action;
    if(action==='reset-all'&&!confirm('Reset all users, offline messages, groups, and invites?'))return;
    showMsg('Running…',false);
    try{
      const r=await fetch(base+'/'+action,{method:'POST'});
      const j=await r.json().catch(function(){return{};});
      showMsg(r.ok?'Done: '+(j.action||action):'Error: '+r.status,!r.ok);
    }catch(e){showMsg('Error: '+e.message,true);}
  };
});
document.getElementById('btnCreateInvite').onclick=async function(){
  const out=document.getElementById('inviteOut');
  clearEl('inviteQR');
  out.textContent='Creating…';
  try{
    const r=await fetch(base+'/create-invite',{method:'POST'});
    const j=await r.json().catch(function(){return{};});
    if(r.ok){
      const url=window.location.origin+'/?invite='+j.token+'#register';
      out.textContent='Token: '+j.token+'\nURL: '+url;
      const qrDiv=document.getElementById('inviteQR');
      if(typeof QRCode!=='undefined'&&qrDiv){new QRCode(qrDiv,{text:url,width:180,height:180});}
    }else{out.textContent='Error: '+r.status;}
  }catch(e){out.textContent='Error: '+e.message;}
};
document.getElementById('btnListInvites').onclick=async function(){
  clearEl('inviteQR');
  const out=document.getElementById('inviteOut');
  try{
    const r=await fetch(base+'/list-invites');
    const j=await r.json().catch(function(){return{};});
    if(r.ok){
      const tokens=j.tokens||[];
      out.textContent=tokens.length===0?'No tokens.':tokens.map(function(t){return t.token+' — '+(t.used?'used':'available');}).join('\n');
    }else{out.textContent='Error: '+r.status;}
  }catch(e){out.textContent='Error: '+e.message;}
};
document.getElementById('btnResetInvites').onclick=async function(){
  if(!confirm('Reset all invite tokens?'))return;
  clearEl('inviteQR');
  const out=document.getElementById('inviteOut');
  try{
    const r=await fetch(base+'/reset-invites',{method:'POST'});
    out.textContent=r.ok?'All tokens reset.':'Error: '+r.status;
  }catch(e){out.textContent='Error: '+e.message;}
};
</script>
</body>
</html>`
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}
