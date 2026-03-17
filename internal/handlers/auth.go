package handlers

import (
	"net/http"
	"strings"

	"goapp/internal/auth"
	"goapp/internal/db"
	"goapp/internal/logger"
	"goapp/internal/middleware"
)

// ─────────────────────────────────────────────────────────────────────────────
// Login handler
// ─────────────────────────────────────────────────────────────────────────────

type LoginData struct {
	PageData
	Username string
	Next     string
}

// LoginHandler serves GET/POST /login.
type LoginHandler struct {
	tmpl    *Renderer
	db      *db.DB
	log     *logger.Logger
	limiter *auth.RateLimiter
}

func NewLoginHandler(r *Renderer, database *db.DB, l *logger.Logger, limiter *auth.RateLimiter) *LoginHandler {
	return &LoginHandler{tmpl: r, db: database, log: l, limiter: limiter}
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if middleware.UserFromCtx(r) != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.showForm(w, r, "", "")
	case http.MethodPost:
		h.handlePost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *LoginHandler) showForm(w http.ResponseWriter, r *http.Request, username, errMsg string) {
	pd := NewPageData(r, "Sign In")
	pd.FlashErr = errMsg
	h.tmpl.Render(w, "login", LoginData{
		PageData: pd,
		Username: username,
		Next:     r.URL.Query().Get("next"),
	})
}

func (h *LoginHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	if !h.limiter.Allow(r) {
		h.log.Warn("login rate limited", "ip", r.RemoteAddr)
		h.showForm(w, r, "", "Too many login attempts. Please wait a minute and try again.")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		h.showForm(w, r, "", "Could not parse form.")
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	next := strings.TrimSpace(r.FormValue("next"))

	if username == "" || password == "" {
		h.showForm(w, r, username, "Username and password are required.")
		return
	}

	user, err := h.db.UserByUsername(username)
	if err != nil {
		h.log.Warn("login failed: user not found", "username", username, "ip", r.RemoteAddr)
		h.showForm(w, r, username, "Invalid username or password.")
		return
	}

	if !auth.CheckPassword(password, user.Password) {
		h.log.Warn("login failed: wrong password", "username", username, "ip", r.RemoteAddr)
		h.showForm(w, r, username, "Invalid username or password.")
		return
	}

	if !user.Active {
		h.log.Warn("login failed: account disabled", "username", username, "ip", r.RemoteAddr)
		h.showForm(w, r, username, "Your account has been disabled. Contact an administrator.")
		return
	}

	h.limiter.Reset(r)

	sess, err := h.db.CreateSession(user.ID)
	if err != nil {
		h.log.Error("create session failed", "err", err)
		h.showForm(w, r, username, "An error occurred. Please try again.")
		return
	}

	_ = h.db.UpdateLastLogin(user.ID)
	h.log.Info("login success", "username", user.Username, "ip", r.RemoteAddr, "role", user.Role)

	middleware.SetSessionCookie(w, sess.Token, sess.ExpiresAt)

	if next == "" || !strings.HasPrefix(next, "/") {
		next = "/dashboard"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// ─────────────────────────────────────────────────────────────────────────────
// Register handler
// ─────────────────────────────────────────────────────────────────────────────

type RegisterData struct {
	PageData
	Username string
	Email    string
}

// RegisterHandler serves GET/POST /register.
type RegisterHandler struct {
	tmpl *Renderer
	db   *db.DB
	log  *logger.Logger
}

func NewRegisterHandler(r *Renderer, database *db.DB, l *logger.Logger) *RegisterHandler {
	return &RegisterHandler{tmpl: r, db: database, log: l}
}

func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if middleware.UserFromCtx(r) != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.showForm(w, r, "", "", "")
	case http.MethodPost:
		h.handlePost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *RegisterHandler) showForm(w http.ResponseWriter, r *http.Request, username, email, errMsg string) {
	pd := NewPageData(r, "Create Account")
	pd.FlashErr = errMsg
	h.tmpl.Render(w, "register", RegisterData{PageData: pd, Username: username, Email: email})
}

func (h *RegisterHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		h.showForm(w, r, "", "", "Could not parse form.")
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	switch {
	case len(username) < 3 || len(username) > 32:
		h.showForm(w, r, username, email, "Username must be 3–32 characters.")
		return
	case !isAlphanumeric(username):
		h.showForm(w, r, username, email, "Username may only contain letters, numbers, and underscores.")
		return
	case !strings.Contains(email, "@") || !strings.Contains(email, "."):
		h.showForm(w, r, username, email, "A valid email address is required.")
		return
	case len(password) < 8:
		h.showForm(w, r, username, email, "Password must be at least 8 characters.")
		return
	case password != confirm:
		h.showForm(w, r, username, email, "Passwords do not match.")
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		h.log.Error("hash password failed", "err", err)
		h.showForm(w, r, username, email, "An error occurred. Please try again.")
		return
	}

	user, err := h.db.CreateUser(username, email, hash, "user")
	if err == db.ErrDuplicate {
		h.showForm(w, r, username, email, "Username or email is already in use.")
		return
	}
	if err != nil {
		h.log.Error("create user failed", "err", err)
		h.showForm(w, r, username, email, "An error occurred. Please try again.")
		return
	}

	h.log.Info("user registered", "username", user.Username, "email", user.Email)
	http.Redirect(w, r, "/login?msg=Account+created.+Please+sign+in.", http.StatusSeeOther)
}

func isAlphanumeric(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// Logout handler
// ─────────────────────────────────────────────────────────────────────────────

// LogoutHandler serves POST /logout.
type LogoutHandler struct {
	db  *db.DB
	log *logger.Logger
}

func NewLogoutHandler(database *db.DB, l *logger.Logger) *LogoutHandler {
	return &LogoutHandler{db: database, log: l}
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := middleware.UserFromCtx(r)
	tok := middleware.SessionTokenFromCtx(r)

	if tok != "" {
		_ = h.db.DeleteSession(tok)
	}
	if user != nil {
		h.log.Info("logout", "username", user.Username)
	}

	http.SetCookie(w, &http.Cookie{
		Name: "session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
	http.Redirect(w, r, "/login?msg=You+have+been+signed+out.", http.StatusSeeOther)
}

// ─────────────────────────────────────────────────────────────────────────────
// Profile handler
// ─────────────────────────────────────────────────────────────────────────────

type ProfileData struct {
	PageData
}

// ProfileHandler serves GET/POST /profile.
type ProfileHandler struct {
	tmpl *Renderer
	db   *db.DB
	log  *logger.Logger
}

func NewProfileHandler(r *Renderer, database *db.DB, l *logger.Logger) *ProfileHandler {
	return &ProfileHandler{tmpl: r, db: database, log: l}
}

func (h *ProfileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		pd := NewPageData(r, "Profile")
		h.tmpl.Render(w, "profile", ProfileData{PageData: pd})
	case http.MethodPost:
		h.handlePost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *ProfileHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/profile?err=Could+not+parse+form.", http.StatusSeeOther)
		return
	}

	user := middleware.UserFromCtx(r)
	current := r.FormValue("current_password")
	newPwd := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	// Re-fetch user to get current hash (ctx user may be stale)
	fresh, err := h.db.UserByID(user.ID)
	if err != nil {
		http.Redirect(w, r, "/profile?err=Could+not+load+account.", http.StatusSeeOther)
		return
	}

	if !auth.CheckPassword(current, fresh.Password) {
		http.Redirect(w, r, "/profile?err=Current+password+is+incorrect.", http.StatusSeeOther)
		return
	}
	if len(newPwd) < 8 {
		http.Redirect(w, r, "/profile?err=New+password+must+be+at+least+8+characters.", http.StatusSeeOther)
		return
	}
	if newPwd != confirm {
		http.Redirect(w, r, "/profile?err=Passwords+do+not+match.", http.StatusSeeOther)
		return
	}

	hash, err := auth.HashPassword(newPwd)
	if err != nil {
		http.Redirect(w, r, "/profile?err=An+error+occurred.", http.StatusSeeOther)
		return
	}
	if err := h.db.UpdateUserPassword(user.ID, hash); err != nil {
		http.Redirect(w, r, "/profile?err=Could+not+update+password.", http.StatusSeeOther)
		return
	}

	h.log.Info("password changed", "username", user.Username)
	// Invalidate all sessions and force re-login
	_ = h.db.DeleteUserSessions(user.ID)
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/login?msg=Password+changed.+Please+sign+in+again.", http.StatusSeeOther)
}
