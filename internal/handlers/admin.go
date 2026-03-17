package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"goapp/internal/auth"
	"goapp/internal/db"
	"goapp/internal/logger"
	"goapp/internal/middleware"
)

// ─────────────────────────────────────────────────────────────────────────────
// Admin: User Management
// ─────────────────────────────────────────────────────────────────────────────

const usersPerPage = 20

type AdminUsersData struct {
	PageData
	Users      []*db.User
	Total      int
	Page       int
	TotalPages int
}

// AdminUsersHandler serves GET /admin/users.
type AdminUsersHandler struct {
	tmpl *Renderer
	db   *db.DB
	log  *logger.Logger
}

func NewAdminUsersHandler(r *Renderer, database *db.DB, l *logger.Logger) *AdminUsersHandler {
	return &AdminUsersHandler{tmpl: r, db: database, log: l}
}

func (h *AdminUsersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	page := qInt(r, "page", 1)
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * usersPerPage

	total, _ := h.db.CountUsers()
	users, err := h.db.AllUsers(usersPerPage, offset)
	if err != nil {
		h.log.Error("admin: list users", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	totalPages := (total + usersPerPage - 1) / usersPerPage
	if totalPages == 0 {
		totalPages = 1
	}

	h.tmpl.Render(w, "admin_users", AdminUsersData{
		PageData:   NewPageData(r, "User Management"),
		Users:      users,
		Total:      total,
		Page:       page,
		TotalPages: totalPages,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin: User Action
// ─────────────────────────────────────────────────────────────────────────────

// AdminUserActionHandler serves POST /admin/users/action.
type AdminUserActionHandler struct {
	db  *db.DB
	log *logger.Logger
}

func NewAdminUserActionHandler(database *db.DB, l *logger.Logger) *AdminUserActionHandler {
	return &AdminUserActionHandler{db: database, log: l}
}

func (h *AdminUserActionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/users?err=Could+not+parse+form.", http.StatusSeeOther)
		return
	}

	action := r.FormValue("action")
	userID, err := strconv.ParseInt(r.FormValue("user_id"), 10, 64)
	if err != nil {
		http.Redirect(w, r, "/admin/users?err=Invalid+user+ID.", http.StatusSeeOther)
		return
	}

	actor := middleware.UserFromCtx(r)

	// Prevent self-lockout.
	if userID == actor.ID && (action == "disable" || action == "delete" || action == "demote") {
		http.Redirect(w, r, "/admin/users?err=You+cannot+modify+your+own+account+this+way.", http.StatusSeeOther)
		return
	}

	target, err := h.db.UserByID(userID)
	if err != nil {
		http.Redirect(w, r, "/admin/users?err=User+not+found.", http.StatusSeeOther)
		return
	}

	switch action {
	case "enable":
		err = h.db.UpdateUserActive(userID, true)
		h.log.Info("admin: user enabled", "actor", actor.Username, "target", target.Username)
	case "disable":
		err = h.db.UpdateUserActive(userID, false)
		if err == nil {
			_ = h.db.DeleteUserSessions(userID)
		}
		h.log.Info("admin: user disabled", "actor", actor.Username, "target", target.Username)
	case "promote":
		err = h.db.UpdateUserRole(userID, "admin")
		h.log.Info("admin: promoted to admin", "actor", actor.Username, "target", target.Username)
	case "demote":
		err = h.db.UpdateUserRole(userID, "user")
		h.log.Info("admin: demoted to user", "actor", actor.Username, "target", target.Username)
	case "delete":
		err = h.db.DeleteUser(userID)
		h.log.Warn("admin: user deleted", "actor", actor.Username, "target", target.Username)
	case "reset_password":
		newPwd := r.FormValue("new_password")
		if len(newPwd) < 8 {
			http.Redirect(w, r, "/admin/users?err=Password+must+be+at+least+8+characters.", http.StatusSeeOther)
			return
		}
		hash, herr := auth.HashPassword(newPwd)
		if herr != nil {
			http.Redirect(w, r, "/admin/users?err=Could+not+hash+password.", http.StatusSeeOther)
			return
		}
		err = h.db.UpdateUserPassword(userID, hash)
		if err == nil {
			_ = h.db.DeleteUserSessions(userID)
		}
		h.log.Warn("admin: password reset", "actor", actor.Username, "target", target.Username)
	case "disable_mfa":
		err = h.db.DisableMFA(userID)
		if err == nil {
			_ = h.db.DeleteUserSessions(userID)
		}
		h.log.Warn("admin: mfa disabled", "actor", actor.Username, "target", target.Username)
	default:
		http.Redirect(w, r, "/admin/users?err=Unknown+action.", http.StatusSeeOther)
		return
	}

	if err != nil {
		h.log.Error("admin: user action failed", "action", action, "err", err)
		http.Redirect(w, r, "/admin/users?err=Action+failed.", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin/users?msg=Action+completed.", http.StatusSeeOther)
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin: Create User
// ─────────────────────────────────────────────────────────────────────────────

// AdminCreateUserHandler serves POST /admin/users/create.
type AdminCreateUserHandler struct {
	db  *db.DB
	log *logger.Logger
}

func NewAdminCreateUserHandler(database *db.DB, l *logger.Logger) *AdminCreateUserHandler {
	return &AdminCreateUserHandler{db: database, log: l}
}

func (h *AdminCreateUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/users?err=Could+not+parse+form.", http.StatusSeeOther)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	role := r.FormValue("role")
	if role != "admin" {
		role = "user"
	}

	switch {
	case len(username) < 3:
		http.Redirect(w, r, "/admin/users?err=Username+too+short+(min+3).", http.StatusSeeOther)
		return
	case !strings.Contains(email, "@"):
		http.Redirect(w, r, "/admin/users?err=Invalid+email+address.", http.StatusSeeOther)
		return
	case len(password) < 8:
		http.Redirect(w, r, "/admin/users?err=Password+must+be+8%2B+characters.", http.StatusSeeOther)
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Redirect(w, r, "/admin/users?err=Could+not+hash+password.", http.StatusSeeOther)
		return
	}

	actor := middleware.UserFromCtx(r)
	user, err := h.db.CreateUser(username, email, hash, role)
	if err == db.ErrDuplicate {
		http.Redirect(w, r, "/admin/users?err=Username+or+email+already+in+use.", http.StatusSeeOther)
		return
	}
	if err != nil {
		h.log.Error("admin: create user failed", "err", err)
		http.Redirect(w, r, "/admin/users?err=Could+not+create+user.", http.StatusSeeOther)
		return
	}

	h.log.Info("admin: user created", "actor", actor.Username, "new_user", user.Username, "role", role)
	http.Redirect(w, r, "/admin/users?msg=User+created+successfully.", http.StatusSeeOther)
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin: Log Viewer
// ─────────────────────────────────────────────────────────────────────────────

const logsPerPage = 50

type AdminLogsData struct {
	PageData
	Logs       []*db.LogEntry
	Total      int
	Page       int
	TotalPages int
	Level      string
	Search     string
	Levels     []string
}

// AdminLogsHandler serves GET /admin/logs.
type AdminLogsHandler struct {
	tmpl *Renderer
	db   *db.DB
	log  *logger.Logger
}

func NewAdminLogsHandler(r *Renderer, database *db.DB, l *logger.Logger) *AdminLogsHandler {
	return &AdminLogsHandler{tmpl: r, db: database, log: l}
}

func (h *AdminLogsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	level := r.URL.Query().Get("level")
	search := r.URL.Query().Get("search")
	page := qInt(r, "page", 1)
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * logsPerPage

	total, _ := h.db.CountLogs(level, search)
	logs, err := h.db.QueryLogs(db.LogFilter{
		Level:  level,
		Search: search,
		Limit:  logsPerPage,
		Offset: offset,
	})
	if err != nil {
		h.log.Error("admin: query logs", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	totalPages := (total + logsPerPage - 1) / logsPerPage
	if totalPages == 0 {
		totalPages = 1
	}

	h.tmpl.Render(w, "admin_logs", AdminLogsData{
		PageData:   NewPageData(r, "Application Logs"),
		Logs:       logs,
		Total:      total,
		Page:       page,
		TotalPages: totalPages,
		Level:      level,
		Search:     search,
		Levels:     []string{"", "ERROR", "WARN", "INFO", "DEBUG"},
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helper
// ─────────────────────────────────────────────────────────────────────────────

// qInt reads an integer query param with a default.
func qInt(r *http.Request, key string, def int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
