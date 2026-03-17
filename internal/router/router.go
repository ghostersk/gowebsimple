// Package router wires together all routes and middleware.
//
// To add a new page:
//  1. Create internal/handlers/mypage.go with a handler struct
//  2. Create web/templates/pages/mypage.html
//  3. Add one mux.Handle() line in the "Page routes" section below
//  4. Optionally add a NavItem in handlers/renderer.go → DefaultNav
package router

import (
	"net/http"
	"path/filepath"
	"time"

	"goapp/internal/auth"
	"goapp/internal/db"
	"goapp/internal/handlers"
	"goapp/internal/logger"
	"goapp/internal/middleware"
)

// New builds and returns the application's root http.Handler.
func New(staticDir, templateDir string, database *db.DB, log *logger.Logger) (http.Handler, error) {
	renderer, err := handlers.NewRenderer(filepath.Clean(templateDir))
	if err != nil {
		return nil, err
	}

	// Rate limiter: 10 login attempts per minute per IP
	loginLimiter := auth.NewRateLimiter(10, time.Minute) // 60s

	mux := http.NewServeMux()

	// ── Static assets ─────────────────────────────────────────────────────────
	mux.Handle("/static/",
		http.StripPrefix("/static/",
			http.FileServer(http.Dir(filepath.Clean(staticDir))),
		),
	)

	// ── Public routes ─────────────────────────────────────────────────────────
	mux.Handle("/", handlers.NewHomeHandler(renderer))
	mux.Handle("/about", handlers.NewAboutHandler(renderer))
	mux.Handle("/contact", handlers.NewContactHandler(renderer))
	mux.Handle("/login", handlers.NewLoginHandler(renderer, database, log, loginLimiter))
	mux.Handle("/register", handlers.NewRegisterHandler(renderer, database, log))
	mux.Handle("/logout", handlers.NewLogoutHandler(database, log))

	// ── Authenticated routes ───────────────────────────────────────────────────
	mux.Handle("/dashboard", middleware.RequireAuth(handlers.NewDashboardHandler(renderer)))
	mux.Handle("/profile", middleware.RequireAuth(handlers.NewProfileHandler(renderer, database, log)))

	// ── Admin routes ──────────────────────────────────────────────────────────
	adminMW := func(h http.Handler) http.Handler {
		return middleware.RequireAuth(middleware.RequireAdmin(h))
	}

	mux.Handle("/admin/users",
		adminMW(handlers.NewAdminUsersHandler(renderer, database, log)))
	mux.Handle("/admin/users/action",
		adminMW(handlers.NewAdminUserActionHandler(database, log)))
	mux.Handle("/admin/users/create",
		adminMW(handlers.NewAdminCreateUserHandler(database, log)))
	mux.Handle("/admin/logs",
		adminMW(handlers.NewAdminLogsHandler(renderer, database, log)))

	// ── Global middleware ─────────────────────────────────────────────────────
	return middleware.Chain(mux,
		middleware.Recovery(log),
		middleware.Logger(log),
		middleware.SecureHeaders,
		middleware.Auth(database),
	), nil
}
