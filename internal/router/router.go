// Package router wires together all routes and middleware.
//
// To add a new page:
//  1. Create internal/handlers/mypage.go
//  2. Create web/templates/pages/mypage.html
//     - Use "pub_" prefix for public/landing layout
//     - Use "bare_" prefix for minimal layout
//     - Default → sidebar layout
//  3. Add one mux.Handle() line below
//  4. Optionally add a NavItem in handlers/renderer.go → DefaultNav
package router

import (
	"net/http"
	"path/filepath"
	"time"

	"goapp/internal/auth"
	"goapp/internal/config"
	"goapp/internal/db"
	"goapp/internal/handlers"
	"goapp/internal/logger"
	"goapp/internal/mailer"
	"goapp/internal/middleware"
)

// New builds and returns the application root http.Handler.
// The Mailer is constructed internally from cfg.Email and injected into
// any handlers that send email (e.g. contact form).
func New(staticDir, templateDir string, database *db.DB, log *logger.Logger, cfg *config.Config) (http.Handler, error) {
	renderer, err := handlers.NewRenderer(filepath.Clean(templateDir))
	if err != nil {
		return nil, err
	}

	// Build the mailer — it is a no-op when cfg.Email.Enabled == false.
	m := mailer.New(&cfg.Email)
	if m.Enabled() {
		log.Info("mailer: enabled", "host", cfg.Email.SMTPHost, "port", cfg.Email.SMTPPort, "enc", cfg.Email.Encryption)
	} else {
		log.Info("mailer: disabled (set email.enabled=true in config.json to activate)")
	}

	// Propagate registration setting into the handlers package so all
	// templates can conditionally show/hide the registration link.
	handlers.SetAllowRegistration(cfg.AllowRegistration)

	errHandler  := handlers.NewErrorHandler(renderer)
	pendingMFA  := handlers.NewPendingMFAStore()
	loginLimiter := auth.NewRateLimiter(10, time.Minute)

	mux := http.NewServeMux()

	// ── Static assets ─────────────────────────────────────────────────────────
	mux.Handle("/static/",
		http.StripPrefix("/static/",
			http.FileServer(http.Dir(filepath.Clean(staticDir))),
		),
	)

	// ── Favicon ───────────────────────────────────────────────────────────────
	// Browsers request /favicon.ico automatically. We serve the PNG from
	// web/static/img/favicon.png for both /favicon.ico and /favicon.png.
	// Replace web/static/img/favicon.png with your own image to customise.
	faviconPath := filepath.Join(filepath.Clean(staticDir), "img", "favicon.png")
	serveFavicon := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFile(w, r, faviconPath)
	}
	mux.HandleFunc("/favicon.ico", serveFavicon)
	mux.HandleFunc("/favicon.png", serveFavicon)

	// ── Public routes ─────────────────────────────────────────────────────────
	mux.Handle("/", handlers.NewHomeHandler(renderer))
	mux.Handle("/landing", handlers.NewPubLandingHandler(renderer))
	mux.Handle("/about", handlers.NewAboutHandler(renderer))
	mux.Handle("/contact", handlers.NewContactHandler(renderer, m))
	mux.Handle("/login", handlers.NewLoginHandler(renderer, database, log, loginLimiter, pendingMFA))
	mux.Handle("/login/mfa", handlers.NewMFAChallengeHandler(renderer, database, log, pendingMFA))
	// /register is only available when allow_registration=true in config.json
	if cfg.AllowRegistration {
		mux.Handle("/register", handlers.NewRegisterHandler(renderer, database, log))
	} else {
		mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
			errHandler.RenderError(w, r, 404, "Registration Closed",
				"Public registration is not available. Contact an administrator to create an account.")
		})
	}
	mux.Handle("/logout", handlers.NewLogoutHandler(database, log))

	// ── Authenticated routes ───────────────────────────────────────────────────
	mux.Handle("/dashboard", middleware.RequireAuth(handlers.NewDashboardHandler(renderer)))
	mux.Handle("/profile",   middleware.RequireAuth(handlers.NewProfileHandler(renderer, database, log)))
	mux.Handle("/profile/mfa", middleware.RequireAuth(handlers.NewMFASetupHandler(renderer, database, log)))

	// ── Admin routes ──────────────────────────────────────────────────────────
	adminMW := func(h http.Handler) http.Handler {
		return middleware.RequireAuth(middleware.RequireAdmin(h))
	}
	mux.Handle("/admin/users",        adminMW(handlers.NewAdminUsersHandler(renderer, database, log)))
	mux.Handle("/admin/users/action", adminMW(handlers.NewAdminUserActionHandler(database, log)))
	mux.Handle("/admin/users/create", adminMW(handlers.NewAdminCreateUserHandler(database, log)))
	mux.Handle("/admin/logs",         adminMW(handlers.NewAdminLogsHandler(renderer, database, log)))

	// ── Error pages ──────────────────────────────────────────────────────────
	mux.HandleFunc("/error/403", func(w http.ResponseWriter, r *http.Request) {
		errHandler.Forbidden(w, r)
	})
	mux.HandleFunc("/error/500", func(w http.ResponseWriter, r *http.Request) {
		errHandler.InternalError(w, r)
	})

	// ── 404 catch-all ─────────────────────────────────────────────────────────
	mux.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) {
		errHandler.NotFound(w, r)
	})

	// Wrap ServeMux to render proper 404 for unknown routes
	wrappedMux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &captureWriter{ResponseWriter: w}
		mux.ServeHTTP(rw, r)
		if rw.status == http.StatusNotFound {
			errHandler.NotFound(w, r)
		}
	})

	// ── Global middleware ─────────────────────────────────────────────────────
	return middleware.Chain(wrappedMux,
		middleware.Recovery(log),
		middleware.Logger(log, cfg),
		middleware.SecureHeaders,
		middleware.DomainGuard(cfg),
		middleware.Auth(database),
	), nil
}

// captureWriter intercepts the 404 response from http.ServeMux so we can
// replace the plain-text "404 page not found" with our styled error page.
//
// How it works:
//   1. WriteHeader(404) is called by the mux → we record the status but
//      deliberately do NOT forward it to the real ResponseWriter yet.
//   2. Write(body) is called with the default "404 page not found" text
//      → we discard it silently.
//   3. After mux.ServeHTTP returns, we check: was status 404?
//      If yes, call errHandler.NotFound(real_w, r) which writes the proper
//      headers and styled HTML to the real ResponseWriter.
//
// For all other status codes (200, 301, 500, etc.) we forward immediately
// so normal responses are unaffected.
type captureWriter struct {
	http.ResponseWriter
	status int
}

func (cw *captureWriter) WriteHeader(code int) {
	cw.status = code
	if code != http.StatusNotFound {
		// Forward non-404 headers immediately.
		cw.ResponseWriter.WriteHeader(code)
	}
	// 404: hold the header — we will replace it with our styled error page.
}

func (cw *captureWriter) Write(b []byte) (int, error) {
	if cw.status == http.StatusNotFound {
		// Discard the default "404 page not found" text body.
		// Our styled error page will be written by errHandler.NotFound instead.
		return len(b), nil
	}
	return cw.ResponseWriter.Write(b)
}
