// Package router wires together all routes and middleware.
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
	"goapp/internal/security"
)

// New builds and returns the application root http.Handler.
func New(
	staticDir, templateDir string,
	database *db.DB,
	log *logger.Logger,
	cfg *config.Config,
	secEngine *security.Engine,
	geoip *security.GeoIPDB,
) (http.Handler, error) {

	renderer, err := handlers.NewRenderer(filepath.Clean(templateDir))
	if err != nil {
		return nil, err
	}

	m := mailer.New(&cfg.Email)
	handlers.SetAllowRegistration(cfg.AllowRegistration)

	errHandler := handlers.NewErrorHandler(renderer)

	// AutoBanner — nil when security is disabled
	var banner *security.AutoBanner
	if secEngine != nil {
		banner = security.NewAutoBanner(database, &cfg.Security, secEngine)
	}

	pendingMFA := handlers.NewPendingMFAStore()
	loginLimiter := auth.NewRateLimiter(10, time.Minute)

	mux := http.NewServeMux()

	// ── Static assets ──────────────────────────────────────────────────────────
	mux.Handle("/static/",
		http.StripPrefix("/static/",
			http.FileServer(http.Dir(filepath.Clean(staticDir))),
		),
	)
	faviconPath := filepath.Join(filepath.Clean(staticDir), "img", "favicon.png")
	serveFavicon := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFile(w, r, faviconPath)
	}
	mux.HandleFunc("/favicon.ico", serveFavicon)
	mux.HandleFunc("/favicon.png", serveFavicon)

	// ── Public routes ──────────────────────────────────────────────────────────
	mux.Handle("/", handlers.NewHomeHandler(renderer))
	mux.Handle("/landing", handlers.NewPubLandingHandler(renderer))
	mux.Handle("/about", handlers.NewAboutHandler(renderer))
	mux.Handle("/contact", handlers.NewContactHandler(renderer, m))
	mux.Handle("/login", handlers.NewLoginHandler(renderer, database, log, loginLimiter, pendingMFA, banner))
	mux.Handle("/login/mfa", handlers.NewMFAChallengeHandler(renderer, database, log, pendingMFA))

	if cfg.AllowRegistration {
		mux.Handle("/register", handlers.NewRegisterHandler(renderer, database, log))
	} else {
		mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
			errHandler.RenderError(w, r, 404, "Registration Closed",
				"Public registration is not available. Contact an administrator.")
		})
	}
	mux.Handle("/logout", handlers.NewLogoutHandler(database, log))

	// ── Authenticated routes ───────────────────────────────────────────────────
	mux.Handle("/dashboard", middleware.RequireAuth(handlers.NewDashboardHandler(renderer)))
	mux.Handle("/profile", middleware.RequireAuth(handlers.NewProfileHandler(renderer, database, log)))
	mux.Handle("/profile/mfa", middleware.RequireAuth(handlers.NewMFASetupHandler(renderer, database, log)))

	// ── Admin routes ──────────────────────────────────────────────────────────
	adminMW := func(h http.Handler) http.Handler {
		return middleware.RequireAuth(middleware.RequireAdmin(h))
	}
	mux.Handle("/admin/users", adminMW(handlers.NewAdminUsersHandler(renderer, database, log)))
	mux.Handle("/admin/users/action", adminMW(handlers.NewAdminUserActionHandler(database, log)))
	mux.Handle("/admin/users/create", adminMW(handlers.NewAdminCreateUserHandler(database, log)))
	mux.Handle("/admin/logs", adminMW(handlers.NewAdminLogsHandler(renderer, database, log)))

	// ── Security admin routes — always registered so admins can configure security
	// even when security.enabled=false. Handlers receive nil engine when disabled
	// and show an informational banner prompting the user to enable security.
	mux.Handle("/admin/security/bans",
		adminMW(handlers.NewAdminBansHandler(renderer, database, log, secEngine)))
	mux.Handle("/admin/security/bans/action",
		adminMW(handlers.NewAdminBanActionHandler(database, log, secEngine)))
	mux.Handle("/admin/security/rules",
		adminMW(handlers.NewAdminIPRulesHandler(renderer, database, log, secEngine)))
	mux.Handle("/admin/security/countries",
		adminMW(handlers.NewAdminCountryRulesHandler(renderer, database, log, secEngine, geoip)))
	mux.Handle("/admin/security/attempts",
		adminMW(handlers.NewAdminAttemptsHandler(renderer, database, log)))

	// ── Error pages ────────────────────────────────────────────────────────────
	mux.HandleFunc("/error/403", func(w http.ResponseWriter, r *http.Request) { errHandler.Forbidden(w, r) })
	mux.HandleFunc("/error/500", func(w http.ResponseWriter, r *http.Request) { errHandler.InternalError(w, r) })
	mux.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) { errHandler.NotFound(w, r) })

	// 404 catch-all
	wrappedMux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &captureWriter{ResponseWriter: w}
		mux.ServeHTTP(rw, r)
		if rw.status == http.StatusNotFound {
			errHandler.NotFound(w, r)
		}
	})

	// ── Build middleware chain ─────────────────────────────────────────────────
	// Order (outermost → innermost):
	// Recovery → Logger → SecureHeaders → DomainGuard → Auth → IPSecurity → Mux
	chain := []func(http.Handler) http.Handler{
		middleware.Recovery(log),
		middleware.Logger(log, cfg),
		middleware.SecureHeaders,
		middleware.DomainGuard(cfg),
		middleware.Auth(database),
	}

	// Add IP security middleware only when engine is configured
	if secEngine != nil {
		realIPFn := middleware.RealIPFromRequest
		renderBlock := func(w http.ResponseWriter, r *http.Request, reason string) {
			errHandler.RenderError(w, r, http.StatusForbidden, "Access Denied", reason)
		}
		chain = append(chain, security.Middleware(secEngine, realIPFn, renderBlock))
	}

	return middleware.Chain(wrappedMux, chain...), nil
}

type captureWriter struct {
	http.ResponseWriter
	status int
}

func (cw *captureWriter) WriteHeader(code int) {
	cw.status = code
	if code != http.StatusNotFound {
		cw.ResponseWriter.WriteHeader(code)
	}
}

func (cw *captureWriter) Write(b []byte) (int, error) {
	if cw.status == http.StatusNotFound {
		return len(b), nil
	}
	return cw.ResponseWriter.Write(b)
}
