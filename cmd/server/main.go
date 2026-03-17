package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"goapp/internal/auth"
	"goapp/internal/db"
	"goapp/internal/logger"
	"goapp/internal/router"
)

func main() {
	// ── Flags ─────────────────────────────────────────────────────────────────
	addr := flag.String("addr", envOr("PORT", ":5000"), "TCP address to listen on")
	dataDir := flag.String("data", envOr("DATA_DIR", "./data"), "Directory for SQLite database")
	debug := flag.Bool("debug", os.Getenv("DEBUG") == "1", "Enable debug-level logging")
	csrfKey := flag.String("csrf-key", envOr("CSRF_KEY", ""), "32-byte hex HMAC key for CSRF tokens")
	flag.Parse()

	// ── Working-directory paths ────────────────────────────────────────────────
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("cannot determine working directory: %v", err)
	}
	staticDir := filepath.Join(cwd, "web", "static")
	templateDir := filepath.Join(cwd, "web", "templates")

	// ── Database ───────────────────────────────────────────────────────────────
	database, err := db.Open(*dataDir)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer database.Close()

	// ── Logger ─────────────────────────────────────────────────────────────────
	appLog := logger.New(database, *debug)
	appLog.Info("server starting", "addr", *addr, "debug", *debug)

	// Seed default admin on first run (no admin exists yet).
	seedAdmin(database, appLog)

	// Background jobs.
	logger.PruneJob(appLog, 90)

	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			n, err := database.PruneExpiredSessions()
			if err != nil {
				appLog.Error("session prune", "err", err)
			} else if n > 0 {
				appLog.Debug("session prune", "deleted", n)
			}
		}
	}()

	// ── CSRF key ───────────────────────────────────────────────────────────────
	key := *csrfKey
	if key == "" {
		key, err = auth.RandomKey(32)
		if err != nil {
			log.Fatalf("csrf key: %v", err)
		}
		appLog.Warn("CSRF_KEY not set — using ephemeral key (sessions invalid after restart)")
	}
	auth.InitCSRF([]byte(key))

	// ── Router ─────────────────────────────────────────────────────────────────
	handler, err := router.New(staticDir, templateDir, database, appLog)
	if err != nil {
		log.Fatalf("router: %v", err)
	}

	// ── HTTP server ────────────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:         *addr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	appLog.Info("server ready", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// seedAdmin creates the default admin account on first run.
// Credentials: admin / Admin1234!  — change immediately in production.
func seedAdmin(database *db.DB, appLog *logger.Logger) {
	count, _ := database.CountUsers()
	if count > 0 {
		return // already seeded
	}
	hash, err := auth.HashPassword("Admin1234!")
	if err != nil {
		appLog.Error("seed admin: hash failed", "err", err)
		return
	}
	user, err := database.CreateUser("admin", "admin@localhost", hash, "admin")
	if err != nil {
		appLog.Error("seed admin: create failed", "err", err)
		return
	}
	appLog.Warn("default admin created — change password immediately",
		"username", user.Username,
		"password", "Admin1234!")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
