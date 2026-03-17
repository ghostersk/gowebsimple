package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"goapp/internal/auth"
	"goapp/internal/config"
	"goapp/internal/db"
	"goapp/internal/logger"
	"goapp/internal/router"
)

func main() {
	// ── Flags ─────────────────────────────────────────────────────────────────
	dataDir   := flag.String("data",     envOr("DATA_DIR", "./data"), "Config/database directory")
	mfaOff    := flag.String("mfaoff",   "",                          "Disable MFA for admin username")
	pwReset   := flag.String("pwreset",  "",                          "Reset password: -pwreset <username> \"<password>\"")
	newPwd    := flag.String("newpwd",   "",                          "New password for -pwreset")
	flag.Parse()

	// ── Config ────────────────────────────────────────────────────────────────
	cfg, err := config.Load(*dataDir)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Override debug from env if set explicitly
	if os.Getenv("DEBUG") == "1" {
		cfg.Debug = true
	}

	// ── Database ───────────────────────────────────────────────────────────────
	database, err := db.Open(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer database.Close()

	// ── Logger ─────────────────────────────────────────────────────────────────
	appLog := logger.New(database, cfg.Debug)

	// ── CLI admin operations (run and exit) ────────────────────────────────────
	if *mfaOff != "" {
		runMFAOff(database, *mfaOff)
		return
	}
	if *pwReset != "" {
		if *newPwd == "" {
			// Check for positional arg after -pwreset
			args := flag.Args()
			if len(args) > 0 {
				*newPwd = args[0]
			}
		}
		if *newPwd == "" {
			fmt.Fprintln(os.Stderr, "Usage: -pwreset <username> -newpwd \"<password>\"")
			os.Exit(1)
		}
		runPwReset(database, *pwReset, *newPwd)
		return
	}

	// ── Normal server startup ──────────────────────────────────────────────────
	appLog.Info("server starting", "addr", cfg.Addr(), "debug", cfg.Debug,
		"driver", database.Driver(), "domain", cfg.WebDomain)

	// Seed default admin on first run
	seedAdmin(database, appLog)

	// Background jobs
	logger.PruneJob(appLog, cfg.LogRetentionDays)

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

	// Initialise CSRF key from config
	auth.InitCSRF([]byte(cfg.CSRFKey))

	// ── Paths ──────────────────────────────────────────────────────────────────
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("cannot determine working directory: %v", err)
	}
	staticDir   := filepath.Join(cwd, "web", "static")
	templateDir := filepath.Join(cwd, "web", "templates")

	// ── Router ─────────────────────────────────────────────────────────────────
	handler, err := router.New(staticDir, templateDir, database, appLog, cfg)
	if err != nil {
		log.Fatalf("router: %v", err)
	}

	// ── HTTP server ────────────────────────────────────────────────────────────
	srv := &http.Server{
		Addr:         cfg.Addr(),
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

// seedAdmin creates the default admin on first run.
func seedAdmin(database *db.DB, appLog *logger.Logger) {
	count, _ := database.CountUsers()
	if count > 0 {
		return
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
		"username", user.Username, "password", "Admin1234!")
}

// runMFAOff disables MFA for a named admin account (emergency CLI op).
func runMFAOff(database *db.DB, username string) {
	user, err := database.UserByUsername(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mfaoff: user %q not found\n", username)
		os.Exit(1)
	}
	if !user.IsAdmin() {
		fmt.Fprintf(os.Stderr, "mfaoff: user %q is not an admin\n", username)
		os.Exit(1)
	}
	if err := database.DisableMFA(user.ID); err != nil {
		fmt.Fprintf(os.Stderr, "mfaoff: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ MFA disabled for admin %q\n", username)
}

// runPwReset resets the password for a named admin account (emergency CLI op).
func runPwReset(database *db.DB, username, password string) {
	user, err := database.UserByUsername(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pwreset: user %q not found\n", username)
		os.Exit(1)
	}
	if !user.IsAdmin() {
		fmt.Fprintf(os.Stderr, "pwreset: user %q is not an admin — flag only works for admins\n", username)
		os.Exit(1)
	}
	if len(password) < 8 {
		fmt.Fprintln(os.Stderr, "pwreset: password must be at least 8 characters")
		os.Exit(1)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pwreset: hash failed: %v\n", err)
		os.Exit(1)
	}
	if err := database.UpdateUserPassword(user.ID, hash); err != nil {
		fmt.Fprintf(os.Stderr, "pwreset: %v\n", err)
		os.Exit(1)
	}
	// Invalidate all sessions for security
	_ = database.DeleteUserSessions(user.ID)
	fmt.Printf("✓ Password reset for admin %q — all sessions invalidated\n", username)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
