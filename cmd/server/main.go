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
	"goapp/internal/security"
)

func main() {
	dataDir  := flag.String("data",    envOr("DATA_DIR", "./data"), "Config/database directory")
	mfaOff   := flag.String("mfaoff",  "",                          "Disable MFA for admin username")
	pwReset  := flag.String("pwreset", "",                          "Reset password: -pwreset <username>")
	newPwd   := flag.String("newpwd",  "",                          "New password for -pwreset")
	flag.Parse()

	cfg, err := config.Load(*dataDir)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if os.Getenv("DEBUG") == "1" {
		cfg.Debug = true
	}

	// ── Database ───────────────────────────────────────────────────────────────
	// Register security schema migrator before opening DB
	db.SetSecurityMigrator(func(d *db.DB) error {
		return security.Migrate(d)
	})
	database, err := db.Open(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer database.Close()

	// ── Logger ─────────────────────────────────────────────────────────────────
	appLog := logger.New(database, cfg.Debug)
	appLog.Info("server starting", "addr", cfg.Addr(), "debug", cfg.Debug, "driver", database.Driver())

	// ── CLI admin operations ───────────────────────────────────────────────────
	if *mfaOff != "" {
		runMFAOff(database, *mfaOff)
		return
	}
	if *pwReset != "" {
		if *newPwd == "" {
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

	// ── Seed admin ─────────────────────────────────────────────────────────────
	seedAdmin(database, appLog)

	// ── Security engine ────────────────────────────────────────────────────────
	var (
		secEngine *security.Engine
		geoip     *security.GeoIPDB
	)

	if cfg.Security.Enabled {
		// GeoIP database path
		geoipPath := cfg.Security.GeoIPDBPath
		if geoipPath == "" {
			geoipPath = filepath.Join(*dataDir, "GeoLite2-Country.mmdb")
		}

		geoip = security.NewGeoIPDB(geoipPath)

		if cfg.Security.GeoIPEnabled {
			// Try to load existing database
			if err := geoip.Load(); err != nil {
				appLog.Warn("geoip: initial load failed (will retry on download)", "err", err)
			} else {
				appLog.Info("geoip: database loaded", "path", geoipPath)
			}
			// Start auto-updater if license key is set
			updateInterval := time.Duration(cfg.Security.GeoIPUpdateDays) * 24 * time.Hour
			if updateInterval == 0 {
				updateInterval = 7 * 24 * time.Hour
			}
			security.StartAutoUpdater(geoip, cfg.Security.MaxMindLicenseKey, geoipPath, updateInterval, appLog.Info)
		}

		eng, err := security.NewEngine(database, &cfg.Security, geoip, cfg.ReverseProxies)
		if err != nil {
			log.Fatalf("security engine: %v", err)
		}
		secEngine = eng
		appLog.Info("security: engine started",
			"auto_ban", cfg.Security.AutoBanEnabled,
			"geoip", cfg.Security.GeoIPEnabled,
			"threshold", cfg.Security.AutoBanThreshold)
	} else {
		appLog.Info("security: disabled (set security.enabled=true in config.json to activate)")
	}

	// ── Background jobs ────────────────────────────────────────────────────────
	logger.PruneJob(appLog, cfg.LogRetentionDays)
	auth.InitCSRF([]byte(cfg.CSRFKey))

	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			n, err := database.PruneExpiredSessions()
			if err != nil {
				appLog.Error("session prune", "err", err)
			} else if n > 0 {
				appLog.Debug("session prune", "deleted", n)
			}
		}
	}()

	// ── Build router ───────────────────────────────────────────────────────────
	cwd, _ := os.Getwd()
	staticDir := filepath.Join(cwd, "web", "static")
	templateDir := filepath.Join(cwd, "web", "templates")

	handler, err := router.New(staticDir, templateDir, database, appLog, cfg, secEngine, geoip)
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

func runPwReset(database *db.DB, username, password string) {
	user, err := database.UserByUsername(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pwreset: user %q not found\n", username)
		os.Exit(1)
	}
	if !user.IsAdmin() {
		fmt.Fprintf(os.Stderr, "pwreset: user %q is not an admin\n", username)
		os.Exit(1)
	}
	if len(password) < 8 {
		fmt.Fprintln(os.Stderr, "pwreset: password must be at least 8 characters")
		os.Exit(1)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pwreset: %v\n", err)
		os.Exit(1)
	}
	if err := database.UpdateUserPassword(user.ID, hash); err != nil {
		fmt.Fprintf(os.Stderr, "pwreset: %v\n", err)
		os.Exit(1)
	}
	_ = database.DeleteUserSessions(user.ID)
	fmt.Printf("✓ Password reset for admin %q — all sessions invalidated\n", username)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
