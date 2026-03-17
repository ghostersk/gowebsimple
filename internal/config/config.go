// Package config loads and saves the application configuration file (data/config.json).
//
// On first run the file is created automatically with safe defaults and
// auto-generated cryptographic secrets. Restart the server after editing it.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Config holds every application setting. Fields map 1-to-1 with config.json keys.
type Config struct {
	// ── Network ───────────────────────────────────────────────────────────────
	Host string `json:"host"` // bind address, e.g. "0.0.0.0" or "127.0.0.1"
	Port string `json:"port"` // listen port, e.g. "8080"

	// WebDomain restricts which Host header the app responds to.
	// "*" (default) accepts any domain.
	// "app.example.com" rejects requests for any other hostname with 404.
	WebDomain string `json:"web_domain"`

	// ReverseProxies lists trusted proxy IP addresses (exact or CIDR).
	// When the request comes from one of these IPs, X-Forwarded-For is used
	// to determine the real client IP shown in logs.
	ReverseProxies []string `json:"reverse_proxies"`

	// ── Database ──────────────────────────────────────────────────────────────
	// DatabaseURL is the connection string passed to database/sql.
	//
	// SQLite (default, no extra imports needed):
	//   "file:./data/app.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
	//
	// MySQL (add import _ "github.com/go-sql-driver/mysql", run go mod tidy):
	//   "mysql://dbuser:dbpass@tcp(127.0.0.1:3306)/mydb?parseTime=true&charset=utf8mb4"
	//
	// PostgreSQL (add import _ "github.com/lib/pq", run go mod tidy):
	//   "postgres://dbuser:dbpass@127.0.0.1:5432/mydb?sslmode=disable"
	//
	// The driver is auto-detected from the URL prefix (file:, mysql://, postgres://).
	DatabaseURL string `json:"database_url"`

	// ── Security ──────────────────────────────────────────────────────────────
	// CSRFKey is a 32-byte hex HMAC signing key for CSRF tokens.
	// Auto-generated on first run. Never change this on a live deployment —
	// it will invalidate all active sessions.
	CSRFKey string `json:"csrf_key"`

	// SessionSecret is reserved for future cookie signing.
	// Auto-generated on first run.
	SessionSecret string `json:"session_secret"`

	// ── Access control ────────────────────────────────────────────────────────
	// AllowRegistration: when false (default), the public /register page is
	// disabled and all "Sign Up" buttons are hidden. Only admins can create
	// accounts via the admin panel.
	AllowRegistration bool `json:"allow_registration"`

	// ── Email ─────────────────────────────────────────────────────────────────
	Email EmailConfig `json:"email"`

	// ── Logging ───────────────────────────────────────────────────────────────
	// Debug: when true, DEBUG-level log entries are written and shown in the
	// admin log viewer. Has no effect on ERROR/WARN/INFO logs.
	Debug bool `json:"debug"`

	// LogRetentionDays: log entries older than this are auto-pruned. Default 90.
	LogRetentionDays int `json:"log_retention_days"`
}

// EmailConfig holds SMTP settings for outbound email.
type EmailConfig struct {
	// Enabled: set to true to activate email sending. When false, Send()
	// returns immediately without error so the rest of the app still works.
	Enabled bool `json:"enabled"`

	// SMTPHost is the mail server hostname, e.g. "smtp.gmail.com".
	SMTPHost string `json:"smtp_host"`

	// SMTPPort is the mail server port.
	//  25  → plain (no encryption)   — Encryption: "none"
	//  465 → SSL/TLS (implicit)      — Encryption: "ssl"
	//  587 → STARTTLS (opportunistic)— Encryption: "starttls"
	SMTPPort int `json:"smtp_port"`

	// Encryption selects the transport security:
	//  "none"     — plain text, port 25
	//  "ssl"      — implicit TLS, port 465
	//  "starttls" — STARTTLS upgrade, port 587
	Encryption string `json:"encryption"` // "none" | "ssl" | "starttls"

	// Auth: set to false to skip SMTP authentication (some internal relays
	// allow unauthenticated sends). When false, Username and Password are ignored.
	Auth bool `json:"auth"`

	// Username is the SMTP login name (usually the sending email address).
	Username string `json:"username"`

	// Password is the SMTP login password or app-specific password.
	Password string `json:"password"`

	// FromAddress is the address that appears in the From: header,
	// e.g. "GoApp <noreply@example.com>".
	FromAddress string `json:"from_address"`
}

// defaults returns a Config with safe production defaults.
func defaults(dataDir string) Config {
	return Config{
		Host:             "0.0.0.0",
		Port:             "8080",
		WebDomain:        "*",
		ReverseProxies:   []string{},
		DatabaseURL:      "file:" + filepath.Join(dataDir, "app.db") + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)",
		AllowRegistration: false,
		Email: EmailConfig{
			Enabled:     false,
			SMTPHost:    "smtp.example.com",
			SMTPPort:    587,
			Encryption:  "starttls",
			Auth:        true,
			Username:    "noreply@example.com",
			Password:    "",
			FromAddress: "GoApp <noreply@example.com>",
		},
		Debug:            false,
		LogRetentionDays: 90,
	}
}

// Addr returns "host:port" for the HTTP listener.
func (c *Config) Addr() string { return c.Host + ":" + c.Port }

// Load reads data/config.json, creating it with defaults on first run.
// Missing fields are back-filled with defaults so upgrades are seamless.
func Load(dataDir string) (*Config, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("config: mkdir: %w", err)
	}

	cfgPath := filepath.Join(dataDir, "config.json")
	cfg := defaults(dataDir)

	data, err := os.ReadFile(cfgPath)
	if os.IsNotExist(err) {
		if err := generateSecrets(&cfg); err != nil {
			return nil, fmt.Errorf("config: generate secrets: %w", err)
		}
		if err := write(cfgPath, &cfg); err != nil {
			return nil, err
		}
		log.Printf("config: created %s (first run — review before going to production)", cfgPath)
		return &cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", cfgPath, err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", cfgPath, err)
	}

	// Back-fill any secrets added in newer versions.
	changed := false
	if cfg.CSRFKey == "" {
		k, _ := randomHex(32)
		cfg.CSRFKey = k
		changed = true
		log.Println("config: generated missing csrf_key")
	}
	if cfg.SessionSecret == "" {
		k, _ := randomHex(32)
		cfg.SessionSecret = k
		changed = true
		log.Println("config: generated missing session_secret")
	}
	if cfg.LogRetentionDays == 0 {
		cfg.LogRetentionDays = 90
		changed = true
	}
	if cfg.Email.SMTPPort == 0 {
		cfg.Email.SMTPPort = 587
		changed = true
	}
	if cfg.Email.Encryption == "" {
		cfg.Email.Encryption = "starttls"
		changed = true
	}

	if changed {
		if err := write(cfgPath, &cfg); err != nil {
			log.Printf("config: warn — could not rewrite updated config: %v", err)
		}
	}

	log.Printf("config: loaded %s", cfgPath)
	return &cfg, nil
}

func write(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("config: write %s: %w", path, err)
	}
	return nil
}

func generateSecrets(cfg *Config) error {
	k, err := randomHex(32)
	if err != nil {
		return err
	}
	cfg.CSRFKey = k
	k, err = randomHex(32)
	if err != nil {
		return err
	}
	cfg.SessionSecret = k
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
