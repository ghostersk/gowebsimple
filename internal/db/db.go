// Package db provides a database/sql wrapper with schema migration.
//
// Driver selection:
//
//   The DatabaseURL scheme determines which driver is used:
//     file:... or sqlite:... → modernc.org/sqlite  (pure Go, default)
//     mysql://...            → github.com/go-sql-driver/mysql  (add import)
//     postgres://... or
//     postgresql://...       → github.com/lib/pq               (add import)
//
//   To switch databases:
//     1. Change DatabaseURL in config.json
//     2. Add the driver import in cmd/server/drivers.go
//     3. Run go mod tidy
//
//   All SQL uses ANSI-compatible syntax. SQLite-only functions (datetime('now'))
//   are confined to this file and clearly marked.
package db

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	_ "modernc.org/sqlite" // default SQLite driver — pure Go, no CGO
	// To add MySQL:    _ "github.com/go-sql-driver/mysql"
	// To add Postgres: _ "github.com/lib/pq"
)

// DB wraps sql.DB with app-level helpers.
type DB struct {
	*sql.DB
	driver string // "sqlite" | "mysql" | "postgres"
}

// Open connects to the database identified by databaseURL and runs migrations.
//
// URL examples:
//
//	file:./data/app.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)
//	mysql://user:pass@tcp(localhost:3306)/mydb?parseTime=true
//	postgres://user:pass@localhost:5432/mydb?sslmode=disable
func Open(databaseURL string) (*DB, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("db: DatabaseURL is empty — check config.json")
	}

	driverName, dsn, err := parseDSN(databaseURL)
	if err != nil {
		return nil, err
	}

	sqlDB, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open (%s): %w", driverName, err)
	}

	// Connection pool tuning — SQLite needs 1 writer; others can use more.
	if driverName == "sqlite" {
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	} else {
		sqlDB.SetMaxOpenConns(25)
		sqlDB.SetMaxIdleConns(5)
		sqlDB.SetConnMaxLifetime(5 * time.Minute)
	}

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("db: ping (%s): %w", driverName, err)
	}

	d := &DB{DB: sqlDB, driver: driverName}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("db: migrate: %w", err)
	}

	log.Printf("db: connected (%s)", driverName)
	return d, nil
}

// Driver returns the database driver name ("sqlite", "mysql", "postgres").
func (d *DB) Driver() string { return d.driver }

// IsSQLite reports whether the underlying database is SQLite.
func (d *DB) IsSQLite() bool { return d.driver == "sqlite" }

// parseDSN infers the driver name and returns a driver-appropriate DSN.
func parseDSN(url string) (driver, dsn string, err error) {
	switch {
	case strings.HasPrefix(url, "file:") || strings.HasPrefix(url, "sqlite:"):
		// Normalise: strip "sqlite://" prefix if present
		dsn = strings.TrimPrefix(url, "sqlite://")
		return "sqlite", dsn, nil

	case strings.HasPrefix(url, "mysql://"):
		// Convert mysql://user:pass@tcp(host:port)/db → user:pass@tcp(host:port)/db
		dsn = strings.TrimPrefix(url, "mysql://")
		return "mysql", dsn, nil

	case strings.HasPrefix(url, "postgres://"),
		strings.HasPrefix(url, "postgresql://"):
		// lib/pq accepts the full postgres:// URL natively
		return "postgres", url, nil

	default:
		return "", "", fmt.Errorf("db: unsupported database URL scheme: %q (expected file:, mysql://, or postgres://)", url)
	}
}

// migrate applies the schema DDL idempotently.
//
// Portability note: The schema uses INTEGER PRIMARY KEY which works for:
//   - SQLite:     rowid alias, implicit auto-increment
//   - MySQL:      add AUTO_INCREMENT after INTEGER for id columns
//   - PostgreSQL: use SERIAL or BIGSERIAL instead of INTEGER for id columns
//
// When switching databases, update the id column definitions accordingly.
// All other columns use portable SQL types (VARCHAR, TEXT, SMALLINT, etc.)
func (d *DB) migrate() error {
	stmts := []string{
		// Users
		`CREATE TABLE IF NOT EXISTS users (
			id          INTEGER      NOT NULL,
			username    VARCHAR(64)  NOT NULL,
			email       VARCHAR(255) NOT NULL,
			password    TEXT         NOT NULL,
			role        VARCHAR(16)  NOT NULL DEFAULT 'user',
			active      SMALLINT     NOT NULL DEFAULT 1,
			mfa_secret  TEXT         NOT NULL DEFAULT '',
			mfa_enabled SMALLINT     NOT NULL DEFAULT 0,
			created_at  TEXT         NOT NULL,
			last_login  TEXT,
			PRIMARY KEY (id)
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email    ON users(email)`,

		// Sessions
		`CREATE TABLE IF NOT EXISTS sessions (
			token       VARCHAR(128) NOT NULL,
			user_id     INTEGER      NOT NULL,
			expires_at  TEXT         NOT NULL,
			created_at  TEXT         NOT NULL,
			PRIMARY KEY (token)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_exp  ON sessions(expires_at)`,

		// App logs
		`CREATE TABLE IF NOT EXISTS app_logs (
			id          INTEGER NOT NULL,
			level       VARCHAR(8) NOT NULL,
			message     TEXT NOT NULL,
			context     TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL,
			PRIMARY KEY (id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_level   ON app_logs(level)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_created ON app_logs(created_at)`,
	}

	for _, stmt := range stmts {
		if _, err := d.Exec(stmt); err != nil {
			return fmt.Errorf("migrate stmt failed: %w\nSQL: %s", err, stmt)
		}
	}

	// Cleanup stale data on startup.
	_, _ = d.Exec(`DELETE FROM sessions WHERE expires_at < ?`, TimeStr(time.Now()))
	_, _ = d.Exec(`DELETE FROM app_logs WHERE created_at < ?`,
		TimeStr(time.Now().AddDate(0, 0, -90)))

	return nil
}

// TimeStr formats a time.Time as an ISO-8601 string for DB storage.
// All databases accept this format via their TEXT/VARCHAR columns.
func TimeStr(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05")
}

// NullString converts an empty string to sql.NullString.
func NullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
