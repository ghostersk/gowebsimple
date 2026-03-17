// Package db provides the database connection and schema management.
//
// SQLite driver: modernc.org/sqlite (pure Go, no CGO required).
// This is the ONLY external dependency in this project, permitted by the
// project spec for database support.
package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGO)
)

// DB wraps sql.DB with app-level helpers.
type DB struct {
	*sql.DB
}

// Open opens (or creates) the SQLite database at the given path
// and runs all schema migrations.
func Open(dataDir string) (*DB, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("db: create data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "app.db")
	dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}

	// WAL mode works best with a single writer connection.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(time.Hour)

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("db: ping: %w", err)
	}

	d := &DB{sqlDB}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("db: migrate: %w", err)
	}

	log.Printf("db: opened %s", dbPath)
	return d, nil
}

func (d *DB) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS users (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	username    TEXT    NOT NULL UNIQUE COLLATE NOCASE,
	email       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
	password    TEXT    NOT NULL,
	role        TEXT    NOT NULL DEFAULT 'user',
	active      INTEGER NOT NULL DEFAULT 1,
	created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
	last_login  TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
	token       TEXT    PRIMARY KEY,
	user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at  TEXT    NOT NULL,
	created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_exp  ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS app_logs (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	level       TEXT    NOT NULL,
	message     TEXT    NOT NULL,
	context     TEXT    NOT NULL DEFAULT '',
	created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_logs_level   ON app_logs(level);
CREATE INDEX IF NOT EXISTS idx_logs_created ON app_logs(created_at);
`
	if _, err := d.Exec(schema); err != nil {
		return err
	}

	// Cleanup old sessions on startup.
	_, _ = d.Exec(`DELETE FROM sessions WHERE expires_at < datetime('now')`)

	// Prune logs older than 90 days.
	_, _ = d.Exec(`DELETE FROM app_logs WHERE created_at < datetime('now', '-90 days')`)

	return nil
}

// NullString converts a string to sql.NullString.
func NullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// TimeStr formats time.Time as SQLite datetime string.
func TimeStr(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05")
}
