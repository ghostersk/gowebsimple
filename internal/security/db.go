package security

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"goapp/internal/db"
)

// ─────────────────────────────────────────────────────────────────────────────
// Schema migration — call once at startup from db.migrate()
// ─────────────────────────────────────────────────────────────────────────────

// Migrate creates all security-related tables. Called by db.migrate().
func Migrate(database *db.DB) error {
	stmts := []string{
		// IP bans (auto from brute force + manual)
		`CREATE TABLE IF NOT EXISTS ip_bans (
			id           INTEGER     NOT NULL,
			ip_address   VARCHAR(45) NOT NULL,
			reason       TEXT        NOT NULL DEFAULT '',
			permanent    SMALLINT    NOT NULL DEFAULT 0,
			expires_at   TEXT,
			created_at   TEXT        NOT NULL,
			created_by   VARCHAR(64) NOT NULL DEFAULT 'system',
			unbanned_at  TEXT,
			unbanned_by  VARCHAR(64) NOT NULL DEFAULT '',
			PRIMARY KEY (id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_bans_ip      ON ip_bans(ip_address)`,
		`CREATE INDEX IF NOT EXISTS idx_bans_expires ON ip_bans(expires_at)`,

		// IP rules (whitelist / blacklist / globalallow)
		`CREATE TABLE IF NOT EXISTS ip_rules (
			id           INTEGER     NOT NULL,
			cidr         VARCHAR(50) NOT NULL,
			type         VARCHAR(16) NOT NULL,
			path_pattern VARCHAR(255) NOT NULL DEFAULT '*',
			path_type    VARCHAR(16) NOT NULL DEFAULT 'wildcard',
			note         TEXT        NOT NULL DEFAULT '',
			created_at   TEXT        NOT NULL,
			created_by   VARCHAR(64) NOT NULL DEFAULT 'system',
			PRIMARY KEY (id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_rules_type ON ip_rules(type)`,

		// Country rules
		`CREATE TABLE IF NOT EXISTS country_rules (
			id           INTEGER     NOT NULL,
			country_code VARCHAR(2)  NOT NULL,
			country_name VARCHAR(64) NOT NULL DEFAULT '',
			action       VARCHAR(8)  NOT NULL,
			path_pattern VARCHAR(255) NOT NULL DEFAULT '*',
			path_type    VARCHAR(16) NOT NULL DEFAULT 'wildcard',
			note         TEXT        NOT NULL DEFAULT '',
			created_at   TEXT        NOT NULL,
			created_by   VARCHAR(64) NOT NULL DEFAULT 'system',
			PRIMARY KEY (id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_country_code ON country_rules(country_code)`,

		// Login attempt history
		`CREATE TABLE IF NOT EXISTS login_attempts (
			id         INTEGER     NOT NULL,
			ip_address VARCHAR(45) NOT NULL,
			username   VARCHAR(64) NOT NULL DEFAULT '',
			created_at TEXT        NOT NULL,
			banned     SMALLINT    NOT NULL DEFAULT 0,
			PRIMARY KEY (id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_attempts_ip      ON login_attempts(ip_address)`,
		`CREATE INDEX IF NOT EXISTS idx_attempts_created ON login_attempts(created_at)`,
	}
	for _, stmt := range stmts {
		if _, err := database.Exec(stmt); err != nil {
			return fmt.Errorf("security migrate: %w\nSQL: %s", err, stmt)
		}
	}

	// Prune expired bans and old attempts on startup
	_, _ = database.Exec(
		`UPDATE ip_bans SET unbanned_at=?, unbanned_by='expired'
		 WHERE permanent=0 AND expires_at < ? AND unbanned_at IS NULL`,
		db.TimeStr(time.Now()), db.TimeStr(time.Now()),
	)
	_, _ = database.Exec(
		`DELETE FROM login_attempts WHERE created_at < ?`,
		db.TimeStr(time.Now().AddDate(0, 0, -30)),
	)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Ban queries
// ─────────────────────────────────────────────────────────────────────────────

// ActiveBans returns all currently active bans (not expired, not unbanned).
func ActiveBans(database *db.DB, limit, offset int) ([]*IPBan, error) {
	rows, err := database.Query(`
		SELECT id, ip_address, reason, permanent, expires_at,
		       created_at, created_by, unbanned_at, unbanned_by
		FROM ip_bans
		WHERE unbanned_at IS NULL
		  AND (permanent=1 OR expires_at > ?)
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?`,
		db.TimeStr(time.Now()), limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBans(rows)
}

// AllBans returns full ban history including expired and removed bans.
func AllBans(database *db.DB, limit, offset int) ([]*IPBan, error) {
	rows, err := database.Query(`
		SELECT id, ip_address, reason, permanent, expires_at,
		       created_at, created_by, unbanned_at, unbanned_by
		FROM ip_bans
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanBans(rows)
}

// CountBans counts total ban records (pass active=true for only active bans).
func CountBans(database *db.DB, activeOnly bool) (int, error) {
	q := `SELECT COUNT(*) FROM ip_bans`
	if activeOnly {
		q += ` WHERE unbanned_at IS NULL AND (permanent=1 OR expires_at > '` + db.TimeStr(time.Now()) + `')`
	}
	var n int
	return n, database.QueryRow(q).Scan(&n)
}

// CreateBan inserts a new ban record.
func CreateBan(database *db.DB, ip, reason, createdBy string, permanent bool, duration time.Duration) (*IPBan, error) {
	now := time.Now().UTC()
	var expiresAt *time.Time
	var expiresStr interface{} = nil
	if !permanent {
		exp := now.Add(duration)
		expiresAt = &exp
		s := db.TimeStr(exp)
		expiresStr = s
	}
	perm := 0
	if permanent {
		perm = 1
	}
	res, err := database.Exec(
		`INSERT INTO ip_bans (ip_address, reason, permanent, expires_at, created_at, created_by)
		 VALUES (?,?,?,?,?,?)`,
		ip, reason, perm, expiresStr, db.TimeStr(now), createdBy,
	)
	if err != nil {
		return nil, fmt.Errorf("security: create ban: %w", err)
	}
	id, _ := res.LastInsertId()
	return &IPBan{
		ID: id, IPAddress: ip, Reason: reason, Permanent: permanent,
		ExpiresAt: expiresAt, CreatedAt: now, CreatedBy: createdBy,
	}, nil
}

// UnbanIP marks the ban as removed.
func UnbanIP(database *db.DB, banID int64, unbannedBy string) error {
	_, err := database.Exec(
		`UPDATE ip_bans SET unbanned_at=?, unbanned_by=? WHERE id=?`,
		db.TimeStr(time.Now()), unbannedBy, banID,
	)
	return err
}

// ExtendBan updates the expiry of a ban.
func ExtendBan(database *db.DB, banID int64, newExpiry time.Time) error {
	_, err := database.Exec(
		`UPDATE ip_bans SET expires_at=?, permanent=0, unbanned_at=NULL, unbanned_by='' WHERE id=?`,
		db.TimeStr(newExpiry), banID,
	)
	return err
}

// MakePermanent makes a ban permanent.
func MakePermanent(database *db.DB, banID int64) error {
	_, err := database.Exec(
		`UPDATE ip_bans SET permanent=1, expires_at=NULL, unbanned_at=NULL, unbanned_by='' WHERE id=?`,
		banID,
	)
	return err
}

// HasActiveBan reports whether the IP currently has an active ban (not expired, not unbanned).
func HasActiveBan(database *db.DB, ip string) (bool, error) {
	var count int
	err := database.QueryRow(`
		SELECT COUNT(*) FROM ip_bans
		WHERE ip_address=?
		  AND unbanned_at IS NULL
		  AND (permanent=1 OR expires_at > ?)`,
		ip, db.TimeStr(time.Now()),
	).Scan(&count)
	return count > 0, err
}

func scanBans(rows *sql.Rows) ([]*IPBan, error) {
	var bans []*IPBan
	for rows.Next() {
		b := &IPBan{}
		var perm int
		var expiresStr, unbannedAtStr sql.NullString
		var createdStr string
		if err := rows.Scan(&b.ID, &b.IPAddress, &b.Reason, &perm,
			&expiresStr, &createdStr, &b.CreatedBy,
			&unbannedAtStr, &b.UnbannedBy); err != nil {
			return nil, err
		}
		b.Permanent = perm == 1
		b.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
		if expiresStr.Valid {
			t, _ := time.Parse("2006-01-02 15:04:05", expiresStr.String)
			b.ExpiresAt = &t
		}
		if unbannedAtStr.Valid {
			t, _ := time.Parse("2006-01-02 15:04:05", unbannedAtStr.String)
			b.UnbannedAt = &t
		}
		bans = append(bans, b)
	}
	return bans, rows.Err()
}

// ─────────────────────────────────────────────────────────────────────────────
// IP rule queries
// ─────────────────────────────────────────────────────────────────────────────

// AllIPRules returns all IP rules.
func AllIPRules(database *db.DB) ([]*IPRule, error) {
	rows, err := database.Query(`
		SELECT id, cidr, type, path_pattern, path_type, note, created_at, created_by
		FROM ip_rules ORDER BY type, cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []*IPRule
	for rows.Next() {
		r := &IPRule{}
		var createdStr string
		if err := rows.Scan(&r.ID, &r.CIDR, &r.Type, &r.PathPattern,
			&r.PathType, &r.Note, &createdStr, &r.CreatedBy); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// CreateIPRule inserts a new IP rule.
func CreateIPRule(database *db.DB, cidr string, ruleType RuleType, pathPattern string, pathType PathMatchType, note, createdBy string) error {
	_, err := database.Exec(
		`INSERT INTO ip_rules (cidr, type, path_pattern, path_type, note, created_at, created_by)
		 VALUES (?,?,?,?,?,?,?)`,
		cidr, string(ruleType), pathPattern, string(pathType), note,
		db.TimeStr(time.Now()), createdBy,
	)
	return err
}

// DeleteIPRule removes an IP rule by ID.
func DeleteIPRule(database *db.DB, id int64) error {
	_, err := database.Exec(`DELETE FROM ip_rules WHERE id=?`, id)
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// Country rule queries
// ─────────────────────────────────────────────────────────────────────────────

// AllCountryRules returns all country rules.
func AllCountryRules(database *db.DB) ([]*CountryRule, error) {
	rows, err := database.Query(`
		SELECT id, country_code, country_name, action, path_pattern, path_type, note, created_at, created_by
		FROM country_rules ORDER BY action, country_code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []*CountryRule
	for rows.Next() {
		r := &CountryRule{}
		var createdStr string
		if err := rows.Scan(&r.ID, &r.CountryCode, &r.CountryName, &r.Action,
			&r.PathPattern, &r.PathType, &r.Note, &createdStr, &r.CreatedBy); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// CreateCountryRule inserts a new country rule.
func CreateCountryRule(database *db.DB, code, name string, action CountryAction, pathPattern string, pathType PathMatchType, note, createdBy string) error {
	_, err := database.Exec(
		`INSERT INTO country_rules (country_code, country_name, action, path_pattern, path_type, note, created_at, created_by)
		 VALUES (?,?,?,?,?,?,?,?)`,
		code, name, string(action), pathPattern, string(pathType), note,
		db.TimeStr(time.Now()), createdBy,
	)
	return err
}

// DeleteCountryRule removes a country rule by ID.
func DeleteCountryRule(database *db.DB, id int64) error {
	_, err := database.Exec(`DELETE FROM country_rules WHERE id=?`, id)
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// Login attempt queries
// ─────────────────────────────────────────────────────────────────────────────

// RecordAttempt inserts a failed login attempt.
func RecordAttempt(database *db.DB, ip, username string, banned bool) error {
	b := 0
	if banned {
		b = 1
	}
	_, err := database.Exec(
		`INSERT INTO login_attempts (ip_address, username, created_at, banned) VALUES (?,?,?,?)`,
		ip, username, db.TimeStr(time.Now()), b,
	)
	return err
}

// CountRecentAttempts counts failed logins from ip within the given window.
func CountRecentAttempts(database *db.DB, ip string, since time.Time) (int, error) {
	var n int
	err := database.QueryRow(
		`SELECT COUNT(*) FROM login_attempts WHERE ip_address=? AND created_at >= ?`,
		ip, db.TimeStr(since),
	).Scan(&n)
	return n, err
}

// RecentAttempts returns the most recent failed login attempts.
func RecentAttempts(database *db.DB, limit, offset int) ([]*LoginAttempt, error) {
	rows, err := database.Query(`
		SELECT id, ip_address, username, created_at, banned
		FROM login_attempts
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?`, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var attempts []*LoginAttempt
	for rows.Next() {
		a := &LoginAttempt{}
		var b int
		var createdStr string
		if err := rows.Scan(&a.ID, &a.IPAddress, &a.Username, &createdStr, &b); err != nil {
			return nil, err
		}
		a.Banned = b == 1
		a.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
		attempts = append(attempts, a)
	}
	return attempts, rows.Err()
}

// CountAttempts returns total attempt count.
func CountAttempts(database *db.DB) (int, error) {
	var n int
	return n, database.QueryRow(`SELECT COUNT(*) FROM login_attempts`).Scan(&n)
}

// ErrNotFound is returned when a record is not found.
var ErrNotFound = errors.New("not found")
