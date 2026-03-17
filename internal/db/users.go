package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// User represents a user record.
type User struct {
	ID         int64
	Username   string
	Email      string
	Password   string // PBKDF2 hash
	Role       string // "user" | "admin"
	Active     bool
	MFASecret  string // base32-encoded TOTP secret (empty = not set)
	MFAEnabled bool
	CreatedAt  time.Time
	LastLogin  *time.Time
}

func (u *User) IsAdmin() bool   { return u.Role == "admin" }
func (u *User) HasMFA() bool    { return u.MFAEnabled && u.MFASecret != "" }

var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("duplicate")
)

const userCols = `id, username, email, password, role, active,
	mfa_secret, mfa_enabled, created_at, last_login`

func (d *DB) UserByID(id int64) (*User, error) {
	return scanUser(d.QueryRow(`SELECT `+userCols+` FROM users WHERE id=?`, id))
}

func (d *DB) UserByUsername(username string) (*User, error) {
	return scanUser(d.QueryRow(`SELECT `+userCols+` FROM users WHERE username=?`, username))
}

func (d *DB) AllUsers(limit, offset int) ([]*User, error) {
	rows, err := d.Query(
		`SELECT `+userCols+` FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*User
	for rows.Next() {
		u, err := scanUserRow(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (d *DB) CountUsers() (int, error) {
	var n int
	return n, d.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
}

func (d *DB) CreateUser(username, email, passwordHash, role string) (*User, error) {
	now := TimeStr(time.Now())
	res, err := d.Exec(
		`INSERT INTO users (username, email, password, role, created_at) VALUES (?,?,?,?,?)`,
		username, email, passwordHash, role, now,
	)
	if err != nil {
		if isConstraint(err) {
			return nil, ErrDuplicate
		}
		return nil, fmt.Errorf("db: create user: %w", err)
	}
	id, _ := res.LastInsertId()
	return d.UserByID(id)
}

func (d *DB) UpdateUserActive(id int64, active bool) error {
	v := 0
	if active {
		v = 1
	}
	_, err := d.Exec(`UPDATE users SET active=? WHERE id=?`, v, id)
	return err
}

func (d *DB) UpdateUserRole(id int64, role string) error {
	_, err := d.Exec(`UPDATE users SET role=? WHERE id=?`, role, id)
	return err
}

func (d *DB) UpdateUserPassword(id int64, hash string) error {
	_, err := d.Exec(`UPDATE users SET password=? WHERE id=?`, hash, id)
	return err
}

func (d *DB) UpdateLastLogin(id int64) error {
	_, err := d.Exec(`UPDATE users SET last_login=? WHERE id=?`, TimeStr(time.Now()), id)
	return err
}

// MFA management
func (d *DB) SetMFASecret(id int64, secret string) error {
	_, err := d.Exec(`UPDATE users SET mfa_secret=?, mfa_enabled=0 WHERE id=?`, secret, id)
	return err
}

func (d *DB) EnableMFA(id int64) error {
	_, err := d.Exec(`UPDATE users SET mfa_enabled=1 WHERE id=?`, id)
	return err
}

func (d *DB) DisableMFA(id int64) error {
	_, err := d.Exec(`UPDATE users SET mfa_enabled=0, mfa_secret='' WHERE id=?`, id)
	return err
}

func (d *DB) DeleteUser(id int64) error {
	_, err := d.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

// ── scan helpers ──────────────────────────────────────────────────────────────

func scanUser(row *sql.Row) (*User, error) {
	u := &User{}
	var active, mfaEnabled int
	var createdStr string
	var lastLoginStr sql.NullString

	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Password,
		&u.Role, &active, &u.MFASecret, &mfaEnabled,
		&createdStr, &lastLoginStr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.Active = active == 1
	u.MFAEnabled = mfaEnabled == 1
	u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
	if lastLoginStr.Valid {
		t, _ := time.Parse("2006-01-02 15:04:05", lastLoginStr.String)
		u.LastLogin = &t
	}
	return u, nil
}

func scanUserRow(rows *sql.Rows) (*User, error) {
	u := &User{}
	var active, mfaEnabled int
	var createdStr string
	var lastLoginStr sql.NullString

	err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Password,
		&u.Role, &active, &u.MFASecret, &mfaEnabled,
		&createdStr, &lastLoginStr)
	if err != nil {
		return nil, err
	}
	u.Active = active == 1
	u.MFAEnabled = mfaEnabled == 1
	u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
	if lastLoginStr.Valid {
		t, _ := time.Parse("2006-01-02 15:04:05", lastLoginStr.String)
		u.LastLogin = &t
	}
	return u, nil
}

func isConstraint(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "UNIQUE") || strings.Contains(s, "unique") ||
		strings.Contains(s, "Duplicate")
}
