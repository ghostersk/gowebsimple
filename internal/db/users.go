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
	ID        int64
	Username  string
	Email     string
	Password  string // PBKDF2 hash
	Role      string // "user" | "admin"
	Active    bool
	CreatedAt time.Time
	LastLogin *time.Time
}

// IsAdmin reports whether the user has the admin role.
func (u *User) IsAdmin() bool { return u.Role == "admin" }

// Sentinel errors.
var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("duplicate")
)

const userColumns = `id, username, email, password, role, active, created_at, last_login`

// UserByID fetches a user by primary key.
func (d *DB) UserByID(id int64) (*User, error) {
	return scanUser(d.QueryRow(
		`SELECT `+userColumns+` FROM users WHERE id=?`, id,
	))
}

// UserByUsername fetches a user by username (case-insensitive).
func (d *DB) UserByUsername(username string) (*User, error) {
	return scanUser(d.QueryRow(
		`SELECT `+userColumns+` FROM users WHERE username=? COLLATE NOCASE`, username,
	))
}

// AllUsers returns all users ordered by created_at DESC.
func (d *DB) AllUsers(limit, offset int) ([]*User, error) {
	rows, err := d.Query(
		`SELECT `+userColumns+` FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`,
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

// CountUsers returns the total number of users.
func (d *DB) CountUsers() (int, error) {
	var n int
	err := d.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser inserts a new user record.
func (d *DB) CreateUser(username, email, passwordHash, role string) (*User, error) {
	res, err := d.Exec(
		`INSERT INTO users (username, email, password, role) VALUES (?,?,?,?)`,
		username, email, passwordHash, role,
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

// UpdateUserActive enables or disables a user account.
func (d *DB) UpdateUserActive(id int64, active bool) error {
	v := 0
	if active {
		v = 1
	}
	_, err := d.Exec(`UPDATE users SET active=? WHERE id=?`, v, id)
	return err
}

// UpdateUserRole changes a user's role.
func (d *DB) UpdateUserRole(id int64, role string) error {
	_, err := d.Exec(`UPDATE users SET role=? WHERE id=?`, role, id)
	return err
}

// UpdateUserPassword sets a new hash.
func (d *DB) UpdateUserPassword(id int64, hash string) error {
	_, err := d.Exec(`UPDATE users SET password=? WHERE id=?`, hash, id)
	return err
}

// UpdateLastLogin records the current UTC time as last_login.
func (d *DB) UpdateLastLogin(id int64) error {
	_, err := d.Exec(`UPDATE users SET last_login=datetime('now') WHERE id=?`, id)
	return err
}

// DeleteUser permanently removes a user and cascades to sessions.
func (d *DB) DeleteUser(id int64) error {
	_, err := d.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

// ── scan helpers ──────────────────────────────────────────────────────────────

func scanUser(row *sql.Row) (*User, error) {
	u := &User{}
	var active int
	var createdStr string
	var lastLoginStr sql.NullString

	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Password,
		&u.Role, &active, &createdStr, &lastLoginStr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.Active = active == 1
	u.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
	if lastLoginStr.Valid {
		t, _ := time.Parse("2006-01-02 15:04:05", lastLoginStr.String)
		u.LastLogin = &t
	}
	return u, nil
}

func scanUserRow(rows *sql.Rows) (*User, error) {
	u := &User{}
	var active int
	var createdStr string
	var lastLoginStr sql.NullString

	err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Password,
		&u.Role, &active, &createdStr, &lastLoginStr)
	if err != nil {
		return nil, err
	}
	u.Active = active == 1
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
	return strings.Contains(s, "UNIQUE constraint") || strings.Contains(s, "NOT NULL constraint")
}
