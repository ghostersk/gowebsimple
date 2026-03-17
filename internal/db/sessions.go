package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const sessionDuration = 7 * 24 * time.Hour

type Session struct {
	Token     string
	UserID    int64
	ExpiresAt time.Time
	CreatedAt time.Time
}

func (d *DB) CreateSession(userID int64) (*Session, error) {
	tok, err := generateToken(32)
	if err != nil {
		return nil, fmt.Errorf("db: session token: %w", err)
	}
	now := time.Now().UTC()
	exp := now.Add(sessionDuration)
	_, err = d.Exec(
		`INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?,?,?,?)`,
		tok, userID, TimeStr(exp), TimeStr(now),
	)
	if err != nil {
		return nil, fmt.Errorf("db: create session: %w", err)
	}
	return &Session{Token: tok, UserID: userID, ExpiresAt: exp, CreatedAt: now}, nil
}

func (d *DB) SessionByToken(token string) (*Session, error) {
	s := &Session{}
	var expStr, createdStr string
	err := d.QueryRow(
		`SELECT token, user_id, expires_at, created_at FROM sessions WHERE token=? AND expires_at > ?`,
		token, TimeStr(time.Now()),
	).Scan(&s.Token, &s.UserID, &expStr, &createdStr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.ExpiresAt, _ = time.Parse("2006-01-02 15:04:05", expStr)
	s.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
	return s, nil
}

func (d *DB) DeleteSession(token string) error {
	_, err := d.Exec(`DELETE FROM sessions WHERE token=?`, token)
	return err
}

func (d *DB) DeleteUserSessions(userID int64) error {
	_, err := d.Exec(`DELETE FROM sessions WHERE user_id=?`, userID)
	return err
}

func (d *DB) PruneExpiredSessions() (int64, error) {
	res, err := d.Exec(`DELETE FROM sessions WHERE expires_at < ?`, TimeStr(time.Now()))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func generateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
