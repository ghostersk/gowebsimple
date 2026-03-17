// Package auth provides password hashing and CSRF token utilities.
// Uses only Go's standard library crypto packages.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Password hashing — PBKDF2-SHA256 (stdlib, no external packages)
// ─────────────────────────────────────────────────────────────────────────────

const (
	pbkdfIter   = 120_000 // OWASP 2024 recommendation for PBKDF2-SHA256
	pbkdfKeyLen = 32
	pbkdfSalt   = 16
)

// HashPassword returns a salted PBKDF2-SHA256 hash encoded as a portable string.
func HashPassword(password string) (string, error) {
	salt := make([]byte, pbkdfSalt)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	key := pbkdf2Key([]byte(password), salt)
	// Format: pbkdf2$<iterations>$<salt_hex>$<key_hex>
	return fmt.Sprintf("pbkdf2$%d$%s$%s", pbkdfIter, hex.EncodeToString(salt), hex.EncodeToString(key)), nil
}

// CheckPassword returns true if password matches the stored hash.
func CheckPassword(password, hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	stored, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	computed := pbkdf2Key([]byte(password), salt)
	return subtle.ConstantTimeCompare(computed, stored) == 1
}

// pbkdf2Key derives a key using PBKDF2 with SHA-256 (stdlib implementation).
func pbkdf2Key(password, salt []byte) []byte {
	// Go 1.20+ ships crypto/pbkdf2 in x/crypto but we implement it inline
	// to stay standard-library-only.
	// Reference: RFC 2898 §5.2
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (pbkdfKeyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		T := prf.Sum(nil)
		copy(U, T)
		for i := 1; i < pbkdfIter; i++ {
			prf.Reset()
			prf.Write(U)
			prf.Sum(U[:0])
			for j := range T {
				T[j] ^= U[j]
			}
		}
		dk = append(dk, T...)
	}
	return dk[:pbkdfKeyLen]
}

// ─────────────────────────────────────────────────────────────────────────────
// CSRF tokens — HMAC-SHA256 signed, time-scoped
// ─────────────────────────────────────────────────────────────────────────────

var csrfKey []byte // set once at startup

// InitCSRF sets the HMAC key for CSRF tokens. Call once at startup.
func InitCSRF(key []byte) {
	csrfKey = key
}

// GenerateCSRF produces a signed CSRF token for the given session token.
// Tokens are valid for 1 hour.
func GenerateCSRF(sessionToken string) string {
	ts := time.Now().UTC().Truncate(time.Hour).Unix()
	msg := fmt.Sprintf("%s|%d", sessionToken, ts)
	mac := hmacSHA256(csrfKey, []byte(msg))
	return base64.RawURLEncoding.EncodeToString([]byte(msg + "|" + hex.EncodeToString(mac)))
}

// ValidateCSRF returns true if the token is valid for the given session.
func ValidateCSRF(sessionToken, token string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return false
	}
	// Verify the session token embedded in the CSRF matches
	if subtle.ConstantTimeCompare([]byte(parts[0]), []byte(sessionToken)) != 1 {
		return false
	}
	// Recompute MAC
	msg := parts[0] + "|" + parts[1]
	mac := hmacSHA256(csrfKey, []byte(msg))
	provided, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	if subtle.ConstantTimeCompare(mac, provided) != 1 {
		return false
	}
	// Check the timestamp (accept current or previous hour)
	now := time.Now().UTC().Truncate(time.Hour).Unix()
	prev := now - 3600
	var ts int64
	fmt.Sscanf(parts[1], "%d", &ts)
	return ts == now || ts == prev
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// RandomKey generates n random bytes as a hex string.
func RandomKey(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
