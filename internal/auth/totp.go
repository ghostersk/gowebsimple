// TOTP implements RFC 6238 Time-Based One-Time Passwords using only
// Go's standard library (crypto/hmac, crypto/sha1, encoding/base32).
//
// Compatible with Google Authenticator, Authy, 1Password, Bitwarden, etc.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	totpDigits   = 6
	totpPeriod   = 30  // seconds
	totpWindow   = 1   // ±1 window tolerance for clock skew
	totpSecretLen = 20  // 160 bits = 20 bytes → 32-char base32
)

// GenerateTOTPSecret creates a new random TOTP secret encoded in base32.
// This is stored in the user record and used to generate/verify codes.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, totpSecretLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("totp: generate secret: %w", err)
	}
	// Unpadded base32 — standard TOTP apps accept both padded and unpadded
	return base32.StdEncoding.EncodeToString(b), nil
}

// TOTPProvisioningURI builds the otpauth:// URI for QR code generation.
// issuer is your app name (e.g. "GoApp"), username is the account label.
func TOTPProvisioningURI(secret, issuer, username string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		urlEncode(issuer), urlEncode(username),
		strings.TrimRight(secret, "="),
		urlEncode(issuer),
		totpDigits, totpPeriod,
	)
}

// ValidateTOTP checks whether code is a valid TOTP for secret at the
// current time, accepting ±totpWindow periods to handle clock skew.
// code should be the raw 6-digit string (leading zeros preserved).
func ValidateTOTP(secret, code string) bool {
	// Normalise: strip spaces, uppercase
	code = strings.ReplaceAll(code, " ", "")
	if len(code) != totpDigits {
		return false
	}

	key, err := decodeSecret(secret)
	if err != nil {
		return false
	}

	now := time.Now().Unix()
	counter := now / totpPeriod

	for i := -totpWindow; i <= totpWindow; i++ {
		expected := generateOTP(key, counter+int64(i))
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

// GenerateTOTPCode returns the current valid TOTP code for a secret.
// Useful in tests and the CLI emergency reset.
func GenerateTOTPCode(secret string) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	counter := time.Now().Unix() / totpPeriod
	return generateOTP(key, counter), nil
}

// ── internal helpers ─────────────────────────────────────────────────────────

func decodeSecret(secret string) ([]byte, error) {
	// Normalise: uppercase, re-pad to multiple of 8
	secret = strings.ToUpper(strings.TrimSpace(secret))
	if pad := len(secret) % 8; pad != 0 {
		secret += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("totp: decode secret: %w", err)
	}
	return key, nil
}

func generateOTP(key []byte, counter int64) string {
	// Step 1 — HMAC-SHA1 of the 8-byte big-endian counter
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(counter))

	h := hmac.New(sha1.New, key)
	h.Write(msg)
	digest := h.Sum(nil)

	// Step 2 — Dynamic truncation (RFC 4226 §5.4)
	offset := digest[len(digest)-1] & 0x0f
	binCode := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff

	// Step 3 — Reduce to N digits
	otp := int(binCode) % int(math.Pow10(totpDigits))
	return fmt.Sprintf("%0*d", totpDigits, otp)
}

// urlEncode performs minimal percent-encoding for otpauth:// URIs.
func urlEncode(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteRune(c)
		} else {
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}
