// Package security provides IP-based access control including:
//   - Brute-force auto-banning on failed logins
//   - Manual IP bans (temporary or permanent)
//   - IP whitelist / blacklist rules (exact IP or CIDR, prefix or wildcard path)
//   - Global allow-only mode (block everything except whitelisted IPs)
//   - Country-level allow/block rules via MaxMind GeoLite2
//   - In-memory cache backed by SQLite for fast per-request evaluation
package security

import "time"

// ─────────────────────────────────────────────────────────────────────────────
// Rule types
// ─────────────────────────────────────────────────────────────────────────────

// RuleType classifies an IP rule's action.
type RuleType string

const (
	RuleWhitelist   RuleType = "whitelist"   // always allow, never ban
	RuleBlacklist   RuleType = "blacklist"   // always block
	RuleGlobalAllow RuleType = "globalallow" // block all IPs not in this list
)

// CountryAction classifies a country rule.
type CountryAction string

const (
	CountryAllow CountryAction = "allow"
	CountryBlock CountryAction = "block"
)

// PathMatchType controls how the path field is compared.
type PathMatchType string

const (
	PathPrefix  PathMatchType = "prefix"   // /admin matches /admin/users
	PathWildcard PathMatchType = "wildcard" // * matches everything; /api/* matches /api/v1/...
	PathExact   PathMatchType = "exact"    // only exact match
)

// ─────────────────────────────────────────────────────────────────────────────
// Data structs returned by queries
// ─────────────────────────────────────────────────────────────────────────────

// IPBan represents a blocked IP address (auto or manual).
type IPBan struct {
	ID          int64
	IPAddress   string
	Reason      string
	Permanent   bool
	ExpiresAt   *time.Time // nil when permanent
	CreatedAt   time.Time
	CreatedBy   string // "system" or admin username
	UnbannedAt  *time.Time
	UnbannedBy  string
}

// Active reports whether this ban is currently in force.
func (b *IPBan) Active() bool {
	if b.UnbannedAt != nil {
		return false
	}
	if b.Permanent {
		return true
	}
	return b.ExpiresAt != nil && time.Now().Before(*b.ExpiresAt)
}

// IPRule is a single IP whitelist/blacklist/global-allow entry.
type IPRule struct {
	ID          int64
	CIDR        string        // e.g. "192.168.1.0/24" or "10.0.0.5/32"
	Type        RuleType
	PathPattern string        // e.g. "/admin", "/login", "*"
	PathType    PathMatchType
	Note        string
	CreatedAt   time.Time
	CreatedBy   string
}

// CountryRule blocks or allows all traffic from a country.
type CountryRule struct {
	ID          int64
	CountryCode string        // ISO 3166-1 alpha-2, e.g. "CN", "RU"
	CountryName string
	Action      CountryAction
	PathPattern string
	PathType    PathMatchType
	Note        string
	CreatedAt   time.Time
	CreatedBy   string
}

// LoginAttempt is a single failed login record.
type LoginAttempt struct {
	ID        int64
	IPAddress string
	Username  string
	CreatedAt time.Time
	Banned    bool   // was this attempt the one that triggered a ban?
}
