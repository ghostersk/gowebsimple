package security

import (
	"net"
	"strings"
	"sync"
	"time"

	"goapp/internal/config"
	"goapp/internal/db"
)

// Engine is the in-memory security rule evaluator.
// Rules and bans are loaded from the DB on startup and after any change.
// All lookups run against the in-memory snapshot — no DB hit per request.
type Engine struct {
	mu sync.RWMutex

	// Loaded rule snapshots
	bans          []*IPBan      // active bans only
	ipRules       []*IPRule
	countryRules  []*CountryRule
	trustedCIDRs  []*net.IPNet  // reverse-proxy IPs — always allowed

	// GeoIP
	geoip  *GeoIPDB

	// Config knobs
	cfg    *config.SecurityConfig
	database *db.DB
}

// NewEngine creates an Engine and loads all rules from the database.
func NewEngine(database *db.DB, cfg *config.SecurityConfig, geoip *GeoIPDB, trustedProxies []string) (*Engine, error) {
	e := &Engine{
		cfg:      cfg,
		database: database,
		geoip:    geoip,
	}
	// Parse trusted proxy CIDRs — these are always whitelisted
	for _, a := range trustedProxies {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		// If it's a plain IP (no CIDR), append /32 to make it a valid CIDR
		if ip := net.ParseIP(a); ip != nil {
			a = ip.String() + "/32"
		}
		if _, ipnet, err := net.ParseCIDR(a); err == nil {
			e.trustedCIDRs = append(e.trustedCIDRs, ipnet)
		}
	}
	return e, e.Reload()
}

// Reload refreshes the in-memory snapshot from the database.
// Call this after any rule or ban change.
func (e *Engine) Reload() error {
	bans, err := ActiveBans(e.database, 10000, 0)
	if err != nil {
		return err
	}
	rules, err := AllIPRules(e.database)
	if err != nil {
		return err
	}
	countries, err := AllCountryRules(e.database)
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.bans = bans
	e.ipRules = rules
	e.countryRules = countries
	e.mu.Unlock()
	return nil
}

// Decision is the outcome of Evaluate().
type Decision int

const (
	DecisionAllow Decision = iota
	DecisionBlock
)

// Evaluate checks ip + path against all active rules and bans.
// Returns DecisionBlock and a reason string if the request should be blocked.
// Returns DecisionAllow if the request should proceed.
func (e *Engine) Evaluate(ipStr, path string) (Decision, string) {
	if !e.cfg.Enabled {
		return DecisionAllow, ""
	}

	parsedIP := net.ParseIP(ipStr)

	// 1. Trusted reverse proxies are never blocked
	if parsedIP != nil && e.isTrusted(parsedIP) {
		return DecisionAllow, ""
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// 2. IP whitelist — always allow (overrides bans, blacklist, global-allow)
	if e.matchesIPRule(parsedIP, path, RuleWhitelist) {
		return DecisionAllow, ""
	}

	// 3. Active ban
	if e.isBanned(ipStr) {
		return DecisionBlock, "IP address is banned"
	}

	// 4. IP blacklist
	if e.matchesIPRule(parsedIP, path, RuleBlacklist) {
		return DecisionBlock, "IP address is blacklisted"
	}

	// 5. Global allow-only mode: block everything not whitelisted
	if e.hasGlobalAllow(path) && !e.matchesIPRule(parsedIP, path, RuleGlobalAllow) {
		return DecisionBlock, "IP address not in allow-list"
	}

	// 6. Country rules (only if GeoIP is loaded)
	if e.geoip != nil && e.geoip.Loaded() && len(e.countryRules) > 0 {
		if dec, reason := e.evaluateCountry(ipStr, path); dec == DecisionBlock {
			return DecisionBlock, reason
		}
	}

	return DecisionAllow, ""
}

// isTrusted reports whether ip is a configured trusted proxy.
func (e *Engine) isTrusted(ip net.IP) bool {
	for _, n := range e.trustedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isBanned checks the in-memory active ban list.
func (e *Engine) isBanned(ipStr string) bool {
	now := time.Now()
	for _, b := range e.bans {
		if b.IPAddress != ipStr {
			continue
		}
		if b.UnbannedAt != nil {
			continue
		}
		if b.Permanent {
			return true
		}
		if b.ExpiresAt != nil && now.Before(*b.ExpiresAt) {
			return true
		}
	}
	return false
}

// matchesIPRule reports whether ip + path matches any rule of the given type.
func (e *Engine) matchesIPRule(ip net.IP, path string, ruleType RuleType) bool {
	if ip == nil {
		return false
	}
	for _, r := range e.ipRules {
		if r.Type != ruleType {
			continue
		}
		if !pathMatches(path, r.PathPattern, r.PathType) {
			continue
		}
		_, ipnet, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			continue
		}
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// hasGlobalAllow reports whether any global-allow rule applies to this path.
func (e *Engine) hasGlobalAllow(path string) bool {
	for _, r := range e.ipRules {
		if r.Type == RuleGlobalAllow && pathMatches(path, r.PathPattern, r.PathType) {
			return true
		}
	}
	return false
}

// evaluateCountry applies country-level rules.
func (e *Engine) evaluateCountry(ipStr, path string) (Decision, string) {
	country := e.geoip.Lookup(ipStr)
	if country == "" {
		// Unknown country — apply only if there are explicit block rules with wildcard
		// (i.e. if no country can be determined, allow unless explicitly blocked with "XX")
		return DecisionAllow, ""
	}

	for _, r := range e.countryRules {
		if !strings.EqualFold(r.CountryCode, country) {
			continue
		}
		if !pathMatches(path, r.PathPattern, r.PathType) {
			continue
		}
		if r.Action == CountryBlock {
			return DecisionBlock, "access from your country (" + country + ") is not permitted"
		}
		// CountryAllow — explicitly permitted
		return DecisionAllow, ""
	}

	// No rule matched — default allow
	return DecisionAllow, ""
}

// ─────────────────────────────────────────────────────────────────────────────
// Path matching
// ─────────────────────────────────────────────────────────────────────────────

// pathMatches reports whether path satisfies pattern given matchType.
//
// Wildcard rules:
//   "*"        matches everything
//   "/admin*"  matches /admin, /admin/, /admin/users, etc.
//   "/api/*"   matches /api/v1, /api/v2/users, etc.
func pathMatches(path, pattern string, matchType PathMatchType) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	switch matchType {
	case PathExact:
		return path == pattern
	case PathPrefix:
		return strings.HasPrefix(path, pattern)
	case PathWildcard:
		return wildcardMatch(path, pattern)
	default:
		return wildcardMatch(path, pattern)
	}
}

// wildcardMatch implements simple glob matching where * matches any sequence.
func wildcardMatch(s, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return strings.HasPrefix(s, pattern)
	}
	// Split on * and match each segment in order
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(s[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			// First part must match at start
			return false
		}
		pos += idx + len(part)
	}
	return true
}
