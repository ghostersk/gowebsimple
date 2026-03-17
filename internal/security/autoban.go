package security

import (
	"fmt"
	"time"

	"goapp/internal/config"
	"goapp/internal/db"
)

// AutoBanner handles brute-force detection and automatic IP banning.
type AutoBanner struct {
	database *db.DB
	cfg      *config.SecurityConfig
	engine   *Engine
}

// NewAutoBanner creates an AutoBanner.
func NewAutoBanner(database *db.DB, cfg *config.SecurityConfig, engine *Engine) *AutoBanner {
	return &AutoBanner{database: database, cfg: cfg, engine: engine}
}

// RecordFailedLogin records a failed login attempt and bans the IP if the
// threshold has been crossed.
//
// Returns (true, banMsg) if the IP was newly banned, (false, "") otherwise.
// The caller (LoginHandler) should log and surface the ban appropriately.
func (ab *AutoBanner) RecordFailedLogin(ip, username string) (banned bool, reason string) {
	if !ab.cfg.Enabled || !ab.cfg.AutoBanEnabled {
		// Still record the attempt for the history log even if auto-ban is off
		_ = RecordAttempt(ab.database, ip, username, false)
		return false, ""
	}

	// Count recent failed attempts from this IP
	window := time.Now().Add(-time.Duration(ab.cfg.AutoBanWindowMinutes) * time.Minute)
	count, err := CountRecentAttempts(ab.database, ip, window)
	if err != nil {
		_ = RecordAttempt(ab.database, ip, username, false)
		return false, ""
	}

	// count+1 because we haven't inserted this attempt yet
	if count+1 >= ab.cfg.AutoBanThreshold {
		// Ban the IP
		duration := time.Duration(ab.cfg.AutoBanDurationHours) * time.Hour
		reason := fmt.Sprintf("Automatic ban: %d failed login attempts in %d minutes",
			ab.cfg.AutoBanThreshold, ab.cfg.AutoBanWindowMinutes)

		_, banErr := CreateBan(ab.database, ip, reason, "system", false, duration)
		_ = RecordAttempt(ab.database, ip, username, banErr == nil)

		if banErr == nil {
			// Refresh the engine's in-memory snapshot
			_ = ab.engine.Reload()
			return true, reason
		}
		return false, ""
	}

	_ = RecordAttempt(ab.database, ip, username, false)
	return false, ""
}
