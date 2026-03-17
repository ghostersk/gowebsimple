package handlers

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"goapp/internal/db"
	"goapp/internal/logger"
	"goapp/internal/middleware"
	"goapp/internal/security"
)

const secPageSize = 50

// securityDisabled renders an informational page when the security engine
// is not running (security.enabled=false in config.json).
func securityDisabled(h *Renderer, w http.ResponseWriter, r *http.Request) {
	pd := NewPageData(r, "Security Disabled")
	pd.FlashErr = "Security is disabled. Set security.enabled=true in data/config.json and restart the server to activate IP banning, rules, and GeoIP filtering."
	type disabledData struct{ PageData }
	h.Render(w, "admin_security_disabled", disabledData{pd})
}

// ─────────────────────────────────────────────────────────────────────────────
// /admin/security/bans
// ─────────────────────────────────────────────────────────────────────────────

type AdminBansData struct {
	PageData
	Bans       []*security.IPBan
	Total      int
	Page       int
	TotalPages int
	ShowAll    bool
}

type AdminBansHandler struct {
	tmpl   *Renderer
	db     *db.DB
	log    *logger.Logger
	engine *security.Engine
}

func NewAdminBansHandler(r *Renderer, database *db.DB, l *logger.Logger, eng *security.Engine) *AdminBansHandler {
	return &AdminBansHandler{tmpl: r, db: database, log: l, engine: eng}
}

func (h *AdminBansHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		securityDisabled(h.tmpl, w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	showAll := r.URL.Query().Get("all") == "1"
	page := qInt(r, "page", 1)
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * secPageSize

	var (
		bans  []*security.IPBan
		total int
		err   error
	)
	if showAll {
		bans, err = security.AllBans(h.db, secPageSize, offset)
		total, _ = security.CountBans(h.db, false)
	} else {
		bans, err = security.ActiveBans(h.db, secPageSize, offset)
		total, _ = security.CountBans(h.db, true)
	}
	if err != nil {
		h.log.Error("admin: list bans", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	totalPages := (total + secPageSize - 1) / secPageSize
	if totalPages == 0 {
		totalPages = 1
	}
	h.tmpl.Render(w, "admin_bans", AdminBansData{
		PageData:   NewPageData(r, "IP Bans"),
		Bans:       bans,
		Total:      total,
		Page:       page,
		TotalPages: totalPages,
		ShowAll:    showAll,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// /admin/security/bans/action  (POST)
// ─────────────────────────────────────────────────────────────────────────────

type AdminBanActionHandler struct {
	db     *db.DB
	log    *logger.Logger
	engine *security.Engine
}

func NewAdminBanActionHandler(database *db.DB, l *logger.Logger, eng *security.Engine) *AdminBanActionHandler {
	return &AdminBanActionHandler{db: database, log: l, engine: eng}
}

func (h *AdminBanActionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		http.Redirect(w, r, "/admin/security/bans", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/security/bans?err=Could+not+parse+form.", http.StatusSeeOther)
		return
	}

	action := r.FormValue("action")
	actor := middleware.UserFromCtx(r)
	actorName := "admin"
	if actor != nil {
		actorName = actor.Username
	}

	switch action {
	case "ban":
		ip := strings.TrimSpace(r.FormValue("ip"))
		reason := strings.TrimSpace(r.FormValue("reason"))
		durHours, _ := strconv.Atoi(r.FormValue("duration_hours"))
		permanent := r.FormValue("permanent") == "1"
		if net.ParseIP(ip) == nil {
			http.Redirect(w, r, "/admin/security/bans?err=Invalid+IP+address.", http.StatusSeeOther)
			return
		}
		if reason == "" {
			reason = "Manual ban by " + actorName
		}
		dur := time.Duration(durHours) * time.Hour
		if permanent || durHours == 0 {
			dur = 0
			permanent = true
		}
		if _, err := security.CreateBan(h.db, ip, reason, actorName, permanent, dur); err != nil {
			h.log.Error("admin: create ban", "err", err)
			http.Redirect(w, r, "/admin/security/bans?err=Could+not+create+ban.", http.StatusSeeOther)
			return
		}
		h.log.Warn("admin: manual ban created", "ip", ip, "actor", actorName, "permanent", permanent)
		_ = h.engine.Reload()
		http.Redirect(w, r, "/admin/security/bans?msg=IP+banned.", http.StatusSeeOther)

	case "unban":
		banID, _ := strconv.ParseInt(r.FormValue("ban_id"), 10, 64)
		if err := security.UnbanIP(h.db, banID, actorName); err != nil {
			http.Redirect(w, r, "/admin/security/bans?err=Could+not+unban.", http.StatusSeeOther)
			return
		}
		h.log.Info("admin: ban removed", "ban_id", banID, "actor", actorName)
		_ = h.engine.Reload()
		http.Redirect(w, r, "/admin/security/bans?msg=Ban+removed.", http.StatusSeeOther)

	case "extend":
		banID, _ := strconv.ParseInt(r.FormValue("ban_id"), 10, 64)
		addHours, _ := strconv.Atoi(r.FormValue("add_hours"))
		if addHours <= 0 {
			addHours = 24
		}
		newExpiry := time.Now().Add(time.Duration(addHours) * time.Hour)
		if err := security.ExtendBan(h.db, banID, newExpiry); err != nil {
			http.Redirect(w, r, "/admin/security/bans?err=Could+not+extend+ban.", http.StatusSeeOther)
			return
		}
		h.log.Info("admin: ban extended", "ban_id", banID, "hours", addHours, "actor", actorName)
		_ = h.engine.Reload()
		http.Redirect(w, r, "/admin/security/bans?msg=Ban+extended.", http.StatusSeeOther)

	case "permanent":
		banID, _ := strconv.ParseInt(r.FormValue("ban_id"), 10, 64)
		if err := security.MakePermanent(h.db, banID); err != nil {
			http.Redirect(w, r, "/admin/security/bans?err=Could+not+update+ban.", http.StatusSeeOther)
			return
		}
		h.log.Warn("admin: ban made permanent", "ban_id", banID, "actor", actorName)
		_ = h.engine.Reload()
		http.Redirect(w, r, "/admin/security/bans?msg=Ban+is+now+permanent.", http.StatusSeeOther)

	default:
		http.Redirect(w, r, "/admin/security/bans?err=Unknown+action.", http.StatusSeeOther)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// /admin/security/rules  (IP rules)
// ─────────────────────────────────────────────────────────────────────────────

type AdminIPRulesData struct {
	PageData
	Rules []*security.IPRule
}

type AdminIPRulesHandler struct {
	tmpl   *Renderer
	db     *db.DB
	log    *logger.Logger
	engine *security.Engine
}

func NewAdminIPRulesHandler(r *Renderer, database *db.DB, l *logger.Logger, eng *security.Engine) *AdminIPRulesHandler {
	return &AdminIPRulesHandler{tmpl: r, db: database, log: l, engine: eng}
}

func (h *AdminIPRulesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		securityDisabled(h.tmpl, w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		rules, err := security.AllIPRules(h.db)
		if err != nil {
			h.log.Error("admin: list ip rules", "err", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		h.tmpl.Render(w, "admin_ip_rules", AdminIPRulesData{
			PageData: NewPageData(r, "IP Rules"),
			Rules:    rules,
		})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/admin/security/rules?err=Could+not+parse+form.", http.StatusSeeOther)
			return
		}
		action := r.FormValue("action")
		actor := middleware.UserFromCtx(r)
		actorName := "admin"
		if actor != nil {
			actorName = actor.Username
		}

		if action == "delete" {
			id, _ := strconv.ParseInt(r.FormValue("rule_id"), 10, 64)
			if err := security.DeleteIPRule(h.db, id); err != nil {
				http.Redirect(w, r, "/admin/security/rules?err=Could+not+delete+rule.", http.StatusSeeOther)
				return
			}
			_ = h.engine.Reload()
			http.Redirect(w, r, "/admin/security/rules?msg=Rule+deleted.", http.StatusSeeOther)
			return
		}

		// Create new rule
		cidrRaw := strings.TrimSpace(r.FormValue("cidr"))
		ruleType := security.RuleType(r.FormValue("type"))
		pathPat := strings.TrimSpace(r.FormValue("path_pattern"))
		pathType := security.PathMatchType(r.FormValue("path_type"))
		note := strings.TrimSpace(r.FormValue("note"))

		if pathPat == "" {
			pathPat = "*"
		}
		if pathType == "" {
			pathType = security.PathWildcard
		}

		// Normalise CIDR
		if !strings.Contains(cidrRaw, "/") {
			if net.ParseIP(cidrRaw) != nil {
				cidrRaw += "/32"
			}
		}
		if _, _, err := net.ParseCIDR(cidrRaw); err != nil {
			http.Redirect(w, r, "/admin/security/rules?err=Invalid+CIDR+or+IP.", http.StatusSeeOther)
			return
		}

		if err := security.CreateIPRule(h.db, cidrRaw, ruleType, pathPat, pathType, note, actorName); err != nil {
			h.log.Error("admin: create ip rule", "err", err)
			http.Redirect(w, r, "/admin/security/rules?err=Could+not+create+rule.", http.StatusSeeOther)
			return
		}
		h.log.Info("admin: ip rule created", "cidr", cidrRaw, "type", ruleType, "actor", actorName)
		_ = h.engine.Reload()
		http.Redirect(w, r, "/admin/security/rules?msg=Rule+added.", http.StatusSeeOther)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// /admin/security/countries  (country rules)
// ─────────────────────────────────────────────────────────────────────────────

type AdminCountryRulesData struct {
	PageData
	Rules       []*security.CountryRule
	GeoIPLoaded bool
	Countries   []countryOption
}

type countryOption struct {
	Code string
	Name string
}

type AdminCountryRulesHandler struct {
	tmpl   *Renderer
	db     *db.DB
	log    *logger.Logger
	engine *security.Engine
	geoip  *security.GeoIPDB
}

func NewAdminCountryRulesHandler(r *Renderer, database *db.DB, l *logger.Logger, eng *security.Engine, geoip *security.GeoIPDB) *AdminCountryRulesHandler {
	return &AdminCountryRulesHandler{tmpl: r, db: database, log: l, engine: eng, geoip: geoip}
}

func (h *AdminCountryRulesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.engine == nil {
		securityDisabled(h.tmpl, w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		rules, err := security.AllCountryRules(h.db)
		if err != nil {
			h.log.Error("admin: list country rules", "err", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		h.tmpl.Render(w, "admin_country_rules", AdminCountryRulesData{
			PageData:    NewPageData(r, "Country Rules"),
			Rules:       rules,
			GeoIPLoaded: h.geoip != nil && h.geoip.Loaded(),
			Countries:   commonCountries,
		})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/admin/security/countries?err=Could+not+parse+form.", http.StatusSeeOther)
			return
		}
		action := r.FormValue("action")
		actor := middleware.UserFromCtx(r)
		actorName := "admin"
		if actor != nil {
			actorName = actor.Username
		}

		if action == "delete" {
			id, _ := strconv.ParseInt(r.FormValue("rule_id"), 10, 64)
			if err := security.DeleteCountryRule(h.db, id); err != nil {
				http.Redirect(w, r, "/admin/security/countries?err=Could+not+delete+rule.", http.StatusSeeOther)
				return
			}
			_ = h.engine.Reload()
			http.Redirect(w, r, "/admin/security/countries?msg=Rule+deleted.", http.StatusSeeOther)
			return
		}

		code := strings.ToUpper(strings.TrimSpace(r.FormValue("country_code")))
		countryName := strings.TrimSpace(r.FormValue("country_name"))
		act := security.CountryAction(r.FormValue("action_type"))
		pathPat := strings.TrimSpace(r.FormValue("path_pattern"))
		pathType := security.PathMatchType(r.FormValue("path_type"))
		note := strings.TrimSpace(r.FormValue("note"))

		if len(code) != 2 {
			http.Redirect(w, r, "/admin/security/countries?err=Country+code+must+be+2+letters.", http.StatusSeeOther)
			return
		}
		if pathPat == "" {
			pathPat = "*"
		}
		if pathType == "" {
			pathType = security.PathWildcard
		}
		if act != security.CountryAllow && act != security.CountryBlock {
			act = security.CountryBlock
		}

		if err := security.CreateCountryRule(h.db, code, countryName, act, pathPat, pathType, note, actorName); err != nil {
			h.log.Error("admin: create country rule", "err", err)
			http.Redirect(w, r, "/admin/security/countries?err=Could+not+create+rule.", http.StatusSeeOther)
			return
		}
		h.log.Info("admin: country rule created", "code", code, "action", act, "actor", actorName)
		_ = h.engine.Reload()
		http.Redirect(w, r, "/admin/security/countries?msg=Country+rule+added.", http.StatusSeeOther)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// /admin/security/attempts
// ─────────────────────────────────────────────────────────────────────────────

type AdminAttemptsData struct {
	PageData
	Attempts   []*security.LoginAttempt
	Total      int
	Page       int
	TotalPages int
}

type AdminAttemptsHandler struct {
	tmpl *Renderer
	db   *db.DB
	log  *logger.Logger
}

func NewAdminAttemptsHandler(r *Renderer, database *db.DB, l *logger.Logger) *AdminAttemptsHandler {
	return &AdminAttemptsHandler{tmpl: r, db: database, log: l}
}

func (h *AdminAttemptsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	page := qInt(r, "page", 1)
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * secPageSize
	total, _ := security.CountAttempts(h.db)
	attempts, err := security.RecentAttempts(h.db, secPageSize, offset)
	if err != nil {
		h.log.Error("admin: list attempts", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	totalPages := (total + secPageSize - 1) / secPageSize
	if totalPages == 0 {
		totalPages = 1
	}
	h.tmpl.Render(w, "admin_attempts", AdminAttemptsData{
		PageData:   NewPageData(r, "Login Attempt History"),
		Attempts:   attempts,
		Total:      total,
		Page:       page,
		TotalPages: totalPages,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Common country list for the dropdown
// ─────────────────────────────────────────────────────────────────────────────

var commonCountries = []countryOption{
	{"AF", "Afghanistan"}, {"AL", "Albania"}, {"DZ", "Algeria"}, {"AR", "Argentina"},
	{"AU", "Australia"}, {"AT", "Austria"}, {"AZ", "Azerbaijan"}, {"BE", "Belgium"},
	{"BR", "Brazil"}, {"BG", "Bulgaria"}, {"CA", "Canada"}, {"CN", "China"},
	{"CO", "Colombia"}, {"HR", "Croatia"}, {"CZ", "Czech Republic"}, {"DK", "Denmark"},
	{"EG", "Egypt"}, {"EE", "Estonia"}, {"FI", "Finland"}, {"FR", "France"},
	{"DE", "Germany"}, {"GR", "Greece"}, {"HU", "Hungary"}, {"IN", "India"},
	{"ID", "Indonesia"}, {"IR", "Iran"}, {"IQ", "Iraq"}, {"IE", "Ireland"},
	{"IL", "Israel"}, {"IT", "Italy"}, {"JP", "Japan"}, {"KZ", "Kazakhstan"},
	{"KR", "South Korea"}, {"LV", "Latvia"}, {"LT", "Lithuania"}, {"MX", "Mexico"},
	{"NL", "Netherlands"}, {"NZ", "New Zealand"}, {"NG", "Nigeria"}, {"NO", "Norway"},
	{"PK", "Pakistan"}, {"PL", "Poland"}, {"PT", "Portugal"}, {"RO", "Romania"},
	{"RU", "Russia"}, {"SA", "Saudi Arabia"}, {"RS", "Serbia"}, {"SG", "Singapore"},
	{"SK", "Slovakia"}, {"ZA", "South Africa"}, {"ES", "Spain"}, {"SE", "Sweden"},
	{"CH", "Switzerland"}, {"TH", "Thailand"}, {"TR", "Turkey"}, {"UA", "Ukraine"},
	{"GB", "United Kingdom"}, {"US", "United States"}, {"VN", "Vietnam"},
}


