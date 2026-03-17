package handlers

import (
	"net/http"
	"strings"

	"goapp/internal/auth"
	"goapp/internal/db"
	"goapp/internal/logger"
	"goapp/internal/middleware"
)

// ─────────────────────────────────────────────────────────────────────────────
// MFA Setup handler  — GET/POST /profile/mfa
// ─────────────────────────────────────────────────────────────────────────────

type MFASetupData struct {
	PageData
	Secret     string
	OTPAuthURI string
	Step       string // "start" | "verify" | "done" | "disable"
}

// MFASetupHandler serves GET/POST /profile/mfa.
type MFASetupHandler struct {
	tmpl *Renderer
	db   *db.DB
	log  *logger.Logger
}

func NewMFASetupHandler(r *Renderer, database *db.DB, l *logger.Logger) *MFASetupHandler {
	return &MFASetupHandler{tmpl: r, db: database, log: l}
}

func (h *MFASetupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.showSetup(w, r)
	case http.MethodPost:
		h.handlePost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *MFASetupHandler) showSetup(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromCtx(r)
	pd := NewPageData(r, "Two-Factor Authentication")

	if user.MFAEnabled {
		h.tmpl.Render(w, "mfa_setup", MFASetupData{PageData: pd, Step: "done"})
		return
	}

	// Check if there's a pending secret in the DB (started setup but not verified)
	fresh, _ := h.db.UserByID(user.ID)
	if fresh != nil && fresh.MFASecret != "" && !fresh.MFAEnabled {
		// Resume setup
		uri := auth.TOTPProvisioningURI(fresh.MFASecret, "GoApp", fresh.Username)
		h.tmpl.Render(w, "mfa_setup", MFASetupData{
			PageData:   pd,
			Step:       "verify",
			Secret:     fresh.MFASecret,
			OTPAuthURI: uri,
		})
		return
	}

	h.tmpl.Render(w, "mfa_setup", MFASetupData{PageData: pd, Step: "start"})
}

func (h *MFASetupHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/profile/mfa?err=Could+not+parse+form.", http.StatusSeeOther)
		return
	}

	user := middleware.UserFromCtx(r)
	action := r.FormValue("action")

	switch action {
	case "generate":
		// Generate a new TOTP secret and store it (unconfirmed)
		secret, err := auth.GenerateTOTPSecret()
		if err != nil {
			h.log.Error("mfa: generate secret", "err", err)
			http.Redirect(w, r, "/profile/mfa?err=Could+not+generate+secret.", http.StatusSeeOther)
			return
		}
		if err := h.db.SetMFASecret(user.ID, secret); err != nil {
			h.log.Error("mfa: save secret", "err", err)
			http.Redirect(w, r, "/profile/mfa?err=Could+not+save+secret.", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/profile/mfa", http.StatusSeeOther)

	case "verify":
		// Confirm setup by verifying the first code
		code := strings.TrimSpace(r.FormValue("code"))
		fresh, err := h.db.UserByID(user.ID)
		if err != nil || fresh.MFASecret == "" {
			http.Redirect(w, r, "/profile/mfa?err=Setup+session+expired.+Please+start+again.", http.StatusSeeOther)
			return
		}
		if !auth.ValidateTOTP(fresh.MFASecret, code) {
			h.log.Warn("mfa: setup verify failed", "username", user.Username)
			http.Redirect(w, r, "/profile/mfa?err=Invalid+code.+Check+your+authenticator+app+and+try+again.", http.StatusSeeOther)
			return
		}
		if err := h.db.EnableMFA(user.ID); err != nil {
			h.log.Error("mfa: enable", "err", err)
			http.Redirect(w, r, "/profile/mfa?err=Could+not+enable+MFA.", http.StatusSeeOther)
			return
		}
		h.log.Info("mfa enabled", "username", user.Username)
		http.Redirect(w, r, "/profile/mfa?msg=Two-factor+authentication+enabled.", http.StatusSeeOther)

	case "disable":
		// User disables their own MFA (requires current TOTP code)
		code := strings.TrimSpace(r.FormValue("code"))
		fresh, err := h.db.UserByID(user.ID)
		if err != nil {
			http.Redirect(w, r, "/profile/mfa?err=Account+not+found.", http.StatusSeeOther)
			return
		}
		if !auth.ValidateTOTP(fresh.MFASecret, code) {
			h.log.Warn("mfa: disable verify failed", "username", user.Username)
			http.Redirect(w, r, "/profile/mfa?err=Invalid+code.+MFA+not+disabled.", http.StatusSeeOther)
			return
		}
		if err := h.db.DisableMFA(user.ID); err != nil {
			http.Redirect(w, r, "/profile/mfa?err=Could+not+disable+MFA.", http.StatusSeeOther)
			return
		}
		h.log.Warn("mfa disabled by user", "username", user.Username)
		http.Redirect(w, r, "/profile/mfa?msg=Two-factor+authentication+disabled.", http.StatusSeeOther)

	default:
		http.Redirect(w, r, "/profile/mfa", http.StatusSeeOther)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// MFA Challenge handler — GET/POST /login/mfa
// After password is verified, users with MFA must pass this step.
// ─────────────────────────────────────────────────────────────────────────────

type MFAChallengeData struct {
	PageData
	PendingToken string // temporary token identifying the pending login
	Next         string // redirect destination after successful MFA
}

// MFAChallengeHandler serves GET/POST /login/mfa.
type MFAChallengeHandler struct {
	tmpl    *Renderer
	db      *db.DB
	log     *logger.Logger
	pending *PendingMFAStore
}

func NewMFAChallengeHandler(r *Renderer, database *db.DB, l *logger.Logger, store *PendingMFAStore) *MFAChallengeHandler {
	return &MFAChallengeHandler{tmpl: r, db: database, log: l, pending: store}
}

func (h *MFAChallengeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		token := r.URL.Query().Get("t")
		entry := h.pending.Get(token)
		if entry == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		pd := NewPageData(r, "Two-Factor Authentication")
		h.tmpl.Render(w, "mfa_challenge", MFAChallengeData{PageData: pd, PendingToken: token, Next: entry.Next})

	case http.MethodPost:
		h.handlePost(w, r)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *MFAChallengeHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	token := r.FormValue("pending_token")
	code := strings.TrimSpace(r.FormValue("code"))
	next := strings.TrimSpace(r.FormValue("next"))

	entry := h.pending.Get(token)
	if entry == nil {
		http.Redirect(w, r, "/login?err=Session+expired.+Please+sign+in+again.", http.StatusSeeOther)
		return
	}

	user, err := h.db.UserByID(entry.UserID)
	if err != nil || !user.Active {
		h.pending.Delete(token)
		http.Redirect(w, r, "/login?err=Account+not+found+or+disabled.", http.StatusSeeOther)
		return
	}

	if !auth.ValidateTOTP(user.MFASecret, code) {
		h.log.Warn("mfa: challenge failed", "username", user.Username)
		pd := NewPageData(r, "Two-Factor Authentication")
		pd.FlashErr = "Invalid code. Please try again."
		h.tmpl.Render(w, "mfa_challenge", MFAChallengeData{
			PageData:     pd,
			PendingToken: token,
			Next:         entry.Next,
		})
		return
	}

	// MFA passed — create real session
	h.pending.Delete(token)
	sess, err := h.db.CreateSession(user.ID)
	if err != nil {
		h.log.Error("mfa: create session", "err", err)
		http.Redirect(w, r, "/login?err=An+error+occurred.", http.StatusSeeOther)
		return
	}
	_ = h.db.UpdateLastLogin(user.ID)
	h.log.Info("login success (mfa)", "username", user.Username)
	middleware.SetSessionCookie(w, sess.Token, sess.ExpiresAt)

	if next == "" || !strings.HasPrefix(next, "/") {
		next = "/dashboard"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}
