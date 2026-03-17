package handlers

import (
	"net/http"
	"strings"

	"goapp/internal/mailer"
)

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard
// ─────────────────────────────────────────────────────────────────────────────

type DashboardHandler struct{ tmpl *Renderer }

func NewDashboardHandler(r *Renderer) *DashboardHandler { return &DashboardHandler{tmpl: r} }

func (h *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dashboard" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := struct{ PageData }{PageData: NewPageData(r, "Dashboard")}
	h.tmpl.Render(w, "dashboard", data)
}

// ─────────────────────────────────────────────────────────────────────────────
// Home
// ─────────────────────────────────────────────────────────────────────────────

type HomeHandler struct{ tmpl *Renderer }

func NewHomeHandler(r *Renderer) *HomeHandler { return &HomeHandler{tmpl: r} }

func (h *HomeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := struct{ PageData }{PageData: NewPageData(r, "Home")}
	h.tmpl.Render(w, "home", data)
}

// ─────────────────────────────────────────────────────────────────────────────
// About
// ─────────────────────────────────────────────────────────────────────────────

type AboutHandler struct{ tmpl *Renderer }

func NewAboutHandler(r *Renderer) *AboutHandler { return &AboutHandler{tmpl: r} }

func (h *AboutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := struct{ PageData }{PageData: NewPageData(r, "About")}
	h.tmpl.Render(w, "about", data)
}

// ─────────────────────────────────────────────────────────────────────────────
// Contact — demonstrates mailer integration
// ─────────────────────────────────────────────────────────────────────────────

type ContactForm struct {
	Name    string
	Email   string
	Message string
}

type ContactData struct {
	PageData
	Form ContactForm
}

// ContactHandler serves GET/POST /contact.
// It accepts a *mailer.Mailer and sends a notification email on form submit.
// When m.Enabled() is false (email disabled in config) the form still works,
// it just skips the email send silently.
type ContactHandler struct {
	tmpl   *Renderer
	mailer *mailer.Mailer
}

func NewContactHandler(r *Renderer, m *mailer.Mailer) *ContactHandler {
	return &ContactHandler{tmpl: r, mailer: m}
}

func (h *ContactHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sent := r.URL.Query().Get("sent") == "1"
		pd := NewPageData(r, "Contact")
		if sent {
			pd.FlashMsg = "Message sent — we'll be in touch soon."
		}
		h.tmpl.Render(w, "contact", ContactData{PageData: pd})
	case http.MethodPost:
		h.handlePost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *ContactHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		h.renderErr(w, r, ContactForm{}, "Could not parse form.")
		return
	}

	form := ContactForm{
		Name:    strings.TrimSpace(r.FormValue("name")),
		Email:   strings.TrimSpace(r.FormValue("email")),
		Message: strings.TrimSpace(r.FormValue("message")),
	}

	switch {
	case form.Name == "":
		h.renderErr(w, r, form, "Name is required.")
		return
	case !strings.Contains(form.Email, "@"):
		h.renderErr(w, r, form, "A valid email address is required.")
		return
	case form.Message == "":
		h.renderErr(w, r, form, "Message cannot be empty.")
		return
	case len(form.Message) > 2000:
		h.renderErr(w, r, form, "Message must be 2 000 characters or fewer.")
		return
	}

	// ── Send notification email ───────────────────────────────────────────
	// To use this in your own handlers, follow this same pattern:
	//   1. Inject *mailer.Mailer into your handler struct
	//   2. Call h.mailer.Send(mailer.Message{...})
	//   3. Log errors but don't abort the request — email failure should
	//      not break the user experience
	// ─────────────────────────────────────────────────────────────────────
	if h.mailer.Enabled() {
		body := "New contact form submission\n\n" +
			"Name:    " + form.Name + "\n" +
			"Email:   " + form.Email + "\n" +
			"Message: " + form.Message
		// In production replace "admin@localhost" with a real address,
		// or read it from config.
		_ = h.mailer.Send(mailer.Message{
			To:      []string{"admin@localhost"},
			Subject: "Contact form: " + form.Name,
			Body:    body,
		})
		// Note: we intentionally ignore the error here so a mail
		// server misconfiguration doesn't break form submission.
		// Log it instead if you need visibility:
		//   if err := h.mailer.Send(...); err != nil {
		//       h.log.Warn("contact: email failed", "err", err)
		//   }
	}

	// PRG pattern — redirect to prevent duplicate submissions on refresh
	http.Redirect(w, r, "/contact?sent=1", http.StatusSeeOther)
}

func (h *ContactHandler) renderErr(w http.ResponseWriter, r *http.Request, form ContactForm, errMsg string) {
	pd := NewPageData(r, "Contact")
	pd.FlashErr = errMsg
	h.tmpl.Render(w, "contact", ContactData{PageData: pd, Form: form})
}

// ─────────────────────────────────────────────────────────────────────────────
// Public landing page (uses base_public.html layout via layout comment)
// ─────────────────────────────────────────────────────────────────────────────

type PubLandingHandler struct{ tmpl *Renderer }

func NewPubLandingHandler(r *Renderer) *PubLandingHandler { return &PubLandingHandler{tmpl: r} }

func (h *PubLandingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := struct{ PageData }{PageData: NewPageData(r, "Welcome")}
	h.tmpl.Render(w, "landing", data)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
