package handlers

import "net/http"

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard handler — the main authenticated landing page
// ─────────────────────────────────────────────────────────────────────────────

type DashboardData struct {
	PageData
}

// DashboardHandler serves GET /dashboard.
type DashboardHandler struct {
	tmpl *Renderer
}

func NewDashboardHandler(r *Renderer) *DashboardHandler {
	return &DashboardHandler{tmpl: r}
}

func (h *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dashboard" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := DashboardData{PageData: NewPageData(r, "Dashboard")}
	h.tmpl.Render(w, "dashboard", data)
}

// ─────────────────────────────────────────────────────────────────────────────
// Home handler — the public landing page
// ─────────────────────────────────────────────────────────────────────────────

// HomeHandler serves GET /.
type HomeHandler struct {
	tmpl *Renderer
}

func NewHomeHandler(r *Renderer) *HomeHandler {
	return &HomeHandler{tmpl: r}
}

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
// About handler
// ─────────────────────────────────────────────────────────────────────────────

// AboutHandler serves GET /about.
type AboutHandler struct {
	tmpl *Renderer
}

func NewAboutHandler(r *Renderer) *AboutHandler {
	return &AboutHandler{tmpl: r}
}

func (h *AboutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := struct{ PageData }{PageData: NewPageData(r, "About")}
	h.tmpl.Render(w, "about", data)
}

// ─────────────────────────────────────────────────────────────────────────────
// Contact handler
// ─────────────────────────────────────────────────────────────────────────────

type ContactForm struct {
	Name    string
	Email   string
	Message string
}

type ContactData struct {
	PageData
	Form    ContactForm
}

// ContactHandler serves GET/POST /contact.
type ContactHandler struct {
	tmpl *Renderer
}

func NewContactHandler(r *Renderer) *ContactHandler {
	return &ContactHandler{tmpl: r}
}

func (h *ContactHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sent := r.URL.Query().Get("sent") == "1"
		pd := NewPageData(r, "Contact")
		if sent {
			pd.FlashMsg = "Message sent successfully!"
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
		h.tmpl.Render(w, "contact", ContactData{
			PageData: newPageDataWithErr(r, "Contact", "Could not parse form."),
		})
		return
	}

	form := ContactForm{
		Name:    trimSafe(r.FormValue("name")),
		Email:   trimSafe(r.FormValue("email")),
		Message: trimSafe(r.FormValue("message")),
	}

	switch {
	case form.Name == "":
		h.renderContactErr(w, r, form, "Name is required.")
		return
	case form.Email == "" || !containsChar(form.Email, '@'):
		h.renderContactErr(w, r, form, "A valid email address is required.")
		return
	case form.Message == "":
		h.renderContactErr(w, r, form, "Message cannot be empty.")
		return
	case len(form.Message) > 2000:
		h.renderContactErr(w, r, form, "Message must be 2 000 characters or fewer.")
		return
	}

	http.Redirect(w, r, "/contact?sent=1", http.StatusSeeOther)
}

func (h *ContactHandler) renderContactErr(w http.ResponseWriter, r *http.Request, form ContactForm, errMsg string) {
	pd := newPageDataWithErr(r, "Contact", errMsg)
	h.tmpl.Render(w, "contact", ContactData{PageData: pd, Form: form})
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

func newPageDataWithErr(r *http.Request, title, errMsg string) PageData {
	pd := NewPageData(r, title)
	pd.FlashErr = errMsg
	return pd
}

func trimSafe(s string) string {
	result := make([]byte, 0, len(s))
	for _, b := range []byte(s) {
		if b != 0 {
			result = append(result, b)
		}
	}
	// Trim spaces
	start, end := 0, len(result)
	for start < end && (result[start] == ' ' || result[start] == '\t' || result[start] == '\n' || result[start] == '\r') {
		start++
	}
	for end > start && (result[end-1] == ' ' || result[end-1] == '\t' || result[end-1] == '\n' || result[end-1] == '\r') {
		end--
	}
	return string(result[start:end])
}

func containsChar(s string, c rune) bool {
	for _, r := range s {
		if r == c {
			return true
		}
	}
	return false
}
