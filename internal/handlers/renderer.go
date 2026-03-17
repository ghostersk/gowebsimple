// Package handlers provides the template renderer and shared page data types.
package handlers

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"goapp/internal/db"
	"goapp/internal/middleware"
)

// ─────────────────────────────────────────────────────────────────────────────
// Renderer
// ─────────────────────────────────────────────────────────────────────────────

// Renderer holds a map of pre-parsed templates, one per page.
type Renderer struct {
	templates map[string]*template.Template
	funcMap   template.FuncMap
}

// NewRenderer builds the Renderer by pairing the base layout with each page template.
func NewRenderer(templateDir string) (*Renderer, error) {
	r := &Renderer{
		templates: make(map[string]*template.Template),
	}
	r.funcMap = template.FuncMap{
		"inc":       func(i int) int { return i + 1 },
		"dec":       func(i int) int { return i - 1 },
		"add":       func(a, b int) int { return a + b },
		"sub":       func(a, b int) int { return a - b },
		"safeHTML":  func(s string) template.HTML { return template.HTML(s) },
		"upper":     strings.ToUpper,
		"lower":     strings.ToLower,
		"contains":  strings.Contains,
		"hasPrefix": strings.HasPrefix,
		"substr": func(s string, i, j int) string {
			if i >= len(s) { return "" }
			if j > len(s)  { j = len(s) }
			return s[i:j]
		},
		"navIcon": navIconSVG,
		"seq":     func(n int) []int {
			s := make([]int, n)
			for i := range s { s[i] = i + 1 }
			return s
		},
		"levelClass": func(level string) string {
			switch level {
			case "ERROR": return "level-error"
			case "WARN":  return "level-warn"
			case "INFO":  return "level-info"
			default:      return "level-debug"
			}
		},
		"formatTime": func(t interface{}) string {
			switch v := t.(type) {
			case interface{ Format(string) string }:
				return v.Format("2006-01-02 15:04")
			}
			return ""
		},
	}

	basePath := filepath.Join(templateDir, "layouts", "base.html")

	pages, err := filepath.Glob(filepath.Join(templateDir, "pages", "*.html"))
	if err != nil {
		return nil, fmt.Errorf("renderer: glob pages: %w", err)
	}
	if len(pages) == 0 {
		return nil, fmt.Errorf("renderer: no page templates found in %s/pages/", templateDir)
	}

	for _, page := range pages {
		name := templateName(page)
		tmpl, err := template.New("base").
			Funcs(r.funcMap).
			ParseFiles(basePath, page)
		if err != nil {
			return nil, fmt.Errorf("renderer: parse %s: %w", name, err)
		}
		r.templates[name] = tmpl
		log.Printf("renderer: registered template %q", name)
	}

	return r, nil
}

// Render executes the named page template into a buffer then writes it.
func (r *Renderer) Render(w http.ResponseWriter, name string, data any) {
	tmpl, ok := r.templates[name]
	if !ok {
		http.Error(w, fmt.Sprintf("template %q not found", name), http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base", data); err != nil {
		log.Printf("renderer: execute %q: %v", name, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func templateName(path string) string {
	base := filepath.Base(path)
	return base[:len(base)-len(filepath.Ext(base))]
}

// navIconSVG returns an inline SVG for sidebar navigation icons.
func navIconSVG(name string) template.HTML {
	icons := map[string]string{
		"home":     `<svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><path stroke-linecap="round" stroke-linejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>`,
		"info":     `<svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`,
		"mail":     `<svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><path stroke-linecap="round" stroke-linejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>`,
		"users":    `<svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg>`,
		"activity": `<svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><path stroke-linecap="round" stroke-linejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>`,
		"settings": `<svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>`,
		"logout":   `<svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>`,
		"shield":   `<svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>`,
		"key":      `<svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><path stroke-linecap="round" stroke-linejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>`,
	}
	if svg, ok := icons[name]; ok {
		return template.HTML(svg)
	}
	return template.HTML(`<svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><circle cx="12" cy="12" r="10"/></svg>`)
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared page data
// ─────────────────────────────────────────────────────────────────────────────

// NavItem represents a sidebar navigation entry.
type NavItem struct {
	Label    string
	Href     string
	Icon     string
	AdminOnly bool
}

// DefaultNav is the navigation structure for the app.
var DefaultNav = []NavItem{
	{Label: "Dashboard", Href: "/dashboard", Icon: "home"},
	{Label: "About",     Href: "/about",     Icon: "info"},
	{Label: "Contact",   Href: "/contact",   Icon: "mail"},
	// Admin-only items
	{Label: "Users",     Href: "/admin/users",   Icon: "users",    AdminOnly: true},
	{Label: "Logs",      Href: "/admin/logs",    Icon: "activity", AdminOnly: true},
}

// PageData contains fields available to every template.
type PageData struct {
	CurrentPath string
	Title       string
	User        *db.User   // nil if unauthenticated
	Nav         []NavItem
	FlashMsg    string
	FlashErr    string
	CSRFToken   string
}

// NewPageData creates a PageData for the current request.
func NewPageData(r *http.Request, title string) PageData {
	user := middleware.UserFromCtx(r)

	// Build nav, filtering admin-only items for non-admins
	nav := make([]NavItem, 0, len(DefaultNav))
	for _, item := range DefaultNav {
		if item.AdminOnly && (user == nil || !user.IsAdmin()) {
			continue
		}
		nav = append(nav, item)
	}

	pd := PageData{
		CurrentPath: r.URL.Path,
		Title:       title,
		User:        user,
		Nav:         nav,
	}

	// Read flash messages from query params (set after redirects)
	if msg := r.URL.Query().Get("msg"); msg != "" {
		pd.FlashMsg = msg
	}
	if errMsg := r.URL.Query().Get("err"); errMsg != "" {
		pd.FlashErr = errMsg
	}

	return pd
}
