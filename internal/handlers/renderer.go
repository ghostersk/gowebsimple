// Package handlers provides the template renderer and shared page data types.
package handlers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"goapp/internal/db"
	"goapp/internal/middleware"
)

// ─────────────────────────────────────────────────────────────────────────────
// Renderer
// ─────────────────────────────────────────────────────────────────────────────
//
// CHOOSING A LAYOUT
// =================
// Every page template can declare its layout in the very first line using a
// Go template comment:
//
//   {{/* layout: base_public.html */}}
//
// If no such comment is present the default sidebar layout (base.html) is used.
//
// You can use any layout file that exists in web/templates/layouts/.
// The three built-in layouts are:
//
//   base.html        — full sidebar navigation (authenticated app pages)
//   base_public.html — top navigation bar      (public/marketing pages)
//   base_bare.html   — no navigation at all    (minimal, embed, print)
//
// To create a completely custom layout:
//   1. Create web/templates/layouts/my_layout.html
//      It must contain {{define "base"}} ... {{block "content" .}} ... {{end}}
//   2. In your page template, add as the very first line:
//        {{/* layout: my_layout.html */}}
//   3. Everything else is the same.
//
// EXAMPLE PAGE TEMPLATE
// =====================
//
//   {{/* layout: base_public.html */}}
//   {{template "base" .}}
//   {{define "title"}}My Page{{end}}
//   {{define "content"}}
//   <div class="max-w-4xl mx-auto py-12">
//       <h1 class="text-3xl font-bold text-white">{{.Title}}</h1>
//   </div>
//   {{end}}
//
// The {{/* layout: ... */}} comment is read by Go (not the browser) and tells
// the renderer which layout file to pair with this page. Remove it to fall back
// to base.html automatically.

const layoutCommentPrefix = "layout:"

// Renderer holds one pre-parsed *template.Template per page.
type Renderer struct {
	templates   map[string]*template.Template
	funcMap     template.FuncMap
	templateDir string
}

// NewRenderer scans web/templates/pages/*.html, reads each file's optional
// layout declaration, and pre-parses every page paired with its layout.
func NewRenderer(templateDir string) (*Renderer, error) {
	r := &Renderer{
		templates:   make(map[string]*template.Template),
		templateDir: templateDir,
	}
	r.funcMap = buildFuncMap()

	pages, err := filepath.Glob(filepath.Join(templateDir, "pages", "*.html"))
	if err != nil {
		return nil, fmt.Errorf("renderer: glob pages: %w", err)
	}
	if len(pages) == 0 {
		return nil, fmt.Errorf("renderer: no page templates found in %s/pages/", templateDir)
	}

	for _, page := range pages {
		if err := r.registerPage(page); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// registerPage reads the optional layout comment from pagePath and parses
// the layout + page into a single *template.Template.
func (r *Renderer) registerPage(pagePath string) error {
	name := templateName(pagePath)

	// Read the layout declaration from the first non-empty line.
	layout := readLayoutComment(pagePath)
	if layout == "" {
		layout = "base.html" // default
	}
	basePath := filepath.Join(r.templateDir, "layouts", layout)

	// If the named layout doesn't exist, fall back gracefully to base.html.
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		log.Printf("renderer: layout %q not found for %q — falling back to base.html", layout, name)
		basePath = filepath.Join(r.templateDir, "layouts", "base.html")
		layout = "base.html"
	}

	tmpl, err := template.New("base").
		Funcs(r.funcMap).
		ParseFiles(basePath, pagePath)
	if err != nil {
		return fmt.Errorf("renderer: parse %q (layout: %s): %w", name, layout, err)
	}
	r.templates[name] = tmpl
	log.Printf("renderer: registered %q → layout: %s", name, layout)
	return nil
}

// readLayoutComment reads the first non-empty line of a template file looking
// for a comment in the form:  {{/* layout: filename.html */}}
// Returns the filename (e.g. "base_public.html"), or "" if not found.
func readLayoutComment(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	linesRead := 0
	for scanner.Scan() && linesRead < 5 { // only look in first 5 lines
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		linesRead++
		// Match: {{/* layout: something.html */}}
		// or:    {{- /* layout: something.html */ -}}
		stripped := line
		for _, wrap := range []string{"{{/*", "*/}}", "{{-", "-}}", "/*", "*/"} {
			stripped = strings.ReplaceAll(stripped, wrap, "")
		}
		stripped = strings.TrimSpace(stripped)
		if strings.HasPrefix(stripped, layoutCommentPrefix) {
			name := strings.TrimSpace(strings.TrimPrefix(stripped, layoutCommentPrefix))
			// Validate: must end in .html and contain no path separators
			if strings.HasSuffix(name, ".html") && !strings.Contains(name, "/") && !strings.Contains(name, "\\") {
				return name
			}
		}
		break // only check the very first non-empty line
	}
	return ""
}

// Render writes the named page template to w with status 200.
func (r *Renderer) Render(w http.ResponseWriter, name string, data any) {
	r.RenderStatus(w, http.StatusOK, name, data)
}

// RenderStatus writes the named page template to w with an explicit HTTP status.
func (r *Renderer) RenderStatus(w http.ResponseWriter, status int, name string, data any) {
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
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func templateName(path string) string {
	base := filepath.Base(path)
	return base[:len(base)-len(filepath.Ext(base))]
}

// ─────────────────────────────────────────────────────────────────────────────
// FuncMap
// ─────────────────────────────────────────────────────────────────────────────

func buildFuncMap() template.FuncMap {
	return template.FuncMap{
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
		"seq": func(n int) []int {
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
		// jsStr safely embeds a Go string inside a JavaScript expression.
		// Usage:  var x = {{.MyField | jsStr}};
		// Output: var x = "hello \"world\"";
		"jsStr": func(s string) template.JS {
			b, _ := json.Marshal(s)
			return template.JS(b)
		},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Navigation & page data
// ─────────────────────────────────────────────────────────────────────────────

// NavItem is a sidebar or top-bar navigation link.
type NavItem struct {
	Label     string
	Href      string
	Icon      string
	AdminOnly bool
}

// DefaultNav is the sidebar navigation shown to authenticated users.
var DefaultNav = []NavItem{
	{Label: "Dashboard", Href: "/dashboard", Icon: "home"},
	{Label: "About",     Href: "/about",     Icon: "info"},
	{Label: "Contact",   Href: "/contact",   Icon: "mail"},
	{Label: "Users",     Href: "/admin/users", Icon: "users",    AdminOnly: true},
	{Label: "Logs",      Href: "/admin/logs",  Icon: "activity", AdminOnly: true},
}

// PublicNav is the top-bar navigation shown in the public layout.
var PublicNav = []NavItem{
	{Label: "Home",    Href: "/"},
	{Label: "About",   Href: "/about"},
	{Label: "Contact", Href: "/contact"},
}

// allowRegistration is set once at startup from config.AllowRegistration.
var allowRegistration bool

// SetAllowRegistration propagates the registration toggle into page data.
// Call this from router.New() after loading config.
func SetAllowRegistration(allow bool) { allowRegistration = allow }

// PageData carries template variables available in every page.
type PageData struct {
	CurrentPath       string
	Title             string
	User              *db.User
	Nav               []NavItem
	PublicNav         []NavItem
	FlashMsg          string
	FlashErr          string
	CSRFToken         string
	AllowRegistration bool
}

// NewPageData builds a PageData for the current request.
func NewPageData(r *http.Request, title string) PageData {
	user := middleware.UserFromCtx(r)

	nav := make([]NavItem, 0, len(DefaultNav))
	for _, item := range DefaultNav {
		if item.AdminOnly && (user == nil || !user.IsAdmin()) {
			continue
		}
		nav = append(nav, item)
	}

	pd := PageData{
		CurrentPath:       r.URL.Path,
		Title:             title,
		User:              user,
		Nav:               nav,
		PublicNav:         PublicNav,
		AllowRegistration: allowRegistration,
	}
	if msg := r.URL.Query().Get("msg"); msg != "" {
		pd.FlashMsg = msg
	}
	if errMsg := r.URL.Query().Get("err"); errMsg != "" {
		pd.FlashErr = errMsg
	}
	return pd
}

// ─────────────────────────────────────────────────────────────────────────────
// SVG icon helper
// ─────────────────────────────────────────────────────────────────────────────

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
		"mfa":      `<svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>`,
	}
	if svg, ok := icons[name]; ok {
		return template.HTML(svg)
	}
	return template.HTML(`<svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.75"><circle cx="12" cy="12" r="10"/></svg>`)
}
