# GoApp — Modular Page Guide

This document explains how to add a new page to the application.
The entire process takes **4 steps** and touches **3 files**.

---

## Quick Start: Add a Page

### Step 1 — Create the Handler (`internal/handlers/mypage.go`)

```go
package handlers

import "net/http"

// MyPageData holds template data for this page.
// Always embed PageData — it carries User, Nav, flash messages, etc.
type MyPageData struct {
    PageData
    // Add your page-specific fields here:
    Items []string
}

// MyPageHandler serves GET /mypage.
type MyPageHandler struct {
    tmpl *Renderer
}

func NewMyPageHandler(r *Renderer) *MyPageHandler {
    return &MyPageHandler{tmpl: r}
}

func (h *MyPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }

    data := MyPageData{
        PageData: NewPageData(r, "My Page"),
        Items:    []string{"foo", "bar", "baz"},
    }
    h.tmpl.Render(w, "mypage", data)
}
```

**Rules:**
- Always check `r.Method` and return 405 for wrong methods.
- For the root `/` route only: add `if r.URL.Path != "/" { http.NotFound(w, r); return }`.
- Use `NewPageData(r, "Title")` — this injects the user, nav, and flash messages automatically.

---

### Step 2 — Create the Template (`web/templates/pages/mypage.html`)

```html
{{template "base" .}}

{{define "title"}}My Page — GoApp{{end}}

{{define "content"}}
<div class="max-w-4xl mx-auto">

    <h2 class="text-2xl font-semibold text-white mb-6">My Page</h2>

    <div class="grid sm:grid-cols-2 gap-4">
        {{range .Items}}
        <div class="card">
            <p class="text-gray-300">{{.}}</p>
        </div>
        {{end}}
    </div>

</div>
{{end}}

{{/* Optional — only if this page needs extra scripts */}}
{{define "scripts"}}
<script>
console.log('mypage loaded');
</script>
{{end}}
```

**Rules:**
- Line 1 MUST be `{{template "base" .}}` — no exceptions.
- Never define `"base"` in a page file.
- The file name (without `.html`) is the template name — must match the `Render(w, "mypage", data)` call.

---

### Step 3 — Register the Route (`internal/router/router.go`)

```go
// Inside func New(...):
mux.Handle("/mypage", handlers.NewMyPageHandler(renderer))
```

For an **authenticated-only** page:
```go
mux.Handle("/mypage", middleware.RequireAuth(handlers.NewMyPageHandler(renderer)))
```

For an **admin-only** page:
```go
mux.Handle("/mypage", adminMW(handlers.NewMyPageHandler(renderer)))
```

---

### Step 4 — (Optional) Add to Sidebar Navigation (`internal/handlers/renderer.go`)

```go
var DefaultNav = []NavItem{
    // ...existing items...
    {Label: "My Page", Href: "/mypage", Icon: "info"},
    // Admin-only sidebar entry:
    {Label: "My Admin Page", Href: "/mypage", Icon: "shield", AdminOnly: true},
}
```

Available icons: `home`, `info`, `mail`, `users`, `activity`, `settings`, `logout`, `shield`, `key`

---

## Page with POST Form

For pages that handle form submission, use the **Post-Redirect-Get (PRG)** pattern:

```go
func (h *MyPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        h.tmpl.Render(w, "mypage", MyPageData{PageData: NewPageData(r, "My Page")})
    case http.MethodPost:
        h.handlePost(w, r)
    default:
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
    }
}

func (h *MyPageHandler) handlePost(w http.ResponseWriter, r *http.Request) {
    // Always limit body size first
    r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
    if err := r.ParseForm(); err != nil {
        http.Redirect(w, r, "/mypage?err=Could+not+parse+form.", http.StatusSeeOther)
        return
    }

    value := strings.TrimSpace(r.FormValue("myfield"))
    if value == "" {
        http.Redirect(w, r, "/mypage?err=Field+is+required.", http.StatusSeeOther)
        return
    }

    // ... process ...

    // Redirect on success (PRG pattern prevents duplicate submissions)
    http.Redirect(w, r, "/mypage?msg=Saved+successfully.", http.StatusSeeOther)
}
```

Flash messages (`?msg=` and `?err=`) are automatically picked up by `NewPageData` and displayed by the base layout.

---

## Database Access

To use the database in a handler, inject `*db.DB` via the constructor:

```go
type MyPageHandler struct {
    tmpl *Renderer
    db   *db.DB
    log  *logger.Logger
}

func NewMyPageHandler(r *Renderer, database *db.DB, l *logger.Logger) *MyPageHandler {
    return &MyPageHandler{tmpl: r, db: database, log: l}
}
```

Then pass it in `router.go`:
```go
mux.Handle("/mypage", handlers.NewMyPageHandler(renderer, database, log))
```

---

## Available CSS Classes

| Class | Usage |
|---|---|
| `.card` | Dark card container with hover border |
| `.btn-primary` | Accent-colored action button |
| `.btn-ghost` | Transparent bordered button |
| `.input-field` | Dark-themed text input / select / textarea |
| `.field-label` | Small uppercase monospace label above inputs |
| `.badge` | Inline label (combine with `.badge-admin`, `.badge-user`, `.badge-active`, `.badge-inactive`) |
| `.flash-success` / `.flash-error` | Alert banners (auto-created by base layout via query params) |
| `.nav-link` / `.nav-link--active` | Sidebar navigation links |
| `.level-badge` | Log level badge (combine with `.level-error`, `.level-warn`, etc.) |

All Tailwind utility classes are also available via CDN.

---

## Security Checklist for New Pages

- [ ] Check `r.Method` and return 405 for wrong methods
- [ ] For `/` route only: check `r.URL.Path != "/"` and return 404
- [ ] Apply `middleware.RequireAuth` or `adminMW` if the page needs authentication
- [ ] `http.MaxBytesReader(w, r.Body, 1<<20)` before `r.ParseForm()` on every POST
- [ ] Trim and validate all form inputs server-side — never trust client data
- [ ] Use PRG pattern for POST forms (`http.Redirect` with `http.StatusSeeOther`)
- [ ] Never interpolate user input directly into SQL — use parameterized queries via `db.*` methods

---

## Running the App

```bash
# Install dependencies (only modernc.org/sqlite — pure Go, no CGO)
go mod tidy

# Run with debug logging enabled
go run ./cmd/server -debug

# Run with custom port and persistent CSRF key
CSRF_KEY=your-32-byte-hex-key go run ./cmd/server -addr :9000

# Default admin credentials (change immediately in production!)
# Username: admin
# Password: Admin1234!
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `:8080` | Listen address |
| `DATA_DIR` | `./data` | SQLite database directory |
| `DEBUG` | `0` | Set to `1` to enable debug logs |
| `CSRF_KEY` | _(auto-generated)_ | 32-byte hex HMAC key for CSRF tokens |

---

## Architecture Summary

```
Request → SecureHeaders → Auth (inject user) → Logger → Recovery → Mux
                                                                      ↓
                                                    RequireAuth / RequireAdmin
                                                                      ↓
                                                            Handler.ServeHTTP
                                                                      ↓
                                                         Renderer.Render(w, name, data)
                                                                      ↓
                                                       tmpl.ExecuteTemplate(&buf, "base", data)
                                                                      ↓
                                                              buf.WriteTo(w)
```
