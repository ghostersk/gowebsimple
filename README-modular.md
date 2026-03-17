# GoApp — Complete Developer Guide

A secure, modular Go web application framework built on the standard library.

---

## Quick Start

```bash
cd goapp
go mod tidy                  # fetch modernc.org/sqlite (the only dependency)
go run ./cmd/server          # → http://localhost:8080

# Default admin credentials (change these immediately):
#   Username: admin
#   Password: Admin1234!
```

The app creates `data/config.json` on first run with auto-generated secrets and safe defaults.

---

## Configuration (`data/config.json`)

Edit this file and restart the server. New fields added in upgrades are back-filled automatically.

```jsonc
{
  // ── Network ────────────────────────────────────────────────────────────────
  "host": "0.0.0.0",          // bind address; "127.0.0.1" for local-only
  "port": "8080",              // listen port

  // Restrict requests to a specific hostname. "*" accepts any Host header.
  // Set to "app.example.com" to block requests for other hostnames (returns 404).
  "web_domain": "*",

  // Real-IP extraction. When a request comes from one of these IPs,
  // X-Forwarded-For is trusted and the real client IP is logged instead.
  "reverse_proxies": [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
  ],

  // ── Database ───────────────────────────────────────────────────────────────
  // See "Switching Databases" section below for MySQL/PostgreSQL examples.
  "database_url": "file:./data/app.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)",

  // ── Security ───────────────────────────────────────────────────────────────
  // Auto-generated on first run. Do NOT change csrf_key on a live deployment —
  // it will invalidate all active user sessions.
  "csrf_key": "...",
  "session_secret": "...",

  // ── Access control ─────────────────────────────────────────────────────────
  // false (default) = public registration disabled; admins create accounts.
  // true            = anyone can create an account at /register.
  "allow_registration": false,

  // ── Email ──────────────────────────────────────────────────────────────────
  "email": {
    "enabled":      false,          // set true to activate email sending
    "smtp_host":    "smtp.example.com",
    "smtp_port":    587,            // 25=none, 465=SSL, 587=STARTTLS
    "encryption":   "starttls",     // "none" | "ssl" | "starttls"
    "auth":         true,           // false = skip SMTP authentication
    "username":     "noreply@example.com",
    "password":     "your-password",
    "from_address": "GoApp <noreply@example.com>"
  },

  // ── Logging ────────────────────────────────────────────────────────────────
  "debug": false,              // true = show DEBUG entries in admin log viewer
  "log_retention_days": 90     // auto-prune logs older than N days
}
```

---

## Switching Databases

The app uses Go's `database/sql` interface. The driver is selected automatically from the URL scheme. To switch databases:

### 1 — SQLite (default, no extra steps)

```json
"database_url": "file:./data/app.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
```

No extra imports or `go get` needed. Uses `modernc.org/sqlite` (pure Go, no CGO).

---

### 2 — MySQL / MariaDB

**Step 1** — Update `database_url` in `config.json`:
```json
"database_url": "mysql://dbuser:dbpass@tcp(127.0.0.1:3306)/mydb?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci"
```

**Step 2** — Create `cmd/server/drivers.go`:
```go
package main

import _ "github.com/go-sql-driver/mysql"
```

**Step 3** — Fetch the driver and update the schema:
```bash
go get github.com/go-sql-driver/mysql
go mod tidy
```

**Step 4** — Create the database and user in MySQL:
```sql
CREATE DATABASE mydb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'dbuser'@'localhost' IDENTIFIED BY 'dbpass';
GRANT ALL PRIVILEGES ON mydb.* TO 'dbuser'@'localhost';
FLUSH PRIVILEGES;
```

**Step 5** — Update the `id` columns in `internal/db/db.go` → `migrate()`.  
Change `INTEGER NOT NULL` to `INT NOT NULL AUTO_INCREMENT` for all three tables:
```sql
-- users
id  INT NOT NULL AUTO_INCREMENT,

-- sessions  (token is TEXT PRIMARY KEY, no change needed)

-- app_logs
id  INT NOT NULL AUTO_INCREMENT,
```

**Full MySQL DSN reference:**
```
mysql://user:pass@tcp(host:port)/dbname?parseTime=true&charset=utf8mb4
         │    │         │    │    │
         │    │         │    │    └─ database name
         │    │         │    └────── port (default 3306)
         │    │         └─────────── host
         │    └───────────────────── password
         └────────────────────────── username

Common options:
  parseTime=true              required for time.Time scanning
  charset=utf8mb4             full Unicode support
  tls=true                    enable TLS (use "skip-verify" to skip cert check)
  timeout=10s                 connection timeout
```

---

### 3 — PostgreSQL

**Step 1** — Update `database_url` in `config.json`:
```json
"database_url": "postgres://dbuser:dbpass@127.0.0.1:5432/mydb?sslmode=disable"
```

**Step 2** — Create `cmd/server/drivers.go`:
```go
package main

import _ "github.com/lib/pq"
```

**Step 3** — Fetch the driver:
```bash
go get github.com/lib/pq
go mod tidy
```

**Step 4** — Create the database and user in PostgreSQL:
```sql
CREATE DATABASE mydb;
CREATE USER dbuser WITH ENCRYPTED PASSWORD 'dbpass';
GRANT ALL PRIVILEGES ON DATABASE mydb TO dbuser;
```

**Step 5** — Update the `id` columns in `internal/db/db.go` → `migrate()`.  
Change `INTEGER NOT NULL` to `SERIAL` or `BIGSERIAL` for auto-increment:
```sql
-- users
id  SERIAL NOT NULL,

-- app_logs
id  SERIAL NOT NULL,
```

Also change `?` placeholders to `$1, $2, ...` (PostgreSQL syntax) or use
`github.com/jmoiron/sqlx` which handles this automatically.

**Full PostgreSQL DSN reference:**
```
postgres://user:pass@host:port/dbname?option=value
              │    │    │    │    │
              │    │    │    │    └─ database name
              │    │    │    └────── port (default 5432)
              │    │    └─────────── host
              │    └──────────────── password
              └───────────────────── username

Common sslmode values:
  sslmode=disable      no SSL (local dev only)
  sslmode=require      SSL required (no cert verification)
  sslmode=verify-full  SSL with full certificate verification (production)

Other options:
  connect_timeout=10   connection timeout in seconds
  application_name=goapp  identify app in pg_stat_activity
```

---

## Adding a New Page — Step by Step

### Step 1 — Choose a layout

Declare the layout in your template's very first line using a Go comment:

```html
{{/* layout: base_public.html */}}
```

If you omit this line, `base.html` (sidebar layout) is used automatically.

**Built-in layouts:**

| Layout file | Navigation | Best for |
|---|---|---|
| `base.html` | Left sidebar | Authenticated app pages (dashboard, profile, etc.) |
| `base_public.html` | Top bar | Public/marketing pages, landing pages |
| `base_bare.html` | None | Minimal pages, print view, embeds |

**Custom layout:** Create `web/templates/layouts/my_layout.html`, then declare `{{/* layout: my_layout.html */}}` in your page. Any layout filename works as long as it lives in the `layouts/` directory and contains `{{define "base"}} ... {{end}}`.

### Step 2 — Create the template

`web/templates/pages/mypage.html`:
```html
{{/* layout: base.html */}}
{{template "base" .}}

{{define "title"}}My Page — GoApp{{end}}

{{define "content"}}
<div class="max-w-4xl mx-auto">
    <h2 class="text-2xl font-semibold text-white mb-6">{{.Title}}</h2>

    {{range .Items}}
    <div class="card">
        <p class="text-gray-300">{{.}}</p>
    </div>
    {{end}}
</div>
{{end}}

{{/* Optional: page-specific <head> additions */}}
{{define "head"}}<style>/* page CSS */</style>{{end}}

{{/* Optional: page-specific scripts */}}
{{define "scripts"}}<script>/* page JS */</script>{{end}}
```

The `{{/* layout: ... */}}` comment is read only by Go at startup — it never appears in the HTML output.

### Step 3 — Create the handler

`internal/handlers/mypage.go`:
```go
package handlers

import "net/http"

// MyPageData holds everything the template needs.
// Always embed PageData — it carries User, Nav, flash messages, etc.
type MyPageData struct {
    PageData
    Items []string // your page-specific data
}

type MyPageHandler struct {
    tmpl *Renderer
    // Add other dependencies here: *db.DB, *mailer.Mailer, *logger.Logger
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
        Items:    []string{"hello", "world"},
    }
    h.tmpl.Render(w, "mypage", data)
}
```

### Step 4 — Register the route

Add one line to `internal/router/router.go`:

```go
// Public page (no login required):
mux.Handle("/mypage", handlers.NewMyPageHandler(renderer))

// Authenticated page (redirects to /login if not signed in):
mux.Handle("/mypage", middleware.RequireAuth(handlers.NewMyPageHandler(renderer)))

// Admin-only page:
mux.Handle("/mypage", adminMW(handlers.NewMyPageHandler(renderer)))
```

### Step 5 — (Optional) Add to sidebar navigation

In `internal/handlers/renderer.go`, append to `DefaultNav`:
```go
var DefaultNav = []NavItem{
    // existing items ...
    {Label: "My Page", Href: "/mypage", Icon: "info"},              // all users
    {Label: "Admin Page", Href: "/mypage", Icon: "shield", AdminOnly: true}, // admins only
}
```

Available icon names: `home`, `info`, `mail`, `users`, `activity`, `settings`, `logout`, `shield`, `key`, `mfa`

---

## Email — Using the Mailer

### Configure in `data/config.json`

```json
"email": {
    "enabled":      true,
    "smtp_host":    "smtp.gmail.com",
    "smtp_port":    587,
    "encryption":   "starttls",
    "auth":         true,
    "username":     "you@gmail.com",
    "password":     "your-app-password",
    "from_address": "GoApp <you@gmail.com>"
}
```

**Gmail tip:** Create an [App Password](https://myaccount.google.com/apppasswords) (not your main password). Requires 2FA enabled on your Google account.

### Wire the Mailer into a handler

```go
// In router.go (m is already created from cfg.Email):
mux.Handle("/notify", handlers.NewNotifyHandler(renderer, m, log))

// In your handler:
type NotifyHandler struct {
    tmpl   *Renderer
    mailer *mailer.Mailer
    log    *logger.Logger
}
func NewNotifyHandler(r *Renderer, m *mailer.Mailer, l *logger.Logger) *NotifyHandler {
    return &NotifyHandler{tmpl: r, mailer: m, log: l}
}
```

### Send plain-text email

```go
err := h.mailer.Send(mailer.Message{
    To:      []string{"user@example.com"},
    Subject: "Welcome to GoApp",
    Body:    "Hello! Your account is ready.",
})
if err != nil {
    h.log.Warn("send welcome email", "err", err)
    // Don't abort — email failure should not break the UX
}
```

### Send HTML email

```go
err := h.mailer.Send(mailer.Message{
    To:      []string{"user@example.com"},
    Subject: "Welcome to GoApp",
    Body:    "<h1>Welcome!</h1><p>Your account is <strong>ready</strong>.</p>",
    IsHTML:  true,
})
```

### Multiple recipients + CC

```go
err := h.mailer.Send(mailer.Message{
    To:      []string{"alice@example.com", "bob@example.com"},
    CC:      []string{"manager@example.com"},
    Subject: "Team notification",
    Body:    "Something happened that you should know about.",
})
```

### Safe error handling pattern

When `email.enabled` is `false`, `Send()` returns `nil` immediately — the rest of your handler works normally. Always log email errors rather than aborting the request:

```go
if err := h.mailer.Send(msg); err != nil {
    h.log.Warn("email send failed", "err", err)
    // continue — don't return an error page to the user
}
```

---

## CLI Emergency Commands

These run without a server restart and exit immediately after:

```bash
# Disable MFA for a locked-out admin:
go run ./cmd/server -mfaoff admin

# Reset an admin account password (also invalidates all their sessions):
go run ./cmd/server -pwreset admin -newpwd "NewSecurePassword1!"
```

These flags only work on accounts with the `admin` role as a safety guard.

---

## CSS Component Reference

All Tailwind utilities are available. These extra component classes are defined in `web/static/css/app.css`:

| Class | Description |
|---|---|
| `.card` | Dark card panel with hover highlight |
| `.btn-primary` | Accent-coloured action button |
| `.btn-ghost` | Transparent bordered button |
| `.input-field` | Dark text input / select / textarea |
| `.field-label` | Monospace uppercase label above inputs |
| `.badge` + modifier | Inline status label — add `.badge-admin`, `.badge-user`, `.badge-active`, `.badge-inactive` |
| `.flash-success` / `.flash-error` | Alert banners (auto-rendered by base layout from `?msg=` / `?err=` query params) |
| `.nav-link` / `.nav-link--active` | Sidebar navigation links |
| `.pub-nav-link` / `.pub-nav-link--active` | Top-bar links (public layout) |
| `.level-badge` + `.level-error` / `.level-warn` / `.level-info` / `.level-debug` | Log level indicator badges |

### Flash messages via redirect

Any page can display a success or error banner simply by appending to the redirect URL. The base layout picks them up automatically:

```go
// Success (green banner):
http.Redirect(w, r, "/dashboard?msg=Settings+saved.", http.StatusSeeOther)

// Error (red banner):
http.Redirect(w, r, "/profile?err=Password+mismatch.", http.StatusSeeOther)
```

---

## Template FuncMap Reference

Functions available in all templates:

| Function | Usage | Example |
|---|---|---|
| `inc` / `dec` | Increment/decrement int | `{{inc .Page}}` |
| `add` / `sub` | Add/subtract ints | `{{add .Page 2}}` |
| `upper` / `lower` | String case | `{{.Name \| upper}}` |
| `contains` | String contains | `{{if contains .Path "/admin"}}` |
| `hasPrefix` | String prefix check | `{{if hasPrefix .Path "/admin"}}` |
| `substr` | Substring (start, end) | `{{substr .Username 0 1 \| upper}}` |
| `safeHTML` | Mark string as safe HTML | `{{.Content \| safeHTML}}` |
| `jsStr` | JSON-encode for JS embedding | `var x = {{.Field \| jsStr}};` |
| `navIcon` | Inline SVG icon | `{{navIcon "home"}}` |
| `seq` | Generate 1..n slice | `{{range seq 5}}` |
| `levelClass` | Log level CSS class | `{{levelClass .Level}}` |

---

## Architecture Overview

```
HTTP Request
  │
  ├─ DomainGuard      — block wrong Host header (config: web_domain)
  ├─ Auth             — inject *db.User into context from session cookie
  ├─ Logger           — log request with real IP (config: reverse_proxies)
  ├─ SecureHeaders    — set CSP, X-Frame-Options, etc.
  ├─ Recovery         — catch panics → render 500 error page
  │
  └─ ServeMux
       ├─ /static/*            → FileServer
       ├─ /                    → HomeHandler
       ├─ /login               → LoginHandler (rate-limited, MFA-aware)
       ├─ /login/mfa           → MFAChallengeHandler
       ├─ /register            → RegisterHandler (disabled when allow_registration=false)
       ├─ /dashboard           → DashboardHandler [RequireAuth]
       ├─ /profile             → ProfileHandler  [RequireAuth]
       ├─ /profile/mfa         → MFASetupHandler [RequireAuth]
       ├─ /admin/*             → Admin handlers  [RequireAuth + RequireAdmin]
       └─ unknown routes       → ErrorHandler.NotFound (styled 404 page)
```

---

## Security Checklist for New Pages

- [ ] Check `r.Method` — return 405 for wrong methods
- [ ] For `/` only — check `r.URL.Path != "/"` → return 404
- [ ] Wrap with `middleware.RequireAuth` or `adminMW` if login is required
- [ ] `http.MaxBytesReader(w, r.Body, 1<<20)` before `r.ParseForm()` on every POST
- [ ] Trim all form inputs with `strings.TrimSpace()` and validate server-side
- [ ] Use PRG pattern on POST: `http.Redirect(w, r, "/path?msg=...", http.StatusSeeOther)`
- [ ] Use `?` placeholder parameters — never interpolate user input into SQL strings
- [ ] Email errors: log them but don't return an error page to the user

---

## Project Structure

```
goapp/
├── go.mod                            ← modernc.org/sqlite (only external dep)
├── README-modular.md                 ← this file
├── cmd/
│   └── server/
│       ├── main.go                   ← startup, CLI flags, background jobs
│       └── drivers.go                ← add MySQL/PostgreSQL driver imports here
├── data/                             ← created at runtime
│   ├── config.json                   ← all app settings (auto-created)
│   └── app.db                        ← SQLite database (auto-created)
├── internal/
│   ├── auth/                         ← PBKDF2, CSRF, TOTP MFA, rate limiter
│   ├── config/                       ← config.json load/save with defaults
│   ├── db/                           ← database/sql wrapper, migrations, models
│   ├── handlers/
│   │   ├── renderer.go               ← template engine with layout comment system
│   │   ├── auth.go                   ← login, register, logout, profile, password
│   │   ├── mfa.go                    ← TOTP setup, MFA challenge
│   │   ├── pages.go                  ← home, about, contact (with mailer), dashboard
│   │   ├── admin.go                  ← user management, log viewer
│   │   └── errors.go                 ← styled 404/403/500 pages
│   ├── logger/                       ← leveled logger writing to DB + stdout
│   ├── mailer/                       ← SMTP email (none/STARTTLS/SSL, stdlib only)
│   ├── middleware/                   ← auth, domain guard, real-IP, security headers
│   └── router/                       ← all route registrations
└── web/
    ├── templates/
    │   ├── layouts/
    │   │   ├── base.html             ← sidebar layout (default)
    │   │   ├── base_public.html      ← top-nav layout
    │   │   └── base_bare.html        ← minimal layout (no navigation)
    │   └── pages/                    ← one .html file per page
    └── static/
        ├── css/app.css               ← component classes (card, btn-*, etc.)
        └── js/app.js                 ← sidebar toggle, flash auto-dismiss
```
