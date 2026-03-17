// Package middleware provides HTTP middleware for the GoApp server.
package middleware

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"goapp/internal/config"
	"goapp/internal/db"
	"goapp/internal/logger"
)

// ─────────────────────────────────────────────────────────────────────────────
// Context keys
// ─────────────────────────────────────────────────────────────────────────────

type ctxKey int

const (
	ctxUser    ctxKey = iota
	ctxSession ctxKey = iota
)

func UserFromCtx(r *http.Request) *db.User {
	u, _ := r.Context().Value(ctxUser).(*db.User)
	return u
}

func SessionTokenFromCtx(r *http.Request) string {
	s, _ := r.Context().Value(ctxSession).(string)
	return s
}

// ─────────────────────────────────────────────────────────────────────────────
// Response writer wrapper
// ─────────────────────────────────────────────────────────────────────────────

type responseWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wrote {
		rw.status = code
		rw.wrote = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wrote {
		rw.status = http.StatusOK
		rw.wrote = true
	}
	return rw.ResponseWriter.Write(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// Security headers
// ─────────────────────────────────────────────────────────────────────────────

func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com 'unsafe-inline'; "+
				"style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"img-src 'self' data:; "+
				"connect-src 'self';",
		)
		next.ServeHTTP(w, r)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain guard
// ─────────────────────────────────────────────────────────────────────────────

// DomainGuard rejects requests whose Host header doesn't match cfg.WebDomain.
// When WebDomain is "*" all hosts are accepted (default).
func DomainGuard(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.WebDomain != "" && cfg.WebDomain != "*" {
				host := r.Host
				// Strip port if present
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				if !strings.EqualFold(host, cfg.WebDomain) {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Request logger
// ─────────────────────────────────────────────────────────────────────────────

func Logger(appLogger *logger.Logger, cfg *config.Config) func(http.Handler) http.Handler {
	trustedProxies := parseCIDRs(cfg.ReverseProxies)
	cachedTrustedProxies = trustedProxies // cache for RealIPFromRequest

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			duration := time.Since(start)

			// Resolve real client IP
			clientIP := realIP(r, trustedProxies)

			if strings.HasPrefix(r.URL.Path, "/static/") {
				appLogger.Debug("http", "method", r.Method, "path", r.URL.Path,
					"status", rw.status, "ip", clientIP, "dur", duration)
				return
			}
			appLogger.Debug("http", "method", r.Method, "path", r.URL.Path,
				"status", rw.status, "ip", clientIP, "dur", duration)
			log.Printf("%s %s %d %s %s", r.Method, r.URL.Path, rw.status, clientIP, duration)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Panic recovery
// ─────────────────────────────────────────────────────────────────────────────

func Recovery(appLogger *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					appLogger.Error("panic recovered", "err", err, "path", r.URL.Path)
					log.Printf("PANIC: %v\n%s", err, debug.Stack())
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Authentication middleware
// ─────────────────────────────────────────────────────────────────────────────

const sessionCookie = "session"

// Auth injects the authenticated user into the request context (if any).
func Auth(database *db.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(sessionCookie)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			sess, err := database.SessionByToken(cookie.Value)
			if err != nil {
				clearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			}
			user, err := database.UserByID(sess.UserID)
			if err != nil || !user.Active {
				clearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.WithValue(r.Context(), ctxUser, user)
			ctx = context.WithValue(ctx, ctxSession, sess.Token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuth redirects unauthenticated requests to /login.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UserFromCtx(r) == nil {
			http.Redirect(w, r, "/login?next="+r.URL.RequestURI(), http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin redirects non-admin users to a 403 error page.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := UserFromCtx(r)
		if u == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !u.IsAdmin() {
			http.Redirect(w, r, "/error/403", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Cookie helpers
// ─────────────────────────────────────────────────────────────────────────────

func SetSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   false, // enable when behind TLS in production
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain
// ─────────────────────────────────────────────────────────────────────────────

func Chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// ─────────────────────────────────────────────────────────────────────────────
// Real-IP extraction
// ─────────────────────────────────────────────────────────────────────────────

// RealIPFromRequest is the exported version used by handlers that need the
// client IP (e.g. the login handler for ban tracking). It reads the cached
// proxy list stored by the Logger middleware initialisation.
// Falls back to RemoteAddr if called before Logger is initialised.
var cachedTrustedProxies []*net.IPNet

// RealIPFromRequest returns the real client IP, handling reverse proxies.
func RealIPFromRequest(r *http.Request) string {
	return realIP(r, cachedTrustedProxies)
}

func realIP(r *http.Request, trustedProxies []*net.IPNet) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(remoteIP)

	// Only trust X-Forwarded-For if request came from a trusted proxy
	if ip != nil && isInCIDRs(ip, trustedProxies) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			// X-Forwarded-For may be a comma-separated list; take the first
			parts := strings.Split(fwd, ",")
			if first := strings.TrimSpace(parts[0]); first != "" {
				return first
			}
		}
		if real := r.Header.Get("X-Real-IP"); real != "" {
			return real
		}
	}
	return remoteIP
}

func parseCIDRs(addrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		// Try as plain IP first → add /32 or /128
		if ip := net.ParseIP(a); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			a = fmt.Sprintf("%s/%d", a, bits)
		}
		if _, ipnet, err := net.ParseCIDR(a); err == nil {
			nets = append(nets, ipnet)
		}
	}
	return nets
}

func isInCIDRs(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

