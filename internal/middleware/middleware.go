// Package middleware provides HTTP middleware for the GoApp server.
package middleware

import (
	"context"
	"log"
	"net/http"
	"runtime/debug"
	"time"

	"goapp/internal/db"
	"goapp/internal/logger"
)

// ─────────────────────────────────────────────────────────────────────────────
// Context key type
// ─────────────────────────────────────────────────────────────────────────────

type ctxKey int

const (
	ctxUser    ctxKey = iota // *db.User
	ctxSession ctxKey = iota // session token string
)

// UserFromCtx retrieves the authenticated user from the request context.
// Returns nil if the request is unauthenticated.
func UserFromCtx(r *http.Request) *db.User {
	u, _ := r.Context().Value(ctxUser).(*db.User)
	return u
}

// SessionTokenFromCtx retrieves the session token from the request context.
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

// SecureHeaders adds recommended security headers to every response.
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; "+
				"style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "+
				"font-src 'self' https://fonts.gstatic.com; "+
				"img-src 'self' data:; "+
				"connect-src 'self';",
		)
		next.ServeHTTP(w, r)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Request logger
// ─────────────────────────────────────────────────────────────────────────────

// Logger logs each request with method, path, status, and duration.
func Logger(appLogger *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			duration := time.Since(start)

			// Static assets — debug only
			if len(r.URL.Path) > 8 && r.URL.Path[:8] == "/static/" {
				appLogger.Debug("http", "method", r.Method, "path", r.URL.Path, "status", rw.status, "dur", duration)
				return
			}

			appLogger.Debug("http", "method", r.Method, "path", r.URL.Path, "status", rw.status, "dur", duration)
			log.Printf("%s %s %d %s", r.Method, r.URL.Path, rw.status, duration)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Panic recovery
// ─────────────────────────────────────────────────────────────────────────────

// Recovery catches panics and returns a 500.
func Recovery(appLogger *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					stack := string(debug.Stack())
					appLogger.Error("panic recovered", "err", err, "path", r.URL.Path)
					log.Printf("PANIC: %v\n%s", err, stack)
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
// It does NOT redirect — use RequireAuth or RequireAdmin for that.
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
				// Invalid/expired session — clear the cookie
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

			// Attach user and token to context
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

// RequireAdmin redirects non-admin users to /dashboard.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := UserFromCtx(r)
		if u == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !u.IsAdmin() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Cookie helpers
// ─────────────────────────────────────────────────────────────────────────────

// SetSessionCookie writes the session cookie to the response.
func SetSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   false, // set to true behind HTTPS in production
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie expires the session cookie.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain helper
// ─────────────────────────────────────────────────────────────────────────────

// Chain applies middleware in order (first listed = outermost).
func Chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}
