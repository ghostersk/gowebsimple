package security

import (
	"net/http"
	"strings"
)

// Middleware returns an HTTP middleware that evaluates every request against
// the security engine. Blocked requests receive a 403 response rendered with
// the provided renderForbidden function (so it uses the app's base layout).
//
// Static assets (/static/, /favicon.*) are always passed through to avoid
// breaking CSS/JS on the block page itself.
//
// The realIPFn extracts the client IP from the request (handles proxies).
func Middleware(engine *Engine, realIPFn func(*http.Request) string, renderForbidden func(http.ResponseWriter, *http.Request, string)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Always pass static assets and favicon — block pages need CSS
			path := r.URL.Path
			if strings.HasPrefix(path, "/static/") ||
				path == "/favicon.ico" || path == "/favicon.png" {
				next.ServeHTTP(w, r)
				return
			}

			ip := realIPFn(r)
			dec, reason := engine.Evaluate(ip, path)
			if dec == DecisionBlock {
				renderForbidden(w, r, reason)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
