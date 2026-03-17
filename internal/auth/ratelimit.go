package auth

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimiter is a token-bucket rate limiter keyed by IP address.
// Used to prevent brute-force login attacks.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    int           // max attempts per window
	window  time.Duration // rolling window
}

type bucket struct {
	count     int
	resetAt   time.Time
}

// NewRateLimiter creates a limiter allowing rate attempts per window per IP.
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		window:  window,
	}
	// Background cleanup goroutine
	go rl.cleanup()
	return rl
}

// Allow reports whether the request's IP is under the rate limit.
func (rl *RateLimiter) Allow(r *http.Request) bool {
	ip := clientIP(r)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[ip]
	now := time.Now()

	if !ok || now.After(b.resetAt) {
		rl.buckets[ip] = &bucket{count: 1, resetAt: now.Add(rl.window)}
		return true
	}

	b.count++
	return b.count <= rl.rate
}

// Reset clears the rate limit for an IP (call after successful login).
func (rl *RateLimiter) Reset(r *http.Request) {
	ip := clientIP(r)
	rl.mu.Lock()
	delete(rl.buckets, ip)
	rl.mu.Unlock()
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		rl.mu.Lock()
		for ip, b := range rl.buckets {
			if now.After(b.resetAt) {
				delete(rl.buckets, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP extracts the real client IP, respecting X-Forwarded-For if trusted.
func clientIP(r *http.Request) string {
	// In a real deployment behind a trusted proxy you'd parse X-Forwarded-For.
	// For safety we default to RemoteAddr here.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
