// Package mailer provides email sending via SMTP using only the standard library.
//
// ─────────────────────────────────────────────────────────────────────────────
// Quick usage — 4 steps
// ─────────────────────────────────────────────────────────────────────────────
//
// Step 1 — Configure in data/config.json:
//
//	"email": {
//	  "enabled":      true,
//	  "smtp_host":    "smtp.gmail.com",
//	  "smtp_port":    587,
//	  "encryption":   "starttls",
//	  "auth":         true,
//	  "username":     "you@gmail.com",
//	  "password":     "your-app-password",
//	  "from_address": "GoApp <you@gmail.com>"
//	}
//
// Step 2 — Create the Mailer in main.go or router.go (cfg is *config.Config):
//
//	m := mailer.New(&cfg.Email)
//
// Step 3 — Inject into any handler that needs to send email:
//
//	type ContactHandler struct {
//	    tmpl   *handlers.Renderer
//	    mailer *mailer.Mailer
//	    log    *logger.Logger
//	}
//	func NewContactHandler(r *handlers.Renderer, m *mailer.Mailer, l *logger.Logger) *ContactHandler {
//	    return &ContactHandler{tmpl: r, mailer: m, log: l}
//	}
//
// Step 4 — Call Send inside your handler:
//
//	err := h.mailer.Send(mailer.Message{
//	    To:      []string{"admin@example.com"},
//	    Subject: "New contact form submission",
//	    Body:    "Name: Alice\nEmail: alice@example.com\nMessage: Hello!",
//	})
//	if err != nil {
//	    h.log.Error("contact: send email", "err", err)
//	    // do not abort the request — email failure should not break the UX
//	}
//
// Sending HTML email:
//
//	err := h.mailer.Send(mailer.Message{
//	    To:      []string{"user@example.com"},
//	    Subject: "Welcome to GoApp",
//	    Body:    "<h1>Welcome!</h1><p>Your account is ready.</p>",
//	    IsHTML:  true,
//	})
//
// Multiple recipients + CC:
//
//	err := h.mailer.Send(mailer.Message{
//	    To:      []string{"alice@example.com", "bob@example.com"},
//	    CC:      []string{"manager@example.com"},
//	    Subject: "Team notification",
//	    Body:    "Something happened.",
//	})
//
// Wire up in router.go — pass cfg.Email to New, pass Mailer to handlers:
//
//	m := mailer.New(&cfg.Email)
//	mux.Handle("/contact", handlers.NewContactHandler(renderer, m, log))
//
// ─────────────────────────────────────────────────────────────────────────────
// Encryption modes
// ─────────────────────────────────────────────────────────────────────────────
//
//	"none"     port 25  — plain SMTP, no TLS. Only for internal/trusted relays.
//	"ssl"      port 465 — implicit TLS from the start of the connection.
//	"starttls" port 587 — connects plain then upgrades via STARTTLS. Recommended.
package mailer

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"goapp/internal/config"
)

// Message is a single outbound email.
type Message struct {
	To      []string // recipient addresses (required)
	CC      []string // CC addresses (optional)
	Subject string   // subject line
	Body    string   // plain-text or HTML body
	IsHTML  bool     // set true to send text/html instead of text/plain
}

// Mailer sends email using config.EmailConfig settings.
// It is safe for concurrent use. When Enabled is false, Send is a no-op.
type Mailer struct {
	cfg *config.EmailConfig
}

// New creates a Mailer. cfg is the Email section of config.Config.
func New(cfg *config.EmailConfig) *Mailer {
	return &Mailer{cfg: cfg}
}

// Enabled reports whether email sending is configured and active.
func (m *Mailer) Enabled() bool {
	return m.cfg != nil && m.cfg.Enabled && m.cfg.SMTPHost != ""
}

// Send delivers msg via SMTP. Returns nil immediately when email is disabled.
func (m *Mailer) Send(msg Message) error {
	if !m.Enabled() {
		return nil // graceful no-op
	}
	if len(msg.To) == 0 {
		return fmt.Errorf("mailer: To field is empty")
	}

	raw, err := buildRaw(m.cfg.FromAddress, msg)
	if err != nil {
		return fmt.Errorf("mailer: build: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", m.cfg.SMTPHost, m.cfg.SMTPPort)

	switch strings.ToLower(m.cfg.Encryption) {
	case "ssl":
		return m.sendSSL(addr, msg.To, raw)
	default: // "starttls" or "none" — smtp.SendMail handles both
		return m.sendSMTP(addr, msg.To, raw)
	}
}

// sendSMTP covers both "none" (port 25) and "starttls" (port 587).
// smtp.SendMail upgrades to TLS automatically when the server advertises STARTTLS.
func (m *Mailer) sendSMTP(addr string, to []string, raw []byte) error {
	var auth smtp.Auth
	if m.cfg.Auth && m.cfg.Username != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.SMTPHost)
	}
	from := extractAddress(m.cfg.FromAddress)
	if err := smtp.SendMail(addr, auth, from, to, raw); err != nil {
		return fmt.Errorf("mailer: smtp: %w", err)
	}
	return nil
}

// sendSSL opens an implicit TLS connection (port 465) manually because
// Go's smtp package does not support implicit TLS natively.
func (m *Mailer) sendSSL(addr string, to []string, raw []byte) error {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 15 * time.Second},
		"tcp", addr,
		&tls.Config{ServerName: m.cfg.SMTPHost, MinVersion: tls.VersionTLS12},
	)
	if err != nil {
		return fmt.Errorf("mailer: ssl dial: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, m.cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("mailer: ssl client: %w", err)
	}
	defer client.Close()

	if m.cfg.Auth && m.cfg.Username != "" {
		a := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.SMTPHost)
		if err := client.Auth(a); err != nil {
			return fmt.Errorf("mailer: ssl auth: %w", err)
		}
	}

	from := extractAddress(m.cfg.FromAddress)
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("mailer: MAIL FROM: %w", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("mailer: RCPT TO %s: %w", rcpt, err)
		}
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("mailer: DATA: %w", err)
	}
	if _, err := wc.Write(raw); err != nil {
		return fmt.Errorf("mailer: write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("mailer: close: %w", err)
	}
	return client.Quit()
}

// ─────────────────────────────────────────────────────────────────────────────
// Message builder
// ─────────────────────────────────────────────────────────────────────────────

func buildRaw(from string, msg Message) ([]byte, error) {
	ct := "text/plain; charset=utf-8"
	if msg.IsHTML {
		ct = "text/html; charset=utf-8"
	}
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(msg.To, ", ") + "\r\n")
	if len(msg.CC) > 0 {
		b.WriteString("Cc: " + strings.Join(msg.CC, ", ") + "\r\n")
	}
	b.WriteString("Subject: " + noNewlines(msg.Subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: " + ct + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 +0000") + "\r\n")
	b.WriteString("\r\n")
	b.WriteString(msg.Body)
	return []byte(b.String()), nil
}

// noNewlines strips CR/LF from header values (header injection prevention).
func noNewlines(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// extractAddress strips the display name from "Display <addr@host>" format.
// smtp.Mail() needs just the bare address.
func extractAddress(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "<"); i >= 0 {
		s = s[i+1:]
		if j := strings.Index(s, ">"); j >= 0 {
			return strings.TrimSpace(s[:j])
		}
	}
	return s
}
