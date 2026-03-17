// Package logger provides a leveled, structured logger that writes to both
// stdout and the application database (visible to admins in the UI).
//
// Log levels (lowest → highest verbosity):
//
//	ERROR — always logged; unexpected failures
//	WARN  — always logged; recoverable issues, failed logins
//	INFO  — always logged; significant events (startup, login)
//	DEBUG — logged only when debug mode is enabled
package logger

import (
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"goapp/internal/db"
)

// Logger is a leveled logger backed by the application database.
type Logger struct {
	db    *db.DB
	debug atomic.Bool // whether DEBUG messages are persisted/printed
}

// New creates a Logger. Set debugOn=true to enable debug output.
func New(database *db.DB, debugOn bool) *Logger {
	l := &Logger{db: database}
	l.debug.Store(debugOn)
	return l
}

// SetDebug enables or disables debug-level logging at runtime.
func (l *Logger) SetDebug(on bool) { l.debug.Store(on) }

// DebugEnabled reports whether debug logging is active.
func (l *Logger) DebugEnabled() bool { return l.debug.Load() }

// Error logs an ERROR level entry.
func (l *Logger) Error(msg string, args ...any) {
	l.write(db.LevelError, msg, args...)
}

// Warn logs a WARN level entry.
func (l *Logger) Warn(msg string, args ...any) {
	l.write(db.LevelWarn, msg, args...)
}

// Info logs an INFO level entry.
func (l *Logger) Info(msg string, args ...any) {
	l.write(db.LevelInfo, msg, args...)
}

// Debug logs a DEBUG level entry (no-op when debug is disabled).
func (l *Logger) Debug(msg string, args ...any) {
	if !l.debug.Load() {
		return
	}
	l.write(db.LevelDebug, msg, args...)
}

func (l *Logger) write(level, msg string, args ...any) {
	// Build context string from key=value pairs
	ctx := ""
	if len(args) > 0 {
		ctx = formatKV(args)
	}

	// Stdout via stdlib log (always)
	prefix := levelPrefix(level)
	if ctx != "" {
		log.Printf("%s %s | %s", prefix, msg, ctx)
	} else {
		log.Printf("%s %s", prefix, msg)
	}

	// Persist to DB asynchronously so logging never blocks the request path
	go func() {
		if err := l.db.InsertLog(level, msg, ctx); err != nil {
			log.Printf("logger: db write failed: %v", err)
		}
	}()
}

func levelPrefix(level string) string {
	switch level {
	case db.LevelError:
		return "[ERROR]"
	case db.LevelWarn:
		return "[WARN ]"
	case db.LevelInfo:
		return "[INFO ]"
	default:
		return "[DEBUG]"
	}
}

// formatKV formats variadic key=value pairs into a single string.
// args should be alternating key, value, key, value...
func formatKV(args []any) string {
	if len(args) == 1 {
		return fmt.Sprintf("%v", args[0])
	}
	out := ""
	for i := 0; i+1 < len(args); i += 2 {
		if out != "" {
			out += " "
		}
		out += fmt.Sprintf("%v=%v", args[i], args[i+1])
	}
	// Odd trailing value
	if len(args)%2 != 0 {
		out += fmt.Sprintf(" %v", args[len(args)-1])
	}
	return out
}

// PruneJob runs a goroutine that periodically prunes old log entries.
func PruneJob(l *Logger, keepDays int) {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			n, err := l.db.PurgeLogs(keepDays)
			if err != nil {
				l.Error("log prune failed", "err", err)
			} else if n > 0 {
				l.Info("log prune completed", "deleted", n, "keep_days", keepDays)
			}
		}
	}()
}
