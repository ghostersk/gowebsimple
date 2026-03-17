package db

import (
	"fmt"
	"time"
)

// LogLevel constants.
const (
	LevelError = "ERROR"
	LevelWarn  = "WARN"
	LevelInfo  = "INFO"
	LevelDebug = "DEBUG"
)

// LogEntry represents one application log record.
type LogEntry struct {
	ID        int64
	Level     string
	Message   string
	Context   string
	CreatedAt time.Time
}

// InsertLog writes a new log entry to the database.
// created_at is supplied explicitly because the portable schema has no
// database-side DEFAULT (SQLite, MySQL, and PostgreSQL handle defaults
// differently; supplying it from Go is the safest cross-DB approach).
func (d *DB) InsertLog(level, message, context string) error {
	_, err := d.Exec(
		`INSERT INTO app_logs (level, message, context, created_at) VALUES (?,?,?,?)`,
		level, message, context, TimeStr(time.Now()),
	)
	return err
}

// LogFilter controls which log entries are returned.
type LogFilter struct {
	Level  string
	Search string
	Limit  int
	Offset int
}

// QueryLogs fetches log entries with optional filtering.
func (d *DB) QueryLogs(f LogFilter) ([]*LogEntry, error) {
	if f.Limit == 0 {
		f.Limit = 100
	}

	q := `SELECT id, level, message, context, created_at FROM app_logs WHERE 1=1`
	args := []any{}

	if f.Level != "" {
		q += ` AND level=?`
		args = append(args, f.Level)
	}
	if f.Search != "" {
		q += ` AND (message LIKE ? OR context LIKE ?)`
		like := "%" + f.Search + "%"
		args = append(args, like, like)
	}
	q += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	args = append(args, f.Limit, f.Offset)

	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("db: query logs: %w", err)
	}
	defer rows.Close()

	var entries []*LogEntry
	for rows.Next() {
		e := &LogEntry{}
		var createdStr string
		if err := rows.Scan(&e.ID, &e.Level, &e.Message, &e.Context, &createdStr); err != nil {
			return nil, err
		}
		e.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// CountLogs returns total matching log count (ignoring pagination).
func (d *DB) CountLogs(level, search string) (int, error) {
	q := `SELECT COUNT(*) FROM app_logs WHERE 1=1`
	args := []any{}
	if level != "" {
		q += ` AND level=?`
		args = append(args, level)
	}
	if search != "" {
		q += ` AND (message LIKE ? OR context LIKE ?)`
		like := "%" + search + "%"
		args = append(args, like, like)
	}
	var n int
	err := d.QueryRow(q, args...).Scan(&n)
	return n, err
}

// PurgeLogs deletes all logs older than days.
// The cutoff timestamp is computed in Go so the SQL is portable across
// SQLite, MySQL, and PostgreSQL (no database-side date arithmetic needed).
func (d *DB) PurgeLogs(days int) (int64, error) {
	cutoff := TimeStr(time.Now().AddDate(0, 0, -days))
	res, err := d.Exec(
		`DELETE FROM app_logs WHERE created_at < ?`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
