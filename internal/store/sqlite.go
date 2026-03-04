package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteSchema = `CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL UNIQUE,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);`

// SQLiteStore implements UserStore backed by SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens a SQLite database and ensures the schema exists.
func NewSQLiteStore(ctx context.Context, dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, sqliteSchema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

// Close closes the database.
func (s *SQLiteStore) Close() {
	_ = s.db.Close()
}

func (s *SQLiteStore) CreateUser(ctx context.Context, u *User) error {
	if u.Username == "" {
		return ErrUsernameRequired
	}

	id, err := newUUID()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, username, enabled, created_at, updated_at)
		 VALUES (?, ?, 1, ?, ?)`,
		id, u.Username, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
	)
	if err != nil {
		if isSQLiteUniqueViolation(err) {
			return ErrUsernameExists
		}
		return err
	}

	u.ID = id
	u.Enabled = true
	u.CreatedAt = now
	u.UpdatedAt = now
	return nil
}

func (s *SQLiteStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, username, enabled, created_at, updated_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	users := make([]User, 0)
	for rows.Next() {
		var u User
		var enabled int
		var createdAt, updatedAt string
		if err := rows.Scan(&u.ID, &u.Username, &enabled, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		u.Enabled = enabled != 0
		u.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, err
		}
		u.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// isSQLiteUniqueViolation checks for SQLITE_CONSTRAINT_UNIQUE (code 2067).
func isSQLiteUniqueViolation(err error) bool {
	// modernc.org/sqlite returns errors that embed the extended error code
	// in the format "UNIQUE constraint failed: ...". Check via string match
	// as the library's error type varies across versions.
	var sqlErr interface{ Code() int }
	if errors.As(err, &sqlErr) {
		return sqlErr.Code() == 2067
	}
	return false
}

// Ensure interface compliance.
var _ UserStore = (*SQLiteStore)(nil)
