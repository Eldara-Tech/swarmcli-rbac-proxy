// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"

	proxylog "swarm-rbac-proxy/internal/log"

	_ "modernc.org/sqlite"
)

func lSqlite() *proxylog.ProxyLogger { return proxylog.L().With("component", "store.sqlite") }

const sqliteSchema = `CREATE TABLE IF NOT EXISTS users (
    id                TEXT PRIMARY KEY,
    username          TEXT NOT NULL UNIQUE,
    role              TEXT NOT NULL DEFAULT 'user',
    enabled           INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    onboard_token     TEXT,
    token_issued_at   TEXT,
    token_consumed_at TEXT
);`

const sqliteAuditSchema = `CREATE TABLE IF NOT EXISTS audit_log (
    id        TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    resource  TEXT NOT NULL DEFAULT '',
    status    TEXT NOT NULL DEFAULT 'success',
    detail    TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT ''
);`

const sqliteAuditIndex = `CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);`

var sqliteMigrations = []string{
	`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`,
	`ALTER TABLE users ADD COLUMN onboard_token TEXT`,
	`ALTER TABLE users ADD COLUMN token_consumed_at TEXT`,
	`ALTER TABLE users ADD COLUMN token_issued_at TEXT`,
}

// SQLiteStore implements UserStore backed by SQLite.
type SQLiteStore struct {
	db       *sql.DB
	ttlMu    sync.RWMutex
	tokenTTL time.Duration // 0 means disabled
}

// SetTokenTTL sets the onboarding-token TTL. Zero or negative disables
// expiry. Safe to call concurrently.
func (s *SQLiteStore) SetTokenTTL(d time.Duration) {
	s.ttlMu.Lock()
	defer s.ttlMu.Unlock()
	s.tokenTTL = d
}

func (s *SQLiteStore) getTokenTTL() time.Duration {
	s.ttlMu.RLock()
	defer s.ttlMu.RUnlock()
	return s.tokenTTL
}

// NewSQLiteStore opens a SQLite database and ensures the schema exists.
func NewSQLiteStore(ctx context.Context, dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		lSqlite().Errorw("open failed", "dsn", dsn, "error", err)
		return nil, err
	}
	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		lSqlite().Errorw("WAL pragma failed", "error", err)
		return nil, err
	}
	if _, err := db.ExecContext(ctx, sqliteSchema); err != nil {
		_ = db.Close()
		lSqlite().Errorw("schema migration failed", "error", err)
		return nil, err
	}
	for _, m := range sqliteMigrations {
		if _, err := db.ExecContext(ctx, m); err != nil {
			// Ignore "duplicate column" errors from already-applied migrations.
			if !isSQLiteDuplicateColumn(err) {
				_ = db.Close()
				lSqlite().Errorw("migration failed", "error", err, "sql", m)
				return nil, err
			}
		}
	}
	if _, err := db.ExecContext(ctx, sqliteAuditSchema); err != nil {
		_ = db.Close()
		lSqlite().Errorw("audit schema failed", "error", err)
		return nil, err
	}
	if _, err := db.ExecContext(ctx, sqliteAuditIndex); err != nil {
		_ = db.Close()
		lSqlite().Errorw("audit index failed", "error", err)
		return nil, err
	}
	lSqlite().Infow("store initialized", "dsn", dsn)
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

	if u.Role == "" {
		u.Role = "user"
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, username, role, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, 1, ?, ?)`,
		id, u.Username, u.Role, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
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

func (s *SQLiteStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, role, enabled, created_at, updated_at FROM users WHERE username = ?`,
		username,
	)
	var u User
	var enabled int
	var createdAt, updatedAt string
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &enabled, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	u.Enabled = enabled != 0
	var err error
	u.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return nil, err
	}
	u.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *SQLiteStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, username, role, enabled, created_at, updated_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	users := make([]User, 0)
	for rows.Next() {
		var u User
		var enabled int
		var createdAt, updatedAt string
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &enabled, &createdAt, &updatedAt); err != nil {
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

func (s *SQLiteStore) DeleteUser(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE username = ?`, username)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *SQLiteStore) SetOnboardToken(ctx context.Context, username string, token string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET onboard_token = ?, token_issued_at = ?, token_consumed_at = NULL, updated_at = ? WHERE username = ?`,
		token, now, now, username,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *SQLiteStore) ConsumeOnboardToken(ctx context.Context, token string) (*User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx,
		`SELECT id, username, role, enabled, created_at, updated_at, token_issued_at, token_consumed_at
		 FROM users WHERE onboard_token = ?`, token,
	)
	var u User
	var enabled int
	var createdAt, updatedAt string
	var issuedAt, consumedAt sql.NullString
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &enabled, &createdAt, &updatedAt, &issuedAt, &consumedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}
	if consumedAt.Valid {
		return nil, ErrTokenConsumed
	}
	// TTL check: a NULL issued_at (rows written before this release) is
	// treated as expired and must be re-issued via
	// `swcproxy user regenerate-token`.
	if ttl := s.getTokenTTL(); ttl > 0 {
		if !issuedAt.Valid {
			return nil, ErrTokenExpired
		}
		t, perr := time.Parse(time.RFC3339Nano, issuedAt.String)
		if perr != nil || time.Since(t) > ttl {
			return nil, ErrTokenExpired
		}
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET token_consumed_at = ?, updated_at = ? WHERE id = ?`,
		nowStr, nowStr, u.ID,
	); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	u.Enabled = enabled != 0
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	u.UpdatedAt = now
	u.TokenConsumedAt = &now
	if issuedAt.Valid {
		if t, perr := time.Parse(time.RFC3339Nano, issuedAt.String); perr == nil {
			u.TokenIssuedAt = &t
		}
	}
	return &u, nil
}

// isSQLiteDuplicateColumn checks if the error is about a duplicate column (already-applied migration).
func isSQLiteDuplicateColumn(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column")
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

func (s *SQLiteStore) RecordAudit(ctx context.Context, e *AuditEntry) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	e.ID = id
	e.Timestamp = time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO audit_log (id, timestamp, actor, action, resource, status, detail, source_ip)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.Timestamp.Format(time.RFC3339Nano), e.Actor, string(e.Action),
		e.Resource, e.Status, e.Detail, e.SourceIP,
	)
	return err
}

func (s *SQLiteStore) ListAuditEntries(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, timestamp, actor, action, resource, status, detail, source_ip
		 FROM audit_log ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	entries := make([]AuditEntry, 0)
	for rows.Next() {
		var e AuditEntry
		var ts, action string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &action, &e.Resource, &e.Status, &e.Detail, &e.SourceIP); err != nil {
			return nil, err
		}
		e.Action = AuditAction(action)
		e.Timestamp, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// Ensure interface compliance.
var _ UserStore = (*SQLiteStore)(nil)
var _ AuditStore = (*SQLiteStore)(nil)
