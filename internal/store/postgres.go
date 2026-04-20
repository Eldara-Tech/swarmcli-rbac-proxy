// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"errors"
	"sync"
	"time"

	proxylog "swarm-rbac-proxy/internal/log"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func lPostgres() *proxylog.ProxyLogger { return proxylog.L().With("component", "store.postgres") }

const schema = `CREATE TABLE IF NOT EXISTS users (
    id                UUID PRIMARY KEY,
    username          TEXT NOT NULL UNIQUE,
    role              TEXT NOT NULL DEFAULT 'user',
    enabled           BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    onboard_token     TEXT,
    token_issued_at   TIMESTAMPTZ,
    token_consumed_at TIMESTAMPTZ
);`

const pgAuditSchema = `CREATE TABLE IF NOT EXISTS audit_log (
    id        UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    resource  TEXT NOT NULL DEFAULT '',
    status    TEXT NOT NULL DEFAULT 'success',
    detail    TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT ''
);`

const pgAuditIndex = `CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);`

var pgMigrations = []string{
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'`,
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS onboard_token TEXT`,
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS token_consumed_at TIMESTAMPTZ`,
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS token_issued_at TIMESTAMPTZ`,
}

// PostgresStore implements UserStore backed by PostgreSQL.
type PostgresStore struct {
	pool     *pgxpool.Pool
	ttlMu    sync.RWMutex
	tokenTTL time.Duration // 0 means disabled
}

// SetTokenTTL sets the onboarding-token TTL. Zero or negative disables
// expiry. Safe to call concurrently.
func (s *PostgresStore) SetTokenTTL(d time.Duration) {
	s.ttlMu.Lock()
	defer s.ttlMu.Unlock()
	s.tokenTTL = d
}

func (s *PostgresStore) getTokenTTL() time.Duration {
	s.ttlMu.RLock()
	defer s.ttlMu.RUnlock()
	return s.tokenTTL
}

// NewPostgresStore connects to PostgreSQL and ensures the schema exists.
func NewPostgresStore(ctx context.Context, connString string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		lPostgres().Errorw("connect failed", "error", err)
		return nil, err
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		lPostgres().Errorw("schema migration failed", "error", err)
		return nil, err
	}
	for _, m := range pgMigrations {
		if _, err := pool.Exec(ctx, m); err != nil {
			pool.Close()
			lPostgres().Errorw("migration failed", "error", err, "sql", m)
			return nil, err
		}
	}
	if _, err := pool.Exec(ctx, pgAuditSchema); err != nil {
		pool.Close()
		lPostgres().Errorw("audit schema failed", "error", err)
		return nil, err
	}
	if _, err := pool.Exec(ctx, pgAuditIndex); err != nil {
		pool.Close()
		lPostgres().Errorw("audit index failed", "error", err)
		return nil, err
	}
	lPostgres().Infow("store initialized")
	return &PostgresStore{pool: pool}, nil
}

// Close releases the connection pool.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

func (s *PostgresStore) CreateUser(ctx context.Context, u *User) error {
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
	_, err = s.pool.Exec(ctx,
		`INSERT INTO users (id, username, role, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, true, $4, $5)`,
		id, u.Username, u.Role, now, now,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
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

func (s *PostgresStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, username, role, enabled, created_at, updated_at FROM users WHERE username = $1`,
		username,
	)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &u.Enabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &u, nil
}

func (s *PostgresStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, role, enabled, created_at, updated_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.Enabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (s *PostgresStore) DeleteUser(ctx context.Context, username string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE username = $1`, username)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *PostgresStore) SetOnboardToken(ctx context.Context, username string, token string) error {
	now := time.Now().UTC()
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET onboard_token = $1, token_issued_at = $2, token_consumed_at = NULL, updated_at = $2 WHERE username = $3`,
		token, now, username,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *PostgresStore) ConsumeOnboardToken(ctx context.Context, token string) (*User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx,
		`SELECT id, username, role, enabled, created_at, updated_at, token_issued_at, token_consumed_at
		 FROM users WHERE onboard_token = $1 FOR UPDATE`, token,
	)
	var u User
	var issuedAt, consumedAt *time.Time
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &u.Enabled, &u.CreatedAt, &u.UpdatedAt, &issuedAt, &consumedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}
	if consumedAt != nil {
		return nil, ErrTokenConsumed
	}
	if ttl := s.getTokenTTL(); ttl > 0 && issuedAt != nil && time.Since(*issuedAt) > ttl {
		return nil, ErrTokenExpired
	}

	now := time.Now().UTC()
	if _, err := tx.Exec(ctx,
		`UPDATE users SET token_consumed_at = $1, updated_at = $1 WHERE id = $2`,
		now, u.ID,
	); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	u.UpdatedAt = now
	u.TokenConsumedAt = &now
	u.TokenIssuedAt = issuedAt
	return &u, nil
}

func (s *PostgresStore) RecordAudit(ctx context.Context, e *AuditEntry) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	e.ID = id
	e.Timestamp = time.Now().UTC()
	_, err = s.pool.Exec(ctx,
		`INSERT INTO audit_log (id, timestamp, actor, action, resource, status, detail, source_ip)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		e.ID, e.Timestamp, e.Actor, string(e.Action),
		e.Resource, e.Status, e.Detail, e.SourceIP,
	)
	return err
}

func (s *PostgresStore) ListAuditEntries(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, timestamp, actor, action, resource, status, detail, source_ip
		 FROM audit_log ORDER BY timestamp DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := make([]AuditEntry, 0)
	for rows.Next() {
		var e AuditEntry
		var action string
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Actor, &action, &e.Resource, &e.Status, &e.Detail, &e.SourceIP); err != nil {
			return nil, err
		}
		e.Action = AuditAction(action)
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// Ensure interface compliance.
var _ UserStore = (*PostgresStore)(nil)
var _ AuditStore = (*PostgresStore)(nil)
