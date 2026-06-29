// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"encoding/json"
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

const pgRBACSchema = `CREATE TABLE IF NOT EXISTS roles (
    id         UUID PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    rules      JSONB NOT NULL DEFAULT '[]',
    builtin    BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS role_bindings (
    id         UUID PRIMARY KEY,
    username   TEXT NOT NULL,
    role_name  TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(username, role_name)
);
CREATE INDEX IF NOT EXISTS idx_role_bindings_username ON role_bindings(username);`

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
	if _, err := pool.Exec(ctx, pgRBACSchema); err != nil {
		pool.Close()
		lPostgres().Errorw("rbac schema failed", "error", err)
		return nil, err
	}
	lPostgres().Infow("store initialized")
	return &PostgresStore{pool: pool}, nil
}

// NewPostgresStoreWithRetry calls NewPostgresStore, retrying with exponential
// backoff (500ms → capped at 5s) until it succeeds or `timeout` elapses. It
// exists so the long-lived proxy survives a not-yet-ready database on a Swarm
// stack deploy (proxy and postgres start together) instead of crash-looping.
// timeout <= 0 means fail-fast — a single attempt, used by the CLI / migrate
// paths where an interactive operator prefers a crisp error.
func NewPostgresStoreWithRetry(ctx context.Context, connString string, timeout time.Duration) (*PostgresStore, error) {
	if timeout <= 0 {
		return NewPostgresStore(ctx, connString)
	}
	deadline := time.Now().Add(timeout)
	const maxBackoff = 5 * time.Second
	backoff := 500 * time.Millisecond
	for attempt := 1; ; attempt++ {
		s, err := NewPostgresStore(ctx, connString)
		if err == nil {
			return s, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, err
		}
		wait := backoff
		if wait > remaining {
			wait = remaining
		}
		lPostgres().Warnw("waiting for postgres", "attempt", attempt, "retry_in", wait, "error", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		if backoff < maxBackoff {
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
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
	// Missing issued_at is treated as expired; only rows written before
	// this release carry NULL, and they must be re-issued via
	// `swcproxy user regenerate-token`.
	if ttl := s.getTokenTTL(); ttl > 0 {
		if issuedAt == nil || time.Since(*issuedAt) > ttl {
			return nil, ErrTokenExpired
		}
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

func (s *PostgresStore) CreateRole(ctx context.Context, r *Role) error {
	if r.Name == "" {
		return ErrRoleNameRequired
	}
	id, err := newUUID()
	if err != nil {
		return err
	}
	rulesJSON, err := json.Marshal(r.Rules)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = s.pool.Exec(ctx,
		`INSERT INTO roles (id, name, rules, builtin, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $5)`,
		id, r.Name, string(rulesJSON), r.Builtin, now,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrRoleExists
		}
		return err
	}
	r.ID = id
	r.CreatedAt = now
	r.UpdatedAt = now
	return nil
}

func pgScanRole(scan func(...any) error) (*Role, error) {
	var r Role
	var rulesJSON []byte
	if err := scan(&r.ID, &r.Name, &rulesJSON, &r.Builtin, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(rulesJSON, &r.Rules); err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *PostgresStore) GetRole(ctx context.Context, name string) (*Role, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, name, rules, builtin, created_at, updated_at FROM roles WHERE name = $1`, name)
	r, err := pgScanRole(row.Scan)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return r, nil
}

func (s *PostgresStore) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, rules, builtin, created_at, updated_at FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]Role, 0)
	for rows.Next() {
		r, err := pgScanRole(rows.Scan)
		if err != nil {
			return nil, err
		}
		roles = append(roles, *r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return roles, nil
}

func (s *PostgresStore) UpdateRole(ctx context.Context, r *Role) error {
	rulesJSON, err := json.Marshal(r.Rules)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	tag, err := s.pool.Exec(ctx,
		`UPDATE roles SET rules = $1, updated_at = $2 WHERE name = $3`,
		string(rulesJSON), now, r.Name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrRoleNotFound
	}
	r.UpdatedAt = now
	return nil
}

func (s *PostgresStore) DeleteRole(ctx context.Context, name string) error {
	existing, err := s.GetRole(ctx, name)
	if err != nil {
		return err
	}
	if existing.Builtin {
		return ErrRoleBuiltin
	}
	var count int
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM role_bindings WHERE role_name = $1`, name).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return ErrRoleInUse
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM roles WHERE name = $1`, name)
	return err
}

func (s *PostgresStore) CreateBinding(ctx context.Context, b *RoleBinding) error {
	if _, err := s.GetRole(ctx, b.RoleName); err != nil {
		return err // ErrRoleNotFound if absent
	}
	id, err := newUUID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = s.pool.Exec(ctx,
		`INSERT INTO role_bindings (id, username, role_name, created_at) VALUES ($1, $2, $3, $4)`,
		id, b.Username, b.RoleName, now)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrBindingExists
		}
		return err
	}
	b.ID = id
	b.CreatedAt = now
	return nil
}

func (s *PostgresStore) listBindingsWhere(ctx context.Context, where string, args ...any) ([]RoleBinding, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, role_name, created_at FROM role_bindings `+where+` ORDER BY created_at`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	bindings := make([]RoleBinding, 0)
	for rows.Next() {
		var b RoleBinding
		if err := rows.Scan(&b.ID, &b.Username, &b.RoleName, &b.CreatedAt); err != nil {
			return nil, err
		}
		bindings = append(bindings, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return bindings, nil
}

func (s *PostgresStore) ListBindings(ctx context.Context) ([]RoleBinding, error) {
	return s.listBindingsWhere(ctx, "")
}

func (s *PostgresStore) ListBindingsForUser(ctx context.Context, username string) ([]RoleBinding, error) {
	return s.listBindingsWhere(ctx, "WHERE username = $1", username)
}

func (s *PostgresStore) DeleteBinding(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM role_bindings WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrBindingNotFound
	}
	return nil
}

func (s *PostgresStore) Export(ctx context.Context) (BackupData, error) {
	users, err := s.exportUsers(ctx)
	if err != nil {
		return BackupData{}, err
	}
	audit, err := s.exportAuditEntries(ctx)
	if err != nil {
		return BackupData{}, err
	}
	roles, err := s.ListRoles(ctx)
	if err != nil {
		return BackupData{}, err
	}
	bindings, err := s.ListBindings(ctx)
	if err != nil {
		return BackupData{}, err
	}
	return BackupData{Users: users, Audit: audit, Roles: roles, Bindings: bindings}, nil
}

func (s *PostgresStore) exportUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, role, enabled, created_at, updated_at,
		        onboard_token, token_issued_at, token_consumed_at
		 FROM users ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		var u User
		var token *string
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.Enabled, &u.CreatedAt, &u.UpdatedAt,
			&token, &u.TokenIssuedAt, &u.TokenConsumedAt); err != nil {
			return nil, err
		}
		if token != nil {
			u.OnboardToken = *token
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (s *PostgresStore) exportAuditEntries(ctx context.Context) ([]AuditEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, timestamp, actor, action, resource, status, detail, source_ip
		 FROM audit_log ORDER BY timestamp, id`)
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

func (s *PostgresStore) Restore(ctx context.Context, data BackupData, replace bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if replace {
		// Bindings reference roles/users by name; clear dependents first.
		for _, q := range []string{
			`DELETE FROM role_bindings`,
			`DELETE FROM roles`,
			`DELETE FROM audit_log`,
			`DELETE FROM users`,
		} {
			if _, err := tx.Exec(ctx, q); err != nil {
				return err
			}
		}
	}

	for i := range data.Users {
		u := &data.Users[i]
		if _, err := tx.Exec(ctx,
			`INSERT INTO users (id, username, role, enabled, created_at, updated_at,
			                    onboard_token, token_issued_at, token_consumed_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			u.ID, u.Username, u.Role, u.Enabled, u.CreatedAt, u.UpdatedAt,
			pgNullStr(u.OnboardToken), u.TokenIssuedAt, u.TokenConsumedAt,
		); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrUsernameExists
			}
			return err
		}
	}
	for i := range data.Audit {
		e := &data.Audit[i]
		if _, err := tx.Exec(ctx,
			`INSERT INTO audit_log (id, timestamp, actor, action, resource, status, detail, source_ip)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			e.ID, e.Timestamp, e.Actor, string(e.Action),
			e.Resource, e.Status, e.Detail, e.SourceIP,
		); err != nil {
			return err
		}
	}
	for i := range data.Roles {
		r := &data.Roles[i]
		rulesJSON, err := json.Marshal(r.Rules)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO roles (id, name, rules, builtin, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			r.ID, r.Name, string(rulesJSON), r.Builtin, r.CreatedAt, r.UpdatedAt,
		); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrRoleExists
			}
			return err
		}
	}
	for i := range data.Bindings {
		b := &data.Bindings[i]
		if _, err := tx.Exec(ctx,
			`INSERT INTO role_bindings (id, username, role_name, created_at) VALUES ($1, $2, $3, $4)`,
			b.ID, b.Username, b.RoleName, b.CreatedAt,
		); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrBindingExists
			}
			return err
		}
	}
	return tx.Commit(ctx)
}

// pgNullStr maps an empty string to a SQL NULL.
func pgNullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Ensure interface compliance.
var _ UserStore = (*PostgresStore)(nil)
var _ AuditStore = (*PostgresStore)(nil)
var _ RBACStore = (*PostgresStore)(nil)
var _ BackupStore = (*PostgresStore)(nil)
