// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"database/sql"
	"encoding/json"
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

const sqliteRBACSchema = `CREATE TABLE IF NOT EXISTS roles (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    rules      TEXT NOT NULL DEFAULT '[]',
    builtin    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS role_bindings (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    role_name  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(username, role_name)
);
CREATE INDEX IF NOT EXISTS idx_role_bindings_username ON role_bindings(username);`

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
	if _, err := db.ExecContext(ctx, sqliteRBACSchema); err != nil {
		_ = db.Close()
		lSqlite().Errorw("rbac schema failed", "error", err)
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

func (s *SQLiteStore) SetUserEnabled(ctx context.Context, username string, enabled bool) error {
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET enabled = ?, updated_at = ? WHERE username = ?`,
		enabledInt, now, username,
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

func (s *SQLiteStore) SetUserRole(ctx context.Context, username string, role string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET role = ?, updated_at = ? WHERE username = ?`,
		role, now, username,
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

func (s *SQLiteStore) CreateRole(ctx context.Context, r *Role) error {
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
	builtin := 0
	if r.Builtin {
		builtin = 1
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO roles (id, name, rules, builtin, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, r.Name, string(rulesJSON), builtin,
		now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
	)
	if err != nil {
		if isSQLiteUniqueViolation(err) {
			return ErrRoleExists
		}
		return err
	}
	r.ID = id
	r.CreatedAt = now
	r.UpdatedAt = now
	return nil
}

func scanRole(scan func(...any) error) (*Role, error) {
	var r Role
	var rulesJSON string
	var builtin int
	var createdAt, updatedAt string
	if err := scan(&r.ID, &r.Name, &rulesJSON, &builtin, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(rulesJSON), &r.Rules); err != nil {
		return nil, err
	}
	r.Builtin = builtin != 0
	var err error
	if r.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt); err != nil {
		return nil, err
	}
	if r.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *SQLiteStore) GetRole(ctx context.Context, name string) (*Role, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, rules, builtin, created_at, updated_at FROM roles WHERE name = ?`, name)
	r, err := scanRole(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return r, nil
}

func (s *SQLiteStore) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, rules, builtin, created_at, updated_at FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	roles := make([]Role, 0)
	for rows.Next() {
		r, err := scanRole(rows.Scan)
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

func (s *SQLiteStore) UpdateRole(ctx context.Context, r *Role) error {
	rulesJSON, err := json.Marshal(r.Rules)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE roles SET rules = ?, updated_at = ? WHERE name = ?`,
		string(rulesJSON), now.Format(time.RFC3339Nano), r.Name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrRoleNotFound
	}
	r.UpdatedAt = now
	return nil
}

func (s *SQLiteStore) DeleteRole(ctx context.Context, name string) error {
	existing, err := s.GetRole(ctx, name)
	if err != nil {
		return err
	}
	if existing.Builtin {
		return ErrRoleBuiltin
	}
	var count int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM role_bindings WHERE role_name = ?`, name).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return ErrRoleInUse
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM roles WHERE name = ?`, name)
	return err
}

func (s *SQLiteStore) CreateBinding(ctx context.Context, b *RoleBinding) error {
	if _, err := s.GetRole(ctx, b.RoleName); err != nil {
		return err // ErrRoleNotFound if absent
	}
	id, err := newUUID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO role_bindings (id, username, role_name, created_at) VALUES (?, ?, ?, ?)`,
		id, b.Username, b.RoleName, now.Format(time.RFC3339Nano))
	if err != nil {
		if isSQLiteUniqueViolation(err) {
			return ErrBindingExists
		}
		return err
	}
	b.ID = id
	b.CreatedAt = now
	return nil
}

func scanBinding(scan func(...any) error) (*RoleBinding, error) {
	var b RoleBinding
	var createdAt string
	if err := scan(&b.ID, &b.Username, &b.RoleName, &createdAt); err != nil {
		return nil, err
	}
	var err error
	if b.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt); err != nil {
		return nil, err
	}
	return &b, nil
}

func (s *SQLiteStore) listBindingsWhere(ctx context.Context, where string, args ...any) ([]RoleBinding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, username, role_name, created_at FROM role_bindings `+where+` ORDER BY created_at`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	bindings := make([]RoleBinding, 0)
	for rows.Next() {
		b, err := scanBinding(rows.Scan)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, *b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return bindings, nil
}

func (s *SQLiteStore) ListBindings(ctx context.Context) ([]RoleBinding, error) {
	return s.listBindingsWhere(ctx, "")
}

func (s *SQLiteStore) ListBindingsForUser(ctx context.Context, username string) ([]RoleBinding, error) {
	return s.listBindingsWhere(ctx, "WHERE username = ?", username)
}

func (s *SQLiteStore) DeleteBinding(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM role_bindings WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrBindingNotFound
	}
	return nil
}

func (s *SQLiteStore) Export(ctx context.Context) (BackupData, error) {
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

func (s *SQLiteStore) exportUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, username, role, enabled, created_at, updated_at,
		        onboard_token, token_issued_at, token_consumed_at
		 FROM users ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	users := make([]User, 0)
	for rows.Next() {
		var u User
		var enabled int
		var createdAt, updatedAt string
		var token, issuedAt, consumedAt sql.NullString
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &enabled, &createdAt, &updatedAt,
			&token, &issuedAt, &consumedAt); err != nil {
			return nil, err
		}
		u.Enabled = enabled != 0
		if u.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt); err != nil {
			return nil, err
		}
		if u.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt); err != nil {
			return nil, err
		}
		if token.Valid {
			u.OnboardToken = token.String
		}
		if u.TokenIssuedAt, err = parseNullTime(issuedAt); err != nil {
			return nil, err
		}
		if u.TokenConsumedAt, err = parseNullTime(consumedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (s *SQLiteStore) exportAuditEntries(ctx context.Context) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, timestamp, actor, action, resource, status, detail, source_ip
		 FROM audit_log ORDER BY timestamp, id`)
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
		if e.Timestamp, err = time.Parse(time.RFC3339Nano, ts); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *SQLiteStore) Restore(ctx context.Context, data BackupData, replace bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if replace {
		// Bindings reference roles/users by name; clear dependents first.
		for _, q := range []string{
			`DELETE FROM role_bindings`,
			`DELETE FROM roles`,
			`DELETE FROM audit_log`,
			`DELETE FROM users`,
		} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
	}

	for i := range data.Users {
		u := &data.Users[i]
		enabled := 0
		if u.Enabled {
			enabled = 1
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO users (id, username, role, enabled, created_at, updated_at,
			                    onboard_token, token_issued_at, token_consumed_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			u.ID, u.Username, u.Role, enabled,
			u.CreatedAt.UTC().Format(time.RFC3339Nano), u.UpdatedAt.UTC().Format(time.RFC3339Nano),
			nullStr(u.OnboardToken), nullTime(u.TokenIssuedAt), nullTime(u.TokenConsumedAt),
		); err != nil {
			if isSQLiteUniqueViolation(err) {
				return ErrUsernameExists
			}
			return err
		}
	}
	for i := range data.Audit {
		e := &data.Audit[i]
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO audit_log (id, timestamp, actor, action, resource, status, detail, source_ip)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			e.ID, e.Timestamp.UTC().Format(time.RFC3339Nano), e.Actor, string(e.Action),
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
		builtin := 0
		if r.Builtin {
			builtin = 1
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO roles (id, name, rules, builtin, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			r.ID, r.Name, string(rulesJSON), builtin,
			r.CreatedAt.UTC().Format(time.RFC3339Nano), r.UpdatedAt.UTC().Format(time.RFC3339Nano),
		); err != nil {
			if isSQLiteUniqueViolation(err) {
				return ErrRoleExists
			}
			return err
		}
	}
	for i := range data.Bindings {
		b := &data.Bindings[i]
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO role_bindings (id, username, role_name, created_at) VALUES (?, ?, ?, ?)`,
			b.ID, b.Username, b.RoleName, b.CreatedAt.UTC().Format(time.RFC3339Nano),
		); err != nil {
			if isSQLiteUniqueViolation(err) {
				return ErrBindingExists
			}
			return err
		}
	}
	return tx.Commit()
}

// parseNullTime parses a nullable RFC3339Nano timestamp column.
func parseNullTime(v sql.NullString) (*time.Time, error) {
	if !v.Valid {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// nullStr maps an empty string to a SQL NULL.
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullTime maps a nil time pointer to a SQL NULL, else an RFC3339Nano string.
func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// Ensure interface compliance.
var _ UserStore = (*SQLiteStore)(nil)
var _ AuditStore = (*SQLiteStore)(nil)
var _ RBACStore = (*SQLiteStore)(nil)
var _ BackupStore = (*SQLiteStore)(nil)
