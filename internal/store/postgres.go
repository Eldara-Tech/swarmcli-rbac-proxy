// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"errors"
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
    token_consumed_at TIMESTAMPTZ
);`

var pgMigrations = []string{
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'`,
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS onboard_token TEXT`,
	`ALTER TABLE users ADD COLUMN IF NOT EXISTS token_consumed_at TIMESTAMPTZ`,
}

// PostgresStore implements UserStore backed by PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool
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
		`UPDATE users SET onboard_token = $1, token_consumed_at = NULL, updated_at = $2 WHERE username = $3`,
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
		`SELECT id, username, role, enabled, created_at, updated_at, token_consumed_at
		 FROM users WHERE onboard_token = $1`, token,
	)
	var u User
	var consumedAt *time.Time
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &u.Enabled, &u.CreatedAt, &u.UpdatedAt, &consumedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}
	if consumedAt != nil {
		return nil, ErrTokenConsumed
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
	return &u, nil
}

// Ensure interface compliance.
var _ UserStore = (*PostgresStore)(nil)
