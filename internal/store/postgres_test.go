// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

//go:build integration

package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func newTestPostgresStore(t *testing.T) *PostgresStore {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	// Clean tables before each test for isolation.
	if _, err := s.pool.Exec(ctx, "DELETE FROM users"); err != nil {
		t.Fatalf("truncate users: %v", err)
	}
	if _, err := s.pool.Exec(ctx, "DELETE FROM audit_log"); err != nil {
		t.Fatalf("truncate audit_log: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestPostgresStore_Contract(t *testing.T) {
	testUserStoreContract(t, func() UserStore { return newTestPostgresStore(t) })
}

func TestPostgresStore_AuditContract(t *testing.T) {
	testAuditStoreContract(t, func() AuditStore { return newTestPostgresStore(t) })
}

// TestPostgresStore_NilIssuedAtExpires simulates an in-place upgrade
// row: non-null onboard_token, NULL token_issued_at. Consume must fail
// closed with ErrTokenExpired once a positive TTL is configured.
func TestPostgresStore_NilIssuedAtExpires(t *testing.T) {
	s := newTestPostgresStore(t)
	ctx := context.Background()
	if err := s.CreateUser(ctx, &User{Username: "legacy"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE users SET onboard_token = $1, token_issued_at = NULL, updated_at = $2 WHERE username = $3`,
		"tok-nil-issued", time.Now().UTC(), "legacy",
	); err != nil {
		t.Fatal(err)
	}

	s.SetTokenTTL(time.Hour)
	if _, err := s.ConsumeOnboardToken(ctx, "tok-nil-issued"); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired for NULL issued_at, got %v", err)
	}
	if err := s.SetOnboardToken(ctx, "legacy", "tok-nil-issued"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeOnboardToken(ctx, "tok-nil-issued"); err != nil {
		t.Fatalf("expected re-issued token to consume, got %v", err)
	}
}

func TestPostgresStore_SchemaCreated(t *testing.T) {
	s := newTestPostgresStore(t)
	ctx := context.Background()

	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_name = 'users'
		)`).Scan(&exists)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("expected users table to exist")
	}
}
