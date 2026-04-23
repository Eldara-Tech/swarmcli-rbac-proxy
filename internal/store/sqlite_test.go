// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := NewSQLiteStore(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSQLiteStore_Contract(t *testing.T) {
	testUserStoreContract(t, func() UserStore { return newTestSQLiteStore(t) })
}

func TestSQLiteStore_AuditContract(t *testing.T) {
	testAuditStoreContract(t, func() AuditStore { return newTestSQLiteStore(t) })
}

// TestSQLiteStore_NilIssuedAtExpires simulates an in-place upgrade where
// a pre-TTL row carries a non-null onboard_token but NULL issued_at. It
// must fail to consume with ErrTokenExpired once a positive TTL is set.
func TestSQLiteStore_NilIssuedAtExpires(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()
	if err := s.CreateUser(ctx, &User{Username: "legacy"}); err != nil {
		t.Fatal(err)
	}
	// Write the pre-TTL shape directly: token set, issued_at NULL.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE users SET onboard_token = ?, token_issued_at = NULL, updated_at = ? WHERE username = ?`,
		"tok-nil-issued", time.Now().UTC().Format(time.RFC3339Nano), "legacy",
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

func TestSQLiteStore_WALEnabled(t *testing.T) {
	s := newTestSQLiteStore(t)
	var mode string
	err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want %q", mode, "wal")
	}
}
