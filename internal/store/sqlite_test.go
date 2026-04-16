// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"path/filepath"
	"testing"
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
