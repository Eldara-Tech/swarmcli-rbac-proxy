//go:build integration

package store

import (
	"context"
	"os"
	"testing"
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
	// Clean table before each test for isolation.
	if _, err := s.pool.Exec(ctx, "DELETE FROM users"); err != nil {
		t.Fatalf("truncate users: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestPostgresStore_Contract(t *testing.T) {
	testUserStoreContract(t, func() UserStore { return newTestPostgresStore(t) })
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
