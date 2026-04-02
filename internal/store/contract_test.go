package store

import (
	"context"
	"errors"
	"testing"
)

// testUserStoreContract exercises the full UserStore contract.
// Both memory and postgres implementations must pass these tests.
func testUserStoreContract(t *testing.T, newStore func() UserStore) {
	t.Helper()

	t.Run("CreateAndList", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		u := &User{Username: "alice"}
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if u.ID == "" {
			t.Fatal("expected ID to be set")
		}
		if !u.Enabled {
			t.Fatal("expected Enabled to be true")
		}
		if u.CreatedAt.IsZero() {
			t.Fatal("expected CreatedAt to be set")
		}
		if u.UpdatedAt.IsZero() {
			t.Fatal("expected UpdatedAt to be set")
		}

		users, err := s.ListUsers(ctx)
		if err != nil {
			t.Fatalf("ListUsers: %v", err)
		}
		if len(users) != 1 {
			t.Fatalf("got %d users, want 1", len(users))
		}
		if users[0].Username != "alice" {
			t.Errorf("username = %q, want %q", users[0].Username, "alice")
		}
		if users[0].ID != u.ID {
			t.Errorf("ID = %q, want %q", users[0].ID, u.ID)
		}
	})

	t.Run("DuplicateUsername", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		if err := s.CreateUser(ctx, &User{Username: "bob"}); err != nil {
			t.Fatal(err)
		}
		err := s.CreateUser(ctx, &User{Username: "bob"})
		if !errors.Is(err, ErrUsernameExists) {
			t.Fatalf("got %v, want ErrUsernameExists", err)
		}
	})

	t.Run("EmptyUsername", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		err := s.CreateUser(ctx, &User{Username: ""})
		if !errors.Is(err, ErrUsernameRequired) {
			t.Fatalf("got %v, want ErrUsernameRequired", err)
		}
	})

	t.Run("GetUserByUsername_Found", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		created := &User{Username: "getme"}
		if err := s.CreateUser(ctx, created); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetUserByUsername(ctx, "getme")
		if err != nil {
			t.Fatalf("GetUserByUsername: %v", err)
		}
		if got.ID != created.ID {
			t.Errorf("ID = %q, want %q", got.ID, created.ID)
		}
		if got.Username != "getme" {
			t.Errorf("Username = %q, want %q", got.Username, "getme")
		}
		if !got.Enabled {
			t.Error("expected Enabled to be true")
		}
	})

	t.Run("GetUserByUsername_NotFound", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		_, err := s.GetUserByUsername(ctx, "nobody")
		if !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("got %v, want ErrUserNotFound", err)
		}
	})

	t.Run("ListEmpty", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		users, err := s.ListUsers(ctx)
		if err != nil {
			t.Fatalf("ListUsers: %v", err)
		}
		if users == nil {
			t.Fatal("expected non-nil empty slice")
		}
		if len(users) != 0 {
			t.Fatalf("got %d users, want 0", len(users))
		}
	})
}
