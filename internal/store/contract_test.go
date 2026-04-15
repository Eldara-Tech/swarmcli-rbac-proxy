// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

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
		if u.Role != "user" {
			t.Fatalf("expected default Role to be 'user', got %q", u.Role)
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
		if users[0].Role != "user" {
			t.Errorf("role = %q, want %q", users[0].Role, "user")
		}
	})

	t.Run("CreateWithRole", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		u := &User{Username: "admin1", Role: "admin"}
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if u.Role != "admin" {
			t.Fatalf("expected Role to be 'admin', got %q", u.Role)
		}
		got, err := s.GetUserByUsername(ctx, "admin1")
		if err != nil {
			t.Fatalf("GetUserByUsername: %v", err)
		}
		if got.Role != "admin" {
			t.Fatalf("expected stored Role to be 'admin', got %q", got.Role)
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

	t.Run("DeleteUser", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		if err := s.CreateUser(ctx, &User{Username: "todelete"}); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteUser(ctx, "todelete"); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		_, err := s.GetUserByUsername(ctx, "todelete")
		if !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("expected ErrUserNotFound after delete, got %v", err)
		}
	})

	t.Run("DeleteUser_NotFound", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		err := s.DeleteUser(ctx, "nobody")
		if !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("expected ErrUserNotFound, got %v", err)
		}
	})

	t.Run("OnboardToken_HappyPath", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		if err := s.CreateUser(ctx, &User{Username: "onboard1"}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetOnboardToken(ctx, "onboard1", "tok123"); err != nil {
			t.Fatalf("SetOnboardToken: %v", err)
		}
		u, err := s.ConsumeOnboardToken(ctx, "tok123")
		if err != nil {
			t.Fatalf("ConsumeOnboardToken: %v", err)
		}
		if u.Username != "onboard1" {
			t.Errorf("username = %q, want %q", u.Username, "onboard1")
		}
		if u.TokenConsumedAt == nil {
			t.Error("expected TokenConsumedAt to be set")
		}
	})

	t.Run("OnboardToken_DoubleConsume", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		if err := s.CreateUser(ctx, &User{Username: "onboard2"}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetOnboardToken(ctx, "onboard2", "tok456"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ConsumeOnboardToken(ctx, "tok456"); err != nil {
			t.Fatal(err)
		}
		_, err := s.ConsumeOnboardToken(ctx, "tok456")
		if !errors.Is(err, ErrTokenConsumed) {
			t.Fatalf("expected ErrTokenConsumed, got %v", err)
		}
	})

	t.Run("OnboardToken_NotFound", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		_, err := s.ConsumeOnboardToken(ctx, "nonexistent")
		if !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("expected ErrTokenNotFound, got %v", err)
		}
	})

	t.Run("OnboardToken_Regenerate", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		if err := s.CreateUser(ctx, &User{Username: "onboard3"}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetOnboardToken(ctx, "onboard3", "old-token"); err != nil {
			t.Fatal(err)
		}
		// Consume the old token.
		if _, err := s.ConsumeOnboardToken(ctx, "old-token"); err != nil {
			t.Fatal(err)
		}
		// Regenerate: new token should reset consumed state.
		if err := s.SetOnboardToken(ctx, "onboard3", "new-token"); err != nil {
			t.Fatal(err)
		}
		// Old token should no longer work.
		_, err := s.ConsumeOnboardToken(ctx, "old-token")
		if !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("expected ErrTokenNotFound for old token, got %v", err)
		}
		// New token should work.
		u, err := s.ConsumeOnboardToken(ctx, "new-token")
		if err != nil {
			t.Fatalf("ConsumeOnboardToken with new token: %v", err)
		}
		if u.Username != "onboard3" {
			t.Errorf("username = %q, want %q", u.Username, "onboard3")
		}
	})

	t.Run("SetOnboardToken_NotFound", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		err := s.SetOnboardToken(ctx, "nobody", "tok")
		if !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("expected ErrUserNotFound, got %v", err)
		}
	})
}
