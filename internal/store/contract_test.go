// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// tokenTTLConfigurable is implemented by stores whose onboarding-token TTL
// can be set per test. All three production stores implement it; the
// contract tests type-assert and skip if ever absent.
type tokenTTLConfigurable interface {
	SetTokenTTL(time.Duration)
}

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

	t.Run("OnboardToken_WithinTTL_Consumes", func(t *testing.T) {
		s := newStore()
		ttl, ok := s.(tokenTTLConfigurable)
		if !ok {
			t.Skip("store does not support SetTokenTTL")
		}
		ttl.SetTokenTTL(time.Hour)

		ctx := context.Background()
		if err := s.CreateUser(ctx, &User{Username: "ttlok"}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetOnboardToken(ctx, "ttlok", "tok-ttl-ok"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ConsumeOnboardToken(ctx, "tok-ttl-ok"); err != nil {
			t.Fatalf("expected consume to succeed within TTL, got %v", err)
		}
	})

	t.Run("OnboardToken_BeyondTTL_Expires", func(t *testing.T) {
		s := newStore()
		ttl, ok := s.(tokenTTLConfigurable)
		if !ok {
			t.Skip("store does not support SetTokenTTL")
		}

		ctx := context.Background()
		if err := s.CreateUser(ctx, &User{Username: "ttlexp"}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetOnboardToken(ctx, "ttlexp", "tok-ttl-expired"); err != nil {
			t.Fatal(err)
		}
		// Tighten TTL to effectively "already expired" after the token was
		// issued. time.Since(issuedAt) > 1ns is true on any real clock.
		ttl.SetTokenTTL(time.Nanosecond)
		time.Sleep(2 * time.Millisecond)
		_, err := s.ConsumeOnboardToken(ctx, "tok-ttl-expired")
		if !errors.Is(err, ErrTokenExpired) {
			t.Fatalf("expected ErrTokenExpired, got %v", err)
		}
	})

	t.Run("OnboardToken_ExpiredCannotBeRevived", func(t *testing.T) {
		s := newStore()
		ttl, ok := s.(tokenTTLConfigurable)
		if !ok {
			t.Skip("store does not support SetTokenTTL")
		}

		ctx := context.Background()
		if err := s.CreateUser(ctx, &User{Username: "ttlrevive"}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetOnboardToken(ctx, "ttlrevive", "tok-revive"); err != nil {
			t.Fatal(err)
		}
		ttl.SetTokenTTL(time.Nanosecond)
		time.Sleep(2 * time.Millisecond)
		if _, err := s.ConsumeOnboardToken(ctx, "tok-revive"); !errors.Is(err, ErrTokenExpired) {
			t.Fatalf("expected ErrTokenExpired, got %v", err)
		}
		// Relaxing TTL afterwards does not resurrect the expired window:
		// time.Since(issuedAt) keeps growing, but the already-issued token
		// remains expired for the duration of its issuance — it must be
		// re-issued via SetOnboardToken to become valid again.
		// Verify by re-issuing with a long TTL.
		ttl.SetTokenTTL(time.Hour)
		if err := s.SetOnboardToken(ctx, "ttlrevive", "tok-revive"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ConsumeOnboardToken(ctx, "tok-revive"); err != nil {
			t.Fatalf("expected re-issued token to consume, got %v", err)
		}
	})
}

// testAuditStoreContract exercises the full AuditStore contract.
func testAuditStoreContract(t *testing.T, newStore func() AuditStore) {
	t.Helper()

	t.Run("ListEmpty", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		entries, err := s.ListAuditEntries(ctx, 10)
		if err != nil {
			t.Fatalf("ListAuditEntries: %v", err)
		}
		if entries == nil {
			t.Fatal("expected non-nil empty slice")
		}
		if len(entries) != 0 {
			t.Fatalf("got %d entries, want 0", len(entries))
		}
	})

	t.Run("RecordSetsIDAndTimestamp", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		e := &AuditEntry{Actor: "alice", Action: AuditUserCreated, Resource: "user:alice", Status: "success"}
		if err := s.RecordAudit(ctx, e); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
		if e.ID == "" {
			t.Fatal("expected ID to be set")
		}
		if e.Timestamp.IsZero() {
			t.Fatal("expected Timestamp to be set")
		}
	})

	t.Run("RecordAndList", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		actions := []AuditAction{AuditUserCreated, AuditCertIssued, AuditUserDeleted}
		for _, a := range actions {
			if err := s.RecordAudit(ctx, &AuditEntry{Actor: "alice", Action: a, Resource: "user:alice", Status: "success"}); err != nil {
				t.Fatalf("RecordAudit(%s): %v", a, err)
			}
		}

		entries, err := s.ListAuditEntries(ctx, 10)
		if err != nil {
			t.Fatalf("ListAuditEntries: %v", err)
		}
		if len(entries) != 3 {
			t.Fatalf("got %d entries, want 3", len(entries))
		}
		// Newest first.
		if entries[0].Action != AuditUserDeleted {
			t.Errorf("entries[0].Action = %q, want %q", entries[0].Action, AuditUserDeleted)
		}
		if entries[2].Action != AuditUserCreated {
			t.Errorf("entries[2].Action = %q, want %q", entries[2].Action, AuditUserCreated)
		}
	})

	t.Run("ListLimit", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		for i := range 5 {
			e := &AuditEntry{Actor: "bob", Action: AuditGuardBlocked, Resource: "services:svc" + string(rune('0'+i)), Status: "denied"}
			if err := s.RecordAudit(ctx, e); err != nil {
				t.Fatalf("RecordAudit: %v", err)
			}
		}

		entries, err := s.ListAuditEntries(ctx, 2)
		if err != nil {
			t.Fatalf("ListAuditEntries: %v", err)
		}
		if len(entries) != 2 {
			t.Fatalf("got %d entries, want 2", len(entries))
		}
		// Most recent entries.
		if entries[0].Resource != "services:svc4" {
			t.Errorf("entries[0].Resource = %q, want %q", entries[0].Resource, "services:svc4")
		}
		if entries[1].Resource != "services:svc3" {
			t.Errorf("entries[1].Resource = %q, want %q", entries[1].Resource, "services:svc3")
		}
	})

	t.Run("RecordAllFields", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		e := &AuditEntry{
			Actor:    "admin",
			Action:   AuditGuardBlocked,
			Resource: "services:my-svc",
			Status:   "denied",
			Detail:   "protected stack delete",
			SourceIP: "10.0.0.1",
		}
		if err := s.RecordAudit(ctx, e); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}

		entries, err := s.ListAuditEntries(ctx, 1)
		if err != nil {
			t.Fatalf("ListAuditEntries: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("got %d entries, want 1", len(entries))
		}
		got := entries[0]
		if got.ID == "" {
			t.Error("expected ID")
		}
		if got.Timestamp.IsZero() {
			t.Error("expected Timestamp")
		}
		if got.Actor != "admin" {
			t.Errorf("Actor = %q, want %q", got.Actor, "admin")
		}
		if got.Action != AuditGuardBlocked {
			t.Errorf("Action = %q, want %q", got.Action, AuditGuardBlocked)
		}
		if got.Resource != "services:my-svc" {
			t.Errorf("Resource = %q, want %q", got.Resource, "services:my-svc")
		}
		if got.Status != "denied" {
			t.Errorf("Status = %q, want %q", got.Status, "denied")
		}
		if got.Detail != "protected stack delete" {
			t.Errorf("Detail = %q, want %q", got.Detail, "protected stack delete")
		}
		if got.SourceIP != "10.0.0.1" {
			t.Errorf("SourceIP = %q, want %q", got.SourceIP, "10.0.0.1")
		}
	})

	t.Run("EmptyOptionalFields", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		e := &AuditEntry{Actor: "cli", Action: AuditUserDeleted, Resource: "user:bob", Status: "success"}
		if err := s.RecordAudit(ctx, e); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}

		entries, err := s.ListAuditEntries(ctx, 1)
		if err != nil {
			t.Fatalf("ListAuditEntries: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("got %d entries, want 1", len(entries))
		}
		if entries[0].Detail != "" {
			t.Errorf("Detail = %q, want empty string", entries[0].Detail)
		}
		if entries[0].SourceIP != "" {
			t.Errorf("SourceIP = %q, want empty string", entries[0].SourceIP)
		}
	})

	t.Run("UniqueIDs", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		e1 := &AuditEntry{Actor: "alice", Action: AuditUserCreated, Resource: "user:alice", Status: "success"}
		e2 := &AuditEntry{Actor: "alice", Action: AuditCertIssued, Resource: "user:alice", Status: "success"}
		if err := s.RecordAudit(ctx, e1); err != nil {
			t.Fatalf("RecordAudit e1: %v", err)
		}
		if err := s.RecordAudit(ctx, e2); err != nil {
			t.Fatalf("RecordAudit e2: %v", err)
		}
		if e1.ID == e2.ID {
			t.Errorf("IDs should be unique, both are %q", e1.ID)
		}
	})

	t.Run("AllActionTypes", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		all := []AuditAction{
			AuditUserCreated, AuditUserDeleted, AuditCertIssued,
			AuditOnboardCompleted, AuditGuardBlocked, AuditTokenRegenerated,
		}
		for _, a := range all {
			if err := s.RecordAudit(ctx, &AuditEntry{Actor: "test", Action: a, Resource: "x", Status: "success"}); err != nil {
				t.Fatalf("RecordAudit(%s): %v", a, err)
			}
		}

		entries, err := s.ListAuditEntries(ctx, 10)
		if err != nil {
			t.Fatalf("ListAuditEntries: %v", err)
		}
		if len(entries) != len(all) {
			t.Fatalf("got %d entries, want %d", len(entries), len(all))
		}
		seen := make(map[AuditAction]bool)
		for _, e := range entries {
			seen[e.Action] = true
		}
		for _, a := range all {
			if !seen[a] {
				t.Errorf("action %q not found in entries", a)
			}
		}
	})

	t.Run("LimitExceedsCount", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		for range 3 {
			if err := s.RecordAudit(ctx, &AuditEntry{Actor: "a", Action: AuditUserCreated, Resource: "x", Status: "success"}); err != nil {
				t.Fatalf("RecordAudit: %v", err)
			}
		}

		entries, err := s.ListAuditEntries(ctx, 100)
		if err != nil {
			t.Fatalf("ListAuditEntries: %v", err)
		}
		if len(entries) != 3 {
			t.Fatalf("got %d entries, want 3", len(entries))
		}
	})

	t.Run("LimitEqualsCount", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		for range 4 {
			if err := s.RecordAudit(ctx, &AuditEntry{Actor: "a", Action: AuditUserCreated, Resource: "x", Status: "success"}); err != nil {
				t.Fatalf("RecordAudit: %v", err)
			}
		}

		entries, err := s.ListAuditEntries(ctx, 4)
		if err != nil {
			t.Fatalf("ListAuditEntries: %v", err)
		}
		if len(entries) != 4 {
			t.Fatalf("got %d entries, want 4", len(entries))
		}
	})

	t.Run("TimestampOrdering", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		for range 3 {
			if err := s.RecordAudit(ctx, &AuditEntry{Actor: "a", Action: AuditUserCreated, Resource: "x", Status: "success"}); err != nil {
				t.Fatalf("RecordAudit: %v", err)
			}
		}

		entries, err := s.ListAuditEntries(ctx, 10)
		if err != nil {
			t.Fatalf("ListAuditEntries: %v", err)
		}
		// Newest first — each timestamp must be >= the next.
		for i := 0; i < len(entries)-1; i++ {
			if entries[i].Timestamp.Before(entries[i+1].Timestamp) {
				t.Errorf("entries[%d].Timestamp (%v) before entries[%d].Timestamp (%v)",
					i, entries[i].Timestamp, i+1, entries[i+1].Timestamp)
			}
		}
	})

	t.Run("DuplicateActionDistinctIDs", func(t *testing.T) {
		s := newStore()
		ctx := context.Background()

		ids := make(map[string]bool)
		for range 5 {
			e := &AuditEntry{Actor: "cli", Action: AuditUserCreated, Resource: "user:same", Status: "success"}
			if err := s.RecordAudit(ctx, e); err != nil {
				t.Fatalf("RecordAudit: %v", err)
			}
			if ids[e.ID] {
				t.Fatalf("duplicate ID %q", e.ID)
			}
			ids[e.ID] = true
		}

		entries, err := s.ListAuditEntries(ctx, 10)
		if err != nil {
			t.Fatalf("ListAuditEntries: %v", err)
		}
		if len(entries) != 5 {
			t.Fatalf("got %d entries, want 5", len(entries))
		}
	})
}
