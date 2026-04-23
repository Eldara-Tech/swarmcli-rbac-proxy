// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	proxylog "swarm-rbac-proxy/internal/log"
)

func TestMain(m *testing.M) {
	proxylog.InitTestIfTestLogEnv()
	defer proxylog.Sync()
	os.Exit(m.Run())
}

func TestMemoryStore_Contract(t *testing.T) {
	testUserStoreContract(t, func() UserStore { return NewMemoryStore() })
}

func TestMemoryStore_AuditContract(t *testing.T) {
	testAuditStoreContract(t, func() AuditStore { return NewMemoryStore() })
}

// TestMemoryStore_NilIssuedAtExpires exercises the "rows written before
// TokenIssuedAt was introduced" path — a token whose issued_at is nil
// must not be consumable once a positive TTL is configured. Rows can
// only reach this state on an in-place upgrade; new code always stamps
// issued_at.
func TestMemoryStore_NilIssuedAtExpires(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if err := s.CreateUser(ctx, &User{Username: "legacy"}); err != nil {
		t.Fatal(err)
	}
	// Inject a pre-TTL row by bypassing SetOnboardToken.
	s.mu.Lock()
	for id, u := range s.users {
		if u.Username == "legacy" {
			u.OnboardToken = "tok-nil-issued"
			u.TokenIssuedAt = nil
			u.UpdatedAt = time.Now().UTC()
			s.users[id] = u
		}
	}
	s.mu.Unlock()

	s.SetTokenTTL(time.Hour)
	if _, err := s.ConsumeOnboardToken(ctx, "tok-nil-issued"); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired for nil issued_at, got %v", err)
	}
	// Regenerating the token via SetOnboardToken must set issued_at and
	// restore consumability.
	if err := s.SetOnboardToken(ctx, "legacy", "tok-nil-issued"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeOnboardToken(ctx, "tok-nil-issued"); err != nil {
		t.Fatalf("expected re-issued token to consume, got %v", err)
	}
}

func TestMemoryStore_ConcurrentCreates(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	n := 100

	var wg sync.WaitGroup
	errs := make(chan error, n)

	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := &User{Username: "user" + string(rune('A'+i%26)) + string(rune('0'+i/26))}
			if err := s.CreateUser(ctx, u); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent create error: %v", err)
	}

	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != n {
		t.Errorf("got %d users, want %d", len(users), n)
	}
}
