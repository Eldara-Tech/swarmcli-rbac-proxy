// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// TestLastAdminLockout_ConcurrentDemote verifies the last-admin guarantee holds
// under concurrency. With exactly two admins, two simultaneous demotions must
// not both succeed — that would race the admin count to zero. adminMu
// serializes the check-then-mutate in the *Checked helpers; without it this test
// observes zero surviving admins. Run with -race.
func TestLastAdminLockout_ConcurrentDemote(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	if err := SeedDefaultRoles(ctx, s); err != nil {
		t.Fatalf("seed roles: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		if _, err := CreateUserWithBinding(ctx, s, s, name, RoleAdmin); err != nil {
			t.Fatalf("seed admin %s: %v", name, err)
		}
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, name := range []string{"alice", "bob"} {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			errs[i] = SetUserRoleChecked(ctx, s, s, name, RoleViewer)
		}(i, name)
	}
	wg.Wait()

	admins, err := computeAdmins(ctx, s, s, nil, "")
	if err != nil {
		t.Fatalf("computeAdmins: %v", err)
	}
	if len(admins) == 0 {
		t.Fatalf("lockout breached: 0 admins remain after concurrent demotion (errs: %v)", errs)
	}
	// Exactly one demotion must have been refused as last-admin.
	refused := 0
	for _, e := range errs {
		if errors.Is(e, ErrLastAdmin) {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("want exactly 1 ErrLastAdmin refusal, got %d (errs: %v)", refused, errs)
	}
}
