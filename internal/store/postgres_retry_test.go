// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

// These tests exercise NewPostgresStoreWithRetry's failure/timeout paths against
// an unreachable address, so they need no PostgreSQL and run in the fast suite.
// The success path is covered by the integration tests (postgres_test.go).
package store

import (
	"context"
	"testing"
	"time"
)

// unreachableDSN points at a closed port so every connection attempt is refused
// immediately — letting us measure the retry/backoff loop without a real DB.
const unreachableDSN = "postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=1"

func TestNewPostgresStoreWithRetry_FailFast(t *testing.T) {
	start := time.Now()
	s, err := NewPostgresStoreWithRetry(context.Background(), unreachableDSN, 0)
	if err == nil {
		s.Close()
		t.Fatal("expected error against unreachable DSN, got nil")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("fail-fast took %s; expected a single attempt", elapsed)
	}
}

func TestNewPostgresStoreWithRetry_TimesOut(t *testing.T) {
	const timeout = 600 * time.Millisecond
	start := time.Now()
	s, err := NewPostgresStoreWithRetry(context.Background(), unreachableDSN, timeout)
	elapsed := time.Since(start)
	if err == nil {
		s.Close()
		t.Fatal("expected error against unreachable DSN, got nil")
	}
	// It must have actually waited (retried) rather than returning instantly...
	if elapsed < timeout/2 {
		t.Errorf("returned after %s; expected to retry until ~%s", elapsed, timeout)
	}
	// ...but must respect the deadline (one backoff of slack).
	if elapsed > timeout+6*time.Second {
		t.Errorf("returned after %s; expected to stop near %s", elapsed, timeout)
	}
}

func TestNewPostgresStoreWithRetry_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s, err := NewPostgresStoreWithRetry(ctx, unreachableDSN, 30*time.Second)
	if err == nil {
		s.Close()
		t.Fatal("expected error when context is cancelled, got nil")
	}
}

func TestNewPostgresStoreWithRetry_BadDSN(t *testing.T) {
	// A malformed DSN can never become reachable, so it must fail fast even with
	// a long timeout rather than retrying for the whole window.
	start := time.Now()
	s, err := NewPostgresStoreWithRetry(context.Background(), "://not a dsn", 30*time.Second)
	if err == nil {
		s.Close()
		t.Fatal("expected error for malformed DSN, got nil")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("malformed DSN took %s; expected fail-fast (no retry loop)", elapsed)
	}
}
