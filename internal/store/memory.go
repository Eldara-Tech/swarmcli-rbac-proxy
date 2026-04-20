// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"sync"
	"time"

	proxylog "swarm-rbac-proxy/internal/log"
)

func lMemory() *proxylog.ProxyLogger { return proxylog.L().With("component", "store.memory") }

// MemoryStore is an in-memory UserStore and AuditStore for development and testing.
type MemoryStore struct {
	mu       sync.RWMutex
	users    map[string]User
	audit    []AuditEntry
	tokenTTL time.Duration // 0 means disabled
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	lMemory().Infow("store initialized")
	return &MemoryStore{users: make(map[string]User)}
}

// SetTokenTTL sets the onboarding-token TTL. A zero or negative duration
// disables expiry. Safe to call concurrently; applies to subsequent
// ConsumeOnboardToken calls.
func (s *MemoryStore) SetTokenTTL(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenTTL = d
}

func (s *MemoryStore) CreateUser(_ context.Context, u *User) error {
	if u.Username == "" {
		return ErrUsernameRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.users {
		if existing.Username == u.Username {
			return ErrUsernameExists
		}
	}

	id, err := newUUID()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	u.ID = id
	if u.Role == "" {
		u.Role = "user"
	}
	u.Enabled = true
	u.CreatedAt = now
	u.UpdatedAt = now

	s.users[id] = *u
	return nil
}

func (s *MemoryStore) DeleteUser(_ context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, u := range s.users {
		if u.Username == username {
			delete(s.users, id)
			return nil
		}
	}
	return ErrUserNotFound
}

func (s *MemoryStore) SetOnboardToken(_ context.Context, username string, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, u := range s.users {
		if u.Username == username {
			now := time.Now().UTC()
			u.OnboardToken = token
			u.TokenConsumedAt = nil
			issued := now
			u.TokenIssuedAt = &issued
			u.UpdatedAt = now
			s.users[id] = u
			return nil
		}
	}
	return ErrUserNotFound
}

func (s *MemoryStore) ConsumeOnboardToken(_ context.Context, token string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, u := range s.users {
		if u.OnboardToken == token {
			if u.TokenConsumedAt != nil {
				return nil, ErrTokenConsumed
			}
			// TTL check: tokens issued before this release (nil
			// TokenIssuedAt) are treated as never-expiring for a one-time
			// grace; new tokens always have TokenIssuedAt set.
			if s.tokenTTL > 0 && u.TokenIssuedAt != nil &&
				time.Since(*u.TokenIssuedAt) > s.tokenTTL {
				return nil, ErrTokenExpired
			}
			now := time.Now().UTC()
			u.TokenConsumedAt = &now
			u.UpdatedAt = now
			s.users[id] = u
			cp := u
			return &cp, nil
		}
	}
	return nil, ErrTokenNotFound
}

func (s *MemoryStore) GetUserByUsername(_ context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Username == username {
			cp := u
			return &cp, nil
		}
	}
	return nil, ErrUserNotFound
}

func (s *MemoryStore) ListUsers(_ context.Context) ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]User, 0, len(s.users))
	for _, u := range s.users {
		result = append(result, u)
	}
	return result, nil
}

func (s *MemoryStore) RecordAudit(_ context.Context, e *AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := newUUID()
	if err != nil {
		return err
	}
	e.ID = id
	e.Timestamp = time.Now().UTC()
	s.audit = append(s.audit, *e)
	return nil
}

func (s *MemoryStore) ListAuditEntries(_ context.Context, limit int) ([]AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := len(s.audit)
	if limit > 0 && limit < n {
		n = limit
	}
	result := make([]AuditEntry, n)
	for i := range n {
		result[i] = s.audit[len(s.audit)-1-i]
	}
	return result, nil
}

// Ensure interface compliance.
var _ AuditStore = (*MemoryStore)(nil)
