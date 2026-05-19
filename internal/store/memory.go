// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"sort"
	"sync"
	"time"

	proxylog "swarm-rbac-proxy/internal/log"
)

func lMemory() *proxylog.ProxyLogger { return proxylog.L().With("component", "store.memory") }

// MemoryStore is an in-memory UserStore, AuditStore, and RBACStore for
// development and testing.
type MemoryStore struct {
	mu       sync.RWMutex
	users    map[string]User
	audit    []AuditEntry
	roles    map[string]Role        // keyed by name
	bindings map[string]RoleBinding // keyed by id
	tokenTTL time.Duration          // 0 means disabled
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	lMemory().Infow("store initialized")
	return &MemoryStore{
		users:    make(map[string]User),
		roles:    make(map[string]Role),
		bindings: make(map[string]RoleBinding),
	}
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
			// TTL check: a missing TokenIssuedAt is treated as expired —
			// only rows written before this release carry nil, and they
			// must be re-issued via `swcproxy user regenerate-token`.
			if s.tokenTTL > 0 {
				if u.TokenIssuedAt == nil || time.Since(*u.TokenIssuedAt) > s.tokenTTL {
					return nil, ErrTokenExpired
				}
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

func (s *MemoryStore) CreateRole(_ context.Context, r *Role) error {
	if r.Name == "" {
		return ErrRoleNameRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[r.Name]; ok {
		return ErrRoleExists
	}
	id, err := newUUID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	r.ID = id
	r.CreatedAt = now
	r.UpdatedAt = now
	s.roles[r.Name] = *r
	return nil
}

func (s *MemoryStore) GetRole(_ context.Context, name string) (*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[name]
	if !ok {
		return nil, ErrRoleNotFound
	}
	cp := r
	cp.Rules = append([]PermissionRule(nil), r.Rules...)
	return &cp, nil
}

func (s *MemoryStore) ListRoles(_ context.Context) ([]Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Role, 0, len(s.roles))
	for _, r := range s.roles {
		cp := r
		cp.Rules = append([]PermissionRule(nil), r.Rules...)
		result = append(result, cp)
	}
	return result, nil
}

func (s *MemoryStore) UpdateRole(_ context.Context, r *Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.roles[r.Name]
	if !ok {
		return ErrRoleNotFound
	}
	existing.Rules = append([]PermissionRule(nil), r.Rules...)
	existing.UpdatedAt = time.Now().UTC()
	s.roles[r.Name] = existing
	r.ID = existing.ID
	r.Builtin = existing.Builtin
	r.CreatedAt = existing.CreatedAt
	r.UpdatedAt = existing.UpdatedAt
	return nil
}

func (s *MemoryStore) DeleteRole(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.roles[name]
	if !ok {
		return ErrRoleNotFound
	}
	if r.Builtin {
		return ErrRoleBuiltin
	}
	for _, b := range s.bindings {
		if b.RoleName == name {
			return ErrRoleInUse
		}
	}
	delete(s.roles, name)
	return nil
}

func (s *MemoryStore) CreateBinding(_ context.Context, b *RoleBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[b.RoleName]; !ok {
		return ErrRoleNotFound
	}
	for _, existing := range s.bindings {
		if existing.Username == b.Username && existing.RoleName == b.RoleName {
			return ErrBindingExists
		}
	}
	id, err := newUUID()
	if err != nil {
		return err
	}
	b.ID = id
	b.CreatedAt = time.Now().UTC()
	s.bindings[id] = *b
	return nil
}

func (s *MemoryStore) ListBindings(_ context.Context) ([]RoleBinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]RoleBinding, 0, len(s.bindings))
	for _, b := range s.bindings {
		result = append(result, b)
	}
	return result, nil
}

func (s *MemoryStore) ListBindingsForUser(_ context.Context, username string) ([]RoleBinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]RoleBinding, 0)
	for _, b := range s.bindings {
		if b.Username == username {
			result = append(result, b)
		}
	}
	return result, nil
}

func (s *MemoryStore) DeleteBinding(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.bindings[id]; !ok {
		return ErrBindingNotFound
	}
	delete(s.bindings, id)
	return nil
}

func (s *MemoryStore) ExportUsers(_ context.Context) ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]User, 0, len(s.users))
	for _, u := range s.users {
		result = append(result, u)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

func (s *MemoryStore) ExportAuditEntries(_ context.Context) ([]AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]AuditEntry, len(s.audit))
	copy(result, s.audit)
	return result, nil
}

func (s *MemoryStore) ImportUsers(_ context.Context, users []User, replace bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if replace {
		s.users = make(map[string]User)
	}
	for i := range users {
		u := users[i]
		for _, existing := range s.users {
			if existing.Username == u.Username {
				return ErrUsernameExists
			}
		}
		s.users[u.ID] = u
	}
	return nil
}

func (s *MemoryStore) ImportAuditEntries(_ context.Context, entries []AuditEntry, replace bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if replace {
		s.audit = nil
	}
	s.audit = append(s.audit, entries...)
	return nil
}

// Ensure interface compliance.
var _ UserStore = (*MemoryStore)(nil)
var _ AuditStore = (*MemoryStore)(nil)
var _ RBACStore = (*MemoryStore)(nil)
var _ BackupStore = (*MemoryStore)(nil)
