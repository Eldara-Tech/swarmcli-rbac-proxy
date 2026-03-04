package store

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-memory UserStore for development and testing.
type MemoryStore struct {
	mu    sync.RWMutex
	users map[string]User
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{users: make(map[string]User)}
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
	u.Enabled = true
	u.CreatedAt = now
	u.UpdatedAt = now

	s.users[id] = *u
	return nil
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
