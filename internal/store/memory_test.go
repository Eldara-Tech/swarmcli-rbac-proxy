package store

import (
	"context"
	"sync"
	"testing"
)

func TestMemoryStore_Contract(t *testing.T) {
	testUserStoreContract(t, func() UserStore { return NewMemoryStore() })
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
