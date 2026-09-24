// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"swarm-rbac-proxy/internal/store"
)

func TestMeHandler_Admin(t *testing.T) {
	h := NewMeHandler(store.NewMemoryStore())
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	r = r.WithContext(context.WithValue(r.Context(), ContextKeyUser,
		&store.User{Username: "alice", Role: "admin"}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got meResponse
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Username != "alice" || got.Role != "admin" {
		t.Errorf("got %+v, want {alice admin}", got)
	}
}

func TestMeHandler_User(t *testing.T) {
	h := NewMeHandler(store.NewMemoryStore())
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	r = r.WithContext(context.WithValue(r.Context(), ContextKeyUser,
		&store.User{Username: "bob", Role: "user"}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got meResponse
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Role != "user" {
		t.Errorf("role = %q, want user", got.Role)
	}
}

func TestMeHandler_NoUser(t *testing.T) {
	h := NewMeHandler(store.NewMemoryStore())
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestMeHandler_MethodNotAllowed(t *testing.T) {
	h := NewMeHandler(store.NewMemoryStore())
	r := httptest.NewRequest(http.MethodPost, "/api/v1/me", nil)
	r = r.WithContext(context.WithValue(r.Context(), ContextKeyUser,
		&store.User{Username: "alice", Role: "admin"}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != "GET" {
		t.Errorf("Allow = %q, want GET", allow)
	}
}

// serveMe runs GET /api/v1/me as username against rbac and returns the recorder.
func serveMe(t *testing.T, rbac store.RBACStore, username string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	r = r.WithContext(context.WithValue(r.Context(), ContextKeyUser,
		&store.User{Username: username, Role: "user"}))
	w := httptest.NewRecorder()
	NewMeHandler(rbac).ServeHTTP(w, r)
	return w
}

func TestMeHandler_RulesUnionOfBindings(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryStore()
	a := store.PermissionRule{Resources: []string{store.ResourceServices}, Verbs: []string{store.VerbGet}}
	b := store.PermissionRule{Resources: []string{store.ResourceVolumes}, Verbs: []string{store.VerbList, store.VerbCreate}}
	for name, rule := range map[string]store.PermissionRule{"a": a, "b": b} {
		if err := s.CreateRole(ctx, &store.Role{Name: name, Rules: []store.PermissionRule{rule}}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateBinding(ctx, &store.RoleBinding{Username: "carol", RoleName: name}); err != nil {
			t.Fatal(err)
		}
	}

	w := serveMe(t, s, "carol")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got meResponse
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Username != "carol" || got.Role != "user" {
		t.Errorf("identity = %+v, want {carol user}", got)
	}
	if len(got.Rules) != 2 {
		t.Fatalf("rules = %+v, want the two bound rules", got.Rules)
	}
	for _, want := range []store.PermissionRule{a, b} {
		found := false
		for _, r := range got.Rules {
			if slices.Equal(r.Resources, want.Resources) && slices.Equal(r.Verbs, want.Verbs) {
				found = true
			}
		}
		if !found {
			t.Errorf("rules %+v missing %+v", got.Rules, want)
		}
	}
}

func TestMeHandler_NoBindingsEncodesEmptyArray(t *testing.T) {
	w := serveMe(t, store.NewMemoryStore(), "dave")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := string(raw["rules"]); got != "[]" {
		t.Errorf("rules = %s, want []", got)
	}
}

// danglingStore reports every role as missing, simulating bindings whose role
// has since been deleted.
type danglingStore struct{ store.RBACStore }

func (danglingStore) GetRole(context.Context, string) (*store.Role, error) {
	return nil, store.ErrRoleNotFound
}

func TestMeHandler_DanglingBindingSkipped(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryStore()
	if err := s.CreateRole(ctx, &store.Role{Name: "gone", Rules: []store.PermissionRule{
		{Resources: []string{store.ResourceServices}, Verbs: []string{store.VerbGet}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateBinding(ctx, &store.RoleBinding{Username: "erin", RoleName: "gone"}); err != nil {
		t.Fatal(err)
	}

	w := serveMe(t, danglingStore{s}, "erin")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := string(raw["rules"]); got != "[]" {
		t.Errorf("rules = %s, want []", got)
	}
}

// failingStore fails every binding lookup.
type failingStore struct{ store.RBACStore }

func (failingStore) ListBindingsForUser(context.Context, string) ([]store.RoleBinding, error) {
	return nil, errors.New("db down")
}

func TestMeHandler_StoreError(t *testing.T) {
	w := serveMe(t, failingStore{store.NewMemoryStore()}, "frank")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), "db down") {
		t.Errorf("body leaks store error: %s", w.Body.String())
	}
}
