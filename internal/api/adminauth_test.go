// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"swarm-rbac-proxy/internal/store"
)

func adminAuthStore(t *testing.T) *store.MemoryStore {
	t.Helper()
	s := store.NewMemoryStore()
	if err := store.SeedDefaultRoles(context.Background(), s); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return s
}

func bindUser(t *testing.T, s *store.MemoryStore, name, role string) {
	t.Helper()
	if _, err := store.CreateUserWithBinding(context.Background(), s, s, name, role); err != nil {
		t.Fatalf("bind %s/%s: %v", name, role, err)
	}
}

func callAdminAuth(h http.Handler, setup func(*http.Request) *http.Request) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	if setup != nil {
		req = setup(req)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestRequireAdminOrToken_BearerValid(t *testing.T) {
	s := adminAuthStore(t)
	h := RequireAdminOrToken("sekret", s, nil, okHandler)
	w := callAdminAuth(h, func(r *http.Request) *http.Request {
		r.Header.Set("Authorization", "Bearer sekret")
		return r
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestRequireAdminOrToken_BearerInvalidNoCert(t *testing.T) {
	s := adminAuthStore(t)
	h := RequireAdminOrToken("sekret", s, nil, okHandler)
	w := callAdminAuth(h, func(r *http.Request) *http.Request {
		r.Header.Set("Authorization", "Bearer wrong")
		return r
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestRequireAdminOrToken_MTLSAdmin(t *testing.T) {
	s := adminAuthStore(t)
	bindUser(t, s, "root", store.RoleAdmin)
	h := RequireAdminOrToken("sekret", s, nil, okHandler)
	w := callAdminAuth(h, func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), ContextKeyUser, &store.User{Username: "root"}))
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (mTLS admin)", w.Code)
	}
}

func TestRequireAdminOrToken_MTLSNonAdmin(t *testing.T) {
	s := adminAuthStore(t)
	bindUser(t, s, "joe", store.RoleOperator)
	h := RequireAdminOrToken("sekret", s, nil, okHandler)
	w := callAdminAuth(h, func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), ContextKeyUser, &store.User{Username: "joe"}))
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (operator)", w.Code)
	}
}

func TestRequireAdminOrToken_NoIdentityNoToken(t *testing.T) {
	s := adminAuthStore(t)
	// Empty configured token: bearer path is disabled, so identity is required.
	h := RequireAdminOrToken("", s, nil, okHandler)
	w := callAdminAuth(h, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestRequireAdminOrToken_NoTokenMTLSAdmin(t *testing.T) {
	s := adminAuthStore(t)
	bindUser(t, s, "root", store.RoleAdmin)
	h := RequireAdminOrToken("", s, nil, okHandler)
	w := callAdminAuth(h, func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), ContextKeyUser, &store.User{Username: "root"}))
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}
