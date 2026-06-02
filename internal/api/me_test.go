// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"swarm-rbac-proxy/internal/store"
)

func TestMeHandler_Admin(t *testing.T) {
	h := NewMeHandler()
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
	h := NewMeHandler()
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
	h := NewMeHandler()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestMeHandler_MethodNotAllowed(t *testing.T) {
	h := NewMeHandler()
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
