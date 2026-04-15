// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"swarm-rbac-proxy/internal/store"
)

// mockUserStore is a minimal UserStore for testing.
type mockUserStore struct {
	users map[string]*store.User
}

func (m *mockUserStore) CreateUser(_ context.Context, _ *store.User) error { return nil }
func (m *mockUserStore) ListUsers(_ context.Context) ([]store.User, error) {
	return nil, nil
}
func (m *mockUserStore) GetUserByUsername(_ context.Context, username string) (*store.User, error) {
	if u, ok := m.users[username]; ok {
		return u, nil
	}
	return nil, store.ErrUserNotFound
}
func (m *mockUserStore) DeleteUser(_ context.Context, _ string) error         { return nil }
func (m *mockUserStore) SetOnboardToken(_ context.Context, _, _ string) error { return nil }
func (m *mockUserStore) ConsumeOnboardToken(_ context.Context, _ string) (*store.User, error) {
	return nil, store.ErrTokenNotFound
}

func TestRequireClientCert_NilStore(t *testing.T) {
	h := RequireClientCert(nil, okHandler)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestRequireClientCert_NoTLS(t *testing.T) {
	s := &mockUserStore{users: map[string]*store.User{}}
	h := RequireClientCert(s, okHandler)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireClientCert_NoPeerCerts(t *testing.T) {
	s := &mockUserStore{users: map[string]*store.User{}}
	h := RequireClientCert(s, okHandler)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireClientCert_UserNotFound(t *testing.T) {
	s := &mockUserStore{users: map[string]*store.User{}}
	h := RequireClientCert(s, okHandler)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "unknown"}},
		},
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireClientCert_UserDisabled(t *testing.T) {
	s := &mockUserStore{users: map[string]*store.User{
		"alice": {ID: "1", Username: "alice", Enabled: false},
	}}
	h := RequireClientCert(s, okHandler)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "alice"}},
		},
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireClientCert_OK(t *testing.T) {
	s := &mockUserStore{users: map[string]*store.User{
		"alice": {ID: "1", Username: "alice", Enabled: true},
	}}

	var gotUser *store.User
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, _ = r.Context().Value(ContextKeyUser).(*store.User)
		w.WriteHeader(http.StatusOK)
	})

	h := RequireClientCert(s, inner)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "alice"}},
		},
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if gotUser == nil {
		t.Fatal("expected user in context")
	}
	if gotUser.Username != "alice" {
		t.Errorf("username = %q, want %q", gotUser.Username, "alice")
	}
}

func TestExtractIdentity_SANEmail(t *testing.T) {
	cert := &x509.Certificate{
		Subject:        pkix.Name{CommonName: "fallback-cn"},
		EmailAddresses: []string{"alice@example.com"},
	}
	got := extractIdentity(cert)
	if got != "alice@example.com" {
		t.Errorf("got %q, want %q", got, "alice@example.com")
	}
}

func TestExtractIdentity_CNFallback(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "alice"},
	}
	got := extractIdentity(cert)
	if got != "alice" {
		t.Errorf("got %q, want %q", got, "alice")
	}
}

func TestExtractIdentity_EmptyCert(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: ""},
	}
	got := extractIdentity(cert)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestRequireClientCert_EmptyIdentity(t *testing.T) {
	s := &mockUserStore{users: map[string]*store.User{}}
	h := RequireClientCert(s, okHandler)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: ""}},
		},
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}
