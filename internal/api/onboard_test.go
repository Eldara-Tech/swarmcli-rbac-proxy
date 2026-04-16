// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"swarm-rbac-proxy/internal/certauth"
	"swarm-rbac-proxy/internal/store"
)

func newTestOnboardHandler(t *testing.T) (*OnboardHandler, *store.MemoryStore) {
	t.Helper()
	s := store.NewMemoryStore()
	ca := loadTestCA(t)
	return NewOnboardHandler(s, ca, "tcp://proxy.example.com:2376"), s
}

func loadTestCA(t *testing.T) *certauth.CA {
	t.Helper()
	ca, err := certauth.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	return ca
}

func setupOnboardUser(t *testing.T, s *store.MemoryStore, username, token string) {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateUser(ctx, &store.User{Username: username}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := s.SetOnboardToken(ctx, username, token); err != nil {
		t.Fatalf("SetOnboardToken: %v", err)
	}
}

func TestOnboardHandler_HappyPath(t *testing.T) {
	h, s := newTestOnboardHandler(t)
	setupOnboardUser(t, s, "alice", "valid-token")

	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/onboard/{token}", h)
	req := httptest.NewRequest("GET", "/api/v1/onboard/valid-token", nil)
	req.TLS = &tls.ConnectionState{} // simulate TLS connection
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-tar" {
		t.Errorf("Content-Type = %q, want application/x-tar", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); cd != "attachment; filename=alice.tar" {
		t.Errorf("Content-Disposition = %q", cd)
	}

	// Verify tar contents.
	tr := tar.NewReader(bytes.NewReader(w.Body.Bytes()))
	found := make(map[string]bool)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		found[hdr.Name] = true

		if hdr.Name == "meta.json" {
			var meta contextMeta
			if err := json.NewDecoder(tr).Decode(&meta); err != nil {
				t.Fatalf("decode meta.json: %v", err)
			}
			if meta.Name != "alice-managed" {
				t.Errorf("meta.Name = %q, want %q", meta.Name, "alice-managed")
			}
			ep, ok := meta.Endpoints["docker"]
			if !ok {
				t.Fatal("missing docker endpoint in meta.json")
			}
			if ep.Host != "tcp://proxy.example.com:2376" {
				t.Errorf("endpoint Host = %q", ep.Host)
			}
		}
	}

	for _, name := range []string{"meta.json", "tls/docker/ca.pem", "tls/docker/cert.pem", "tls/docker/key.pem"} {
		if !found[name] {
			t.Errorf("missing tar entry %q", name)
		}
	}
}

func TestOnboardHandler_TokenNotFound(t *testing.T) {
	h, _ := newTestOnboardHandler(t)

	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/onboard/{token}", h)
	req := httptest.NewRequest("GET", "/api/v1/onboard/nonexistent", nil)
	req.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestOnboardHandler_TokenConsumed(t *testing.T) {
	h, s := newTestOnboardHandler(t)
	setupOnboardUser(t, s, "bob", "used-token")

	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/onboard/{token}", h)

	// First request succeeds.
	req := httptest.NewRequest("GET", "/api/v1/onboard/used-token", nil)
	req.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want 200", w.Code)
	}

	// Second request should fail with 410 Gone.
	req = httptest.NewRequest("GET", "/api/v1/onboard/used-token", nil)
	req.TLS = &tls.ConnectionState{}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusGone {
		t.Fatalf("second request: status = %d, want 410", w.Code)
	}
}

func TestOnboardHandler_RequiresTLS(t *testing.T) {
	h, s := newTestOnboardHandler(t)
	setupOnboardUser(t, s, "carol", "tls-token")

	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/onboard/{token}", h)

	// Plain HTTP (no TLS, no internal flag) should be rejected.
	req := httptest.NewRequest("GET", "/api/v1/onboard/tls-token", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("plain HTTP: status = %d, want 403; body: %s", w.Code, w.Body.String())
	}

	// Internal listener (no TLS but ContextKeyInternal set) should be allowed.
	req = httptest.NewRequest("GET", "/api/v1/onboard/tls-token", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyInternal, true))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("internal listener: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}
