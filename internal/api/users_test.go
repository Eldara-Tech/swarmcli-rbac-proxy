// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"swarm-rbac-proxy/internal/certauth"
	proxylog "swarm-rbac-proxy/internal/log"
	"swarm-rbac-proxy/internal/store"
)

func TestMain(m *testing.M) {
	proxylog.InitTestIfTestLogEnv()
	defer proxylog.Sync()
	os.Exit(m.Run())
}

func newTestHandler() *UserHandler {
	return NewUserHandler(store.NewMemoryStore(), nil, nil)
}

func TestCreateUser(t *testing.T) {
	h := newTestHandler()

	body := `{"username":"alice"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	var u store.User
	if err := json.NewDecoder(w.Body).Decode(&u); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if u.Username != "alice" {
		t.Errorf("username = %q, want %q", u.Username, "alice")
	}
	if u.ID == "" {
		t.Error("expected ID to be set")
	}
	if !u.Enabled {
		t.Error("expected enabled to be true")
	}
}

func TestCreateUser_DuplicateUsername(t *testing.T) {
	h := newTestHandler()

	for i, wantCode := range []int{http.StatusCreated, http.StatusConflict} {
		body := `{"username":"bob"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != wantCode {
			t.Fatalf("request %d: status = %d, want %d", i, w.Code, wantCode)
		}
	}
}

func TestCreateUser_MissingUsername(t *testing.T) {
	h := newTestHandler()

	body := `{"username":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateUser_BadJSON(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateUser_WrongContentType(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"x"}`))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestListUsers_Empty(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := strings.TrimSpace(w.Body.String())
	if body != "[]" {
		t.Errorf("body = %q, want %q", body, "[]")
	}
}

func TestListUsers_AfterCreate(t *testing.T) {
	h := newTestHandler()

	// Create a user first.
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"carol"}`))
	createReq.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), createReq)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var users []store.User
	if err := json.NewDecoder(w.Body).Decode(&users); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("got %d users, want 1", len(users))
	}
	if users[0].Username != "carol" {
		t.Errorf("username = %q, want %q", users[0].Username, "carol")
	}
}

// testCAForHandler creates a certauth.CA backed by a temporary self-signed CA.
func testCAForHandler(t *testing.T) *certauth.CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	dir := t.TempDir()
	certPath := dir + "/ca.pem"
	keyPath := dir + "/ca-key.pem"
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	ca, err := certauth.LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestCreateUser_WithCertificate(t *testing.T) {
	ca := testCAForHandler(t)
	h := NewUserHandler(store.NewMemoryStore(), ca, nil)

	body := `{"username":"alice"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	var resp struct {
		Username    string `json:"username"`
		Certificate *struct {
			CertPEM string `json:"cert_pem"`
			KeyPEM  string `json:"key_pem"`
			CAPEM   string `json:"ca_pem"`
		} `json:"certificate"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Certificate == nil {
		t.Fatal("expected certificate in response")
	}

	// Verify cert CN matches username.
	block, _ := pem.Decode([]byte(resp.Certificate.CertPEM))
	if block == nil {
		t.Fatal("no PEM block in cert_pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.Subject.CommonName != "alice" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "alice")
	}

	// Verify key is valid ECDSA P-256.
	keyBlock, _ := pem.Decode([]byte(resp.Certificate.KeyPEM))
	if keyBlock == nil {
		t.Fatal("no PEM block in key_pem")
	}
	ecKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Errorf("curve = %v, want P-256", ecKey.Curve)
	}

	// Verify CA PEM is parseable.
	caBlock, _ := pem.Decode([]byte(resp.Certificate.CAPEM))
	if caBlock == nil {
		t.Fatal("no PEM block in ca_pem")
	}
}

func TestCreateUser_WithoutCA(t *testing.T) {
	h := NewUserHandler(store.NewMemoryStore(), nil, nil)

	body := `{"username":"bob"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	// Verify no certificate field in response.
	raw := w.Body.String()
	if strings.Contains(raw, "certificate") {
		t.Errorf("response should not contain certificate field: %s", raw)
	}
}

// --- Audit entry tests ---

func TestCreateUser_AuditEntry(t *testing.T) {
	s := store.NewMemoryStore()
	h := NewUserHandler(s, nil, s)

	body := `{"username":"alice"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	entries, err := s.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Action != store.AuditUserCreated {
		t.Errorf("Action = %q, want %q", e.Action, store.AuditUserCreated)
	}
	if e.Resource != "user:alice" {
		t.Errorf("Resource = %q, want %q", e.Resource, "user:alice")
	}
	if e.Status != "success" {
		t.Errorf("Status = %q, want %q", e.Status, "success")
	}
	if e.Detail != "role:user" {
		t.Errorf("Detail = %q, want %q", e.Detail, "role:user")
	}
}

func TestCreateUser_WithCert_AuditEntries(t *testing.T) {
	s := store.NewMemoryStore()
	ca := testCAForHandler(t)
	h := NewUserHandler(s, ca, s)

	body := `{"username":"bob","role":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	entries, err := s.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d audit entries, want 2", len(entries))
	}
	// Newest first: cert.issued, then user.created.
	if entries[0].Action != store.AuditCertIssued {
		t.Errorf("entries[0].Action = %q, want %q", entries[0].Action, store.AuditCertIssued)
	}
	if entries[1].Action != store.AuditUserCreated {
		t.Errorf("entries[1].Action = %q, want %q", entries[1].Action, store.AuditUserCreated)
	}
	if entries[1].Detail != "role:admin" {
		t.Errorf("entries[1].Detail = %q, want %q", entries[1].Detail, "role:admin")
	}
}

func TestDeleteUser_AuditEntry(t *testing.T) {
	s := store.NewMemoryStore()
	h := NewUserHandler(s, nil, s)

	// Create user directly in store.
	if err := s.CreateUser(context.Background(), &store.User{Username: "todelete"}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("DELETE /api/v1/users/{username}", http.HandlerFunc(h.Delete))
	req := httptest.NewRequest("DELETE", "/api/v1/users/todelete", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNoContent)
	}

	entries, err := s.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(entries))
	}
	if entries[0].Action != store.AuditUserDeleted {
		t.Errorf("Action = %q, want %q", entries[0].Action, store.AuditUserDeleted)
	}
	if entries[0].Resource != "user:todelete" {
		t.Errorf("Resource = %q, want %q", entries[0].Resource, "user:todelete")
	}
}

func TestCreateUser_Failure_NoAudit(t *testing.T) {
	s := store.NewMemoryStore()
	h := NewUserHandler(s, nil, s)
	ctx := context.Background()

	// Duplicate: create first, then try again.
	if err := s.CreateUser(ctx, &store.User{Username: "dup"}); err != nil {
		t.Fatal(err)
	}

	for _, body := range []string{
		`{"username":"dup"}`, // duplicate
		`{"username":""}`,    // empty username
		`{invalid`,           // bad JSON
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code < 400 {
			t.Errorf("body %q: expected error status, got %d", body, w.Code)
		}
	}

	entries, err := s.ListAuditEntries(ctx, 10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 audit entries on failures, got %d", len(entries))
	}
}

func TestDeleteUser_NotFound_NoAudit(t *testing.T) {
	s := store.NewMemoryStore()
	h := NewUserHandler(s, nil, s)

	mux := http.NewServeMux()
	mux.Handle("DELETE /api/v1/users/{username}", http.HandlerFunc(h.Delete))
	req := httptest.NewRequest("DELETE", "/api/v1/users/nobody", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}

	entries, err := s.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 audit entries, got %d", len(entries))
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := newTestHandler()

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/v1/users", nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want %d", method, w.Code, http.StatusMethodNotAllowed)
		}
	}
}
