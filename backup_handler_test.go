// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"swarm-rbac-proxy/internal/backup"
	"swarm-rbac-proxy/internal/store"
	"swarm-rbac-proxy/internal/version"
)

func seedBackupStore(t *testing.T) *store.MemoryStore {
	t.Helper()
	ms := store.NewMemoryStore()
	if err := ms.CreateUser(context.Background(), &store.User{
		ID: "u1", Username: "alice", Role: "admin", Enabled: true,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return ms
}

func TestBackupHandlerWritesFileAndReturnsMetadata(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			ms := seedBackupStore(t)
			dir := filepath.Join(t.TempDir(), "backup")
			h := newBackupHandler(ms, ms, dir)

			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(method, "/startbackup", nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body)
			}
			var resp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}
			if resp["result"] != "success" {
				t.Errorf("result = %q, want success", resp["result"])
			}
			if resp["file"] == "" || resp["path"] == "" {
				t.Errorf("missing file/path in response: %v", resp)
			}
			if filepath.Join(dir, resp["file"]) != resp["path"] {
				t.Errorf("path %q is not dir/%q", resp["path"], resp["file"])
			}

			data, err := os.ReadFile(resp["path"])
			if err != nil {
				t.Fatalf("read written backup: %v", err)
			}
			var doc backup.Doc
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("written file not valid backup: %v", err)
			}
			if doc.Schema != backup.Schema || len(doc.Users) != 1 {
				t.Errorf("doc schema=%q users=%d", doc.Schema, len(doc.Users))
			}
			if doc.CA != nil {
				t.Error("HTTP-triggered backup must never embed the CA")
			}

			entries, _ := ms.ListAuditEntries(context.Background(), 10)
			if !hasBackupAudit(entries) {
				t.Errorf("backup.exported audit not recorded: %+v", entries)
			}
		})
	}
}

func hasBackupAudit(entries []store.AuditEntry) bool {
	for _, e := range entries {
		if e.Action == store.AuditBackupExported && e.Actor == "internal" && e.Status == "success" {
			return true
		}
	}
	return false
}

func TestBackupHandlerRejectsOtherMethods(t *testing.T) {
	ms := seedBackupStore(t)
	h := newBackupHandler(ms, ms, t.TempDir())
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPut, "/startbackup", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestBackupHandlerRedactsTokens(t *testing.T) {
	ms := store.NewMemoryStore()
	ctx := context.Background()
	if err := ms.CreateUser(ctx, &store.User{ID: "u1", Username: "alice", Role: "admin", Enabled: true}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := ms.SetOnboardToken(ctx, "alice", "tok-alice"); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	h := newBackupHandler(ms, ms, dir)

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/startbackup", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body)
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	data, err := os.ReadFile(resp["path"])
	if err != nil {
		t.Fatalf("read written backup: %v", err)
	}
	var doc backup.Doc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("written file not valid backup: %v", err)
	}
	for _, u := range doc.Users {
		if u.OnboardToken != "" || u.TokenIssuedAt != nil || u.TokenConsumedAt != nil {
			t.Errorf("/startbackup leaked token columns for %s: %+v", u.Username, u)
		}
	}
}

// TestMountControlPlaneOnlyOnInternalListener locks in the security invariant
// that the /_swc/ control-plane namespace (and the /startbackup back-compat
// alias) is registered on the internal mux but never the external one — the
// endpoints are unauthenticated and the backup trigger dumps the full user DB.
func TestMountControlPlaneOnlyOnInternalListener(t *testing.T) {
	ms := seedBackupStore(t)
	dir := t.TempDir()

	internalMux := http.NewServeMux()
	mountControlPlane(internalMux, true, ms, ms, dir)
	for _, tc := range []struct{ method, path, want string }{
		{http.MethodPost, "/_swc/startbackup", "/_swc/startbackup"},
		{http.MethodPost, "/startbackup", "/startbackup"},
		{http.MethodGet, "/_swc/version", "GET /_swc/version"},
		{http.MethodGet, "/_swc/anything-else", "/_swc/"},
	} {
		if _, pattern := internalMux.Handler(httptest.NewRequest(tc.method, tc.path, nil)); pattern != tc.want {
			t.Errorf("internal mux: %s %s pattern = %q, want %q", tc.method, tc.path, pattern, tc.want)
		}
	}

	externalMux := http.NewServeMux()
	mountControlPlane(externalMux, false, ms, ms, dir)
	for _, path := range []string{"/_swc/startbackup", "/startbackup", "/_swc/version", "/_swc/anything-else"} {
		if _, pattern := externalMux.Handler(httptest.NewRequest(http.MethodGet, path, nil)); pattern != "" {
			t.Errorf("external mux must not register %q, got pattern %q", path, pattern)
		}
	}
}

// TestControlVersionHandler verifies the build-identity endpoint reports the
// version package's values — the signal an operator uses to tell whether a
// build carries a given feature.
func TestControlVersionHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	handleControlVersion(rec, httptest.NewRequest(http.MethodGet, "/_swc/version", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["version"] != version.Version || resp["commit"] != version.Commit || resp["date"] != version.Date {
		t.Errorf("version response = %v, want version=%q commit=%q date=%q",
			resp, version.Version, version.Commit, version.Date)
	}
}

// TestControlNotFoundHandler verifies an unknown control route gets a branded
// JSON 404 naming the path, not a bare or daemon-shaped 404.
func TestControlNotFoundHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	handleControlNotFound(rec, httptest.NewRequest(http.MethodGet, "/_swc/bogus", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["result"] != "error" || !strings.Contains(resp["error"], "/_swc/bogus") {
		t.Errorf("not-found response = %v, want error naming the path", resp)
	}
}

// TestControlPlaneNamespacePreemptsCatchAll is the PR #107 regression: an
// unknown path under /_swc/ must be answered by the namespace 404, never fall
// through to the catch-all that forwards to the Docker socket (which is what
// made a missing route look like a genuine Docker 404).
func TestControlPlaneNamespacePreemptsCatchAll(t *testing.T) {
	ms := seedBackupStore(t)
	mux := http.NewServeMux()
	mountControlPlane(mux, true, ms, ms, t.TempDir())
	catchAllHit := false
	mux.HandleFunc("/", func(http.ResponseWriter, *http.Request) { catchAllHit = true })

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_swc/nope", nil))

	if catchAllHit {
		t.Error("/_swc/nope reached the catch-all (would be forwarded to Docker); the namespace must own it")
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// TestControlPlaneBackupAliasRoutes verifies both the canonical
// /_swc/startbackup and the /startbackup alias dispatch to the backup handler
// through the mux (precedence over the /_swc/ namespace 404).
func TestControlPlaneBackupAliasRoutes(t *testing.T) {
	for _, path := range []string{"/_swc/startbackup", "/startbackup"} {
		t.Run(path, func(t *testing.T) {
			ms := seedBackupStore(t)
			mux := http.NewServeMux()
			mountControlPlane(mux, true, ms, ms, filepath.Join(t.TempDir(), "backup"))

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want 200 (body %s)", path, rec.Code, rec.Body)
			}
			var resp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp["result"] != "success" {
				t.Errorf("%s result = %q, want success", path, resp["result"])
			}
		})
	}
}

func TestRequestIP(t *testing.T) {
	cases := []struct{ remoteAddr, want string }{
		{"10.0.0.5:5555", "10.0.0.5"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"no-port", "no-port"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, "/startbackup", nil)
		r.RemoteAddr = tc.remoteAddr
		if got := requestIP(r); got != tc.want {
			t.Errorf("requestIP(%q) = %q, want %q", tc.remoteAddr, got, tc.want)
		}
	}
}

// userStoreWithoutBackup is a UserStore that does NOT implement BackupStore,
// to exercise the handler's capability guard.
type userStoreWithoutBackup struct{ store.UserStore }

func TestBackupHandlerWhenStoreLacksBackupSupport(t *testing.T) {
	h := newBackupHandler(userStoreWithoutBackup{}, store.NewMemoryStore(), t.TempDir())
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/startbackup", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}
