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
	"testing"

	"swarm-rbac-proxy/internal/backup"
	"swarm-rbac-proxy/internal/store"
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

// TestMountBackupRouteOnlyOnInternalListener locks in the security invariant
// that /startbackup is registered on the internal mux but never the external
// one (it is unauthenticated and dumps the full user DB).
func TestMountBackupRouteOnlyOnInternalListener(t *testing.T) {
	ms := seedBackupStore(t)
	dir := t.TempDir()

	internalMux := http.NewServeMux()
	mountBackupRoute(internalMux, true, ms, ms, dir)
	if _, pattern := internalMux.Handler(httptest.NewRequest(http.MethodGet, "/startbackup", nil)); pattern != "/startbackup" {
		t.Errorf("internal mux: /startbackup pattern = %q, want \"/startbackup\"", pattern)
	}

	externalMux := http.NewServeMux()
	mountBackupRoute(externalMux, false, ms, ms, dir)
	if _, pattern := externalMux.Handler(httptest.NewRequest(http.MethodGet, "/startbackup", nil)); pattern != "" {
		t.Errorf("external mux must not register /startbackup, got pattern %q", pattern)
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
