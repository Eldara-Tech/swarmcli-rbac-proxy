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
