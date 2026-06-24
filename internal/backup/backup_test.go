// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package backup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"swarm-rbac-proxy/internal/config"
	"swarm-rbac-proxy/internal/store"
)

func seededStore(t *testing.T) *store.MemoryStore {
	t.Helper()
	ms := store.NewMemoryStore()
	ctx := context.Background()
	issued := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := ms.CreateUser(ctx, &store.User{
		ID: "u1", Username: "alice", Role: "admin", Enabled: true,
		OnboardToken: "tok-alice", TokenIssuedAt: &issued,
	}); err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	if err := ms.CreateUser(ctx, &store.User{
		ID: "u2", Username: "bob", Role: "operator", Enabled: true,
	}); err != nil {
		t.Fatalf("seed bob: %v", err)
	}
	if err := ms.RecordAudit(ctx, &store.AuditEntry{
		ID: "a1", Actor: "cli", Action: store.AuditUserCreated,
		Resource: "user:alice", Status: "success",
	}); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	return ms
}

func TestCreateExportsUsersAndAuditWithoutCA(t *testing.T) {
	ms := seededStore(t)
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

	doc, err := Create(context.Background(), ms, "v9.9.9", now, true)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if doc.Schema != Schema || doc.Version != Version {
		t.Errorf("schema/version = %q/%d, want %q/%d", doc.Schema, doc.Version, Schema, Version)
	}
	if !doc.CreatedAt.Equal(now) || doc.ProxyVersion != "v9.9.9" {
		t.Errorf("createdAt/proxyVersion = %v/%q", doc.CreatedAt, doc.ProxyVersion)
	}
	if doc.CA != nil {
		t.Error("Create must never populate CA")
	}
	if len(doc.Users) != 2 || len(doc.Audit) != 1 {
		t.Fatalf("users=%d audit=%d, want 2/1", len(doc.Users), len(doc.Audit))
	}
	// Onboarding-token columns (json:"-" on store.User) must survive the export.
	var alice *User
	for i := range doc.Users {
		if doc.Users[i].Username == "alice" {
			alice = &doc.Users[i]
		}
	}
	if alice == nil || alice.OnboardToken != "tok-alice" || alice.TokenIssuedAt == nil {
		t.Errorf("alice token not exported: %+v", alice)
	}
}

func TestCreateRedactsTokensByDefault(t *testing.T) {
	ms := seededStore(t)
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

	doc, err := Create(context.Background(), ms, "v1", now, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, u := range doc.Users {
		if u.OnboardToken != "" || u.TokenIssuedAt != nil || u.TokenConsumedAt != nil {
			t.Errorf("token columns not redacted for %s: %+v", u.Username, u)
		}
	}

	// includeTokens=true preserves them (alice has a token in the fixture).
	withTokens, err := Create(context.Background(), ms, "v1", now, true)
	if err != nil {
		t.Fatalf("Create(includeTokens): %v", err)
	}
	var found bool
	for _, u := range withTokens.Users {
		if u.Username == "alice" && u.OnboardToken == "tok-alice" {
			found = true
		}
	}
	if !found {
		t.Error("includeTokens=true did not preserve alice's onboarding token")
	}
}

func TestMarshalIsIndentedJSONWithTrailingNewline(t *testing.T) {
	doc := &Doc{Schema: Schema, Version: Version}
	data, err := Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Error("want trailing newline")
	}
	if !strings.Contains(string(data), "\n  \"schema\"") {
		t.Errorf("want indented JSON, got:\n%s", data)
	}
	var rt Doc
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
}

func TestFilename(t *testing.T) {
	got := Filename(time.Date(2026, 6, 24, 14, 5, 9, 0, time.UTC))
	if want := "swc-proxy-backup-20260624-140509.json"; got != want {
		t.Errorf("Filename = %q, want %q", got, want)
	}
	// Non-UTC input is normalised to UTC.
	loc := time.FixedZone("plus2", 2*3600)
	got = Filename(time.Date(2026, 6, 24, 16, 5, 9, 0, loc))
	if want := "swc-proxy-backup-20260624-140509.json"; got != want {
		t.Errorf("Filename(non-UTC) = %q, want %q", got, want)
	}
}

func TestWriteToDirCreatesFileWithSecurePerms(t *testing.T) {
	ms := seededStore(t)
	now := time.Date(2026, 6, 24, 14, 5, 9, 0, time.UTC)
	doc, err := Create(context.Background(), ms, "v1", now, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "nested", "backup") // not yet created
	path, err := WriteToDir(dir, doc)
	if err != nil {
		t.Fatalf("WriteToDir: %v", err)
	}
	if want := filepath.Join(dir, "swc-proxy-backup-20260624-140509.json"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written backup: %v", err)
	}
	var rt Doc
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatalf("written file is not valid backup JSON: %v", err)
	}
	if len(rt.Users) != 2 {
		t.Errorf("round-trip users = %d, want 2", len(rt.Users))
	}

	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Errorf("file mode = %o, want 600", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
			t.Errorf("dir mode = %o, want 700", fi.Mode().Perm())
		}
	}
}

func TestWriteToDirDoesNotOverwriteOnSameSecondCollision(t *testing.T) {
	ms := seededStore(t)
	now := time.Date(2026, 6, 24, 14, 5, 9, 0, time.UTC) // identical timestamp → same base name
	doc, err := Create(context.Background(), ms, "v1", now, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	dir := t.TempDir()

	first, err := WriteToDir(dir, doc)
	if err != nil {
		t.Fatalf("WriteToDir(first): %v", err)
	}
	second, err := WriteToDir(dir, doc)
	if err != nil {
		t.Fatalf("WriteToDir(second): %v", err)
	}
	if first == second {
		t.Fatalf("collision silently overwrote: both wrote %q", first)
	}
	if want := filepath.Join(dir, "swc-proxy-backup-20260624-140509.json"); first != want {
		t.Errorf("first path = %q, want %q", first, want)
	}
	if want := filepath.Join(dir, "swc-proxy-backup-20260624-140509-1.json"); second != want {
		t.Errorf("second path = %q, want %q", second, want)
	}
	for _, p := range []string{first, second} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected file %q to exist: %v", p, err)
		}
	}
}

func TestDefaultDir(t *testing.T) {
	cases := []struct {
		dbPath string
		want   string
	}{
		{"/data/proxy.db", "/data/backup"},
		{"proxy.db", "backup"},
		{"", "backup"},
		{"/var/lib/swc/proxy.db", "/var/lib/swc/backup"},
	}
	for _, tc := range cases {
		got := DefaultDir(config.Config{DatabasePath: tc.dbPath})
		if got != tc.want {
			t.Errorf("DefaultDir(%q) = %q, want %q", tc.dbPath, got, tc.want)
		}
	}
}

func TestUsersRoundTrip(t *testing.T) {
	issued := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	in := []store.User{
		{ID: "u1", Username: "alice", Role: "admin", Enabled: true, OnboardToken: "x", TokenIssuedAt: &issued},
		{ID: "u2", Username: "bob", Role: "operator", Enabled: false},
	}
	out := FromUsers(ToUsers(in))
	if len(out) != len(in) {
		t.Fatalf("len = %d, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Errorf("user[%d] round-trip mismatch:\n got %+v\nwant %+v", i, out[i], in[i])
		}
	}
}
