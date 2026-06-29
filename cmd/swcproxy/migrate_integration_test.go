// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

//go:build integration

// End-to-end tests for `swcproxy migrate` (SQLite → PostgreSQL). They drive the
// real CLI entrypoint as a subprocess (see TestMain in cli_integration_test.go)
// against a temporary SQLite source and the CI PostgreSQL service named by
// TEST_DATABASE_URL, exercising the full Export → Restore copy, the non-empty
// destination guard, --force, the missing-source guard, and the db.migrated
// audit record on the destination.
package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"swarm-rbac-proxy/internal/store"
)

// destPGURL returns the destination DSN or skips when no PostgreSQL is available.
func destPGURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	return url
}

// cleanPostgres empties every table via a replace-with-nothing Restore, so each
// test starts from a known-empty destination using only the public store API.
func cleanPostgres(t *testing.T, url string) {
	t.Helper()
	ctx := context.Background()
	s, err := store.NewPostgresStore(ctx, url)
	if err != nil {
		t.Fatalf("clean: open postgres: %v", err)
	}
	defer s.Close()
	if err := s.Restore(ctx, store.BackupData{}, true); err != nil {
		t.Fatalf("clean: clear tables: %v", err)
	}
}

func exportPostgres(t *testing.T, url string) store.BackupData {
	t.Helper()
	ctx := context.Background()
	s, err := store.NewPostgresStore(ctx, url)
	if err != nil {
		t.Fatalf("export: open postgres: %v", err)
	}
	defer s.Close()
	data, err := s.Export(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return data
}

func TestCLIMigrate_SqliteToPostgres(t *testing.T) {
	pgURL := destPGURL(t)
	cleanPostgres(t, pgURL)

	src := dbPath(t)
	seedUsers(t, src, "admin", "bob") // bob (index 1) gets onboarding token "tok-bob"
	seedRoleBinding(t, src, "deployer", "bob")

	stdout, stderr, code := runCLI(t, map[string]string{"PROXY_ENV": "dev"}, "",
		"migrate", "--sqlite", src, "--postgres", pgURL)
	if code != 0 {
		t.Fatalf("migrate exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	data := exportPostgres(t, pgURL)
	if len(data.Users) != 2 {
		t.Fatalf("users = %d, want 2", len(data.Users))
	}
	var bob *store.User
	for i := range data.Users {
		if data.Users[i].Username == "bob" {
			bob = &data.Users[i]
		}
	}
	if bob == nil {
		t.Fatal("bob not migrated")
	}
	if bob.OnboardToken != "tok-bob" {
		t.Errorf("bob onboard token = %q, want tok-bob (token columns not copied)", bob.OnboardToken)
	}
	if len(data.Roles) != 1 || data.Roles[0].Name != "deployer" {
		t.Errorf("roles = %+v, want [deployer]", data.Roles)
	}
	if len(data.Bindings) != 1 || data.Bindings[0].Username != "bob" || data.Bindings[0].RoleName != "deployer" {
		t.Errorf("bindings = %+v, want bob->deployer", data.Bindings)
	}
	var migrated bool
	for _, e := range data.Audit {
		if e.Action == store.AuditDBMigrated {
			migrated = true
		}
	}
	if !migrated {
		t.Errorf("destination audit missing %q entry: %+v", store.AuditDBMigrated, data.Audit)
	}
}

func TestCLIMigrate_NonEmptyRefusedThenForce(t *testing.T) {
	pgURL := destPGURL(t)
	cleanPostgres(t, pgURL)

	src := dbPath(t)
	seedUsers(t, src, "admin")

	// First migration into an empty destination succeeds.
	if _, stderr, code := runCLI(t, map[string]string{"PROXY_ENV": "dev"}, "",
		"migrate", "--sqlite", src, "--postgres", pgURL); code != 0 {
		t.Fatalf("first migrate exit %d: %s", code, stderr)
	}

	// Second migration without --force is refused (destination non-empty).
	_, stderr, code := runCLI(t, map[string]string{"PROXY_ENV": "dev"}, "",
		"migrate", "--sqlite", src, "--postgres", pgURL)
	if code == 0 {
		t.Fatal("expected refusal on non-empty destination, got exit 0")
	}
	if !strings.Contains(stderr, "--force") {
		t.Errorf("stderr should mention --force, got: %s", stderr)
	}

	// With --force it replaces.
	if _, stderr, code := runCLI(t, map[string]string{"PROXY_ENV": "dev"}, "",
		"migrate", "--sqlite", src, "--postgres", pgURL, "--force"); code != 0 {
		t.Fatalf("forced migrate exit %d: %s", code, stderr)
	}
}

func TestCLIMigrate_MissingSource(t *testing.T) {
	// Fails at the source-existence guard before touching PostgreSQL, so no DB
	// is required; --postgres is only parsed.
	missing := dbPath(t) // path under a TempDir that was never created
	_, stderr, code := runCLI(t, map[string]string{"PROXY_ENV": "dev"}, "",
		"migrate", "--sqlite", missing, "--postgres", "postgres://unused")
	if code == 0 {
		t.Fatal("expected failure for missing source, got exit 0")
	}
	if !strings.Contains(stderr, "source sqlite database") {
		t.Errorf("stderr should name the missing source, got: %s", stderr)
	}
}
