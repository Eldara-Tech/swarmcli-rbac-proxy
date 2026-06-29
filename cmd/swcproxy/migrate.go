// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import (
	"context"
	"fmt"
	"os"

	"swarm-rbac-proxy/internal/config"
	"swarm-rbac-proxy/internal/store"
)

type migrateOpts struct {
	sqlitePath string
	pgURL      string
	force      bool
}

// parseMigrateArgs parses `swcproxy migrate` flags. Unset --sqlite/--postgres
// fall back to the configured DatabasePath / DatabaseURL so an operator already
// running SQLite can just point at their target postgres.
func parseMigrateArgs(args []string, cfg config.Config) (migrateOpts, error) {
	o := migrateOpts{sqlitePath: cfg.DatabasePath, pgURL: cfg.DatabaseURL}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--sqlite":
			if i+1 >= len(args) {
				return o, fmt.Errorf("--sqlite requires a file path")
			}
			i++
			o.sqlitePath = args[i]
		case "--postgres":
			if i+1 >= len(args) {
				return o, fmt.Errorf("--postgres requires a connection URL")
			}
			i++
			o.pgURL = args[i]
		case "--force":
			o.force = true
		default:
			return o, fmt.Errorf("unknown flag: %s", args[i])
		}
	}
	if o.sqlitePath == "" {
		return o, fmt.Errorf("no source: pass --sqlite <path> or set PROXY_DATABASE_PATH")
	}
	if o.pgURL == "" {
		return o, fmt.Errorf("no destination: pass --postgres <url> or set PROXY_DATABASE_URL")
	}
	return o, nil
}

func printMigrateUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  swcproxy migrate [--sqlite <path>] [--postgres <url>] [--force]
                     Copy a SQLite store into PostgreSQL (users, audit log and
                     RBAC roles/bindings) in one transaction. Onboarding tokens
                     are copied verbatim — no intermediate file is written.

  --sqlite <path>    Source SQLite database (default: PROXY_DATABASE_PATH, or proxy.db)
  --postgres <url>   Destination DSN (default: PROXY_DATABASE_URL),
                     e.g. postgres://user:pass@host:5432/db?sslmode=verify-full
  --force            Replace a non-empty destination (clears all tables first)

The client CA lives in Docker secrets, not the database, so migrating the store
does not affect existing user connections. After verifying the counts, switch
the proxy to PROXY_STORE=postgres + PROXY_DATABASE_URL and redeploy. See
docs/sqlite-to-postgres.md.
`)
}

func runMigrateCommand(args []string) {
	if len(args) > 0 && isHelpFlag(args[0]) {
		printMigrateUsage()
		return
	}
	o, err := parseMigrateArgs(args, loadCfg())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
		printMigrateUsage()
		os.Exit(1)
	}

	// Guard the empty-source footgun: NewSQLiteStore would otherwise create a
	// fresh (empty) database from a typo'd path and "migrate" nothing.
	if _, err := os.Stat(o.sqlitePath); err != nil {
		fatal("source sqlite database %q: %v", o.sqlitePath, err)
	}

	ctx := context.Background()

	src, err := store.NewSQLiteStore(ctx, o.sqlitePath)
	if err != nil {
		fatal("open source sqlite %q: %v", o.sqlitePath, err)
	}
	defer src.Close()

	// Fail-fast on the destination (no retry): an interactive operator prefers a
	// crisp error over a 30s wait. NewPostgresStore also ensures the schema.
	dst, err := store.NewPostgresStore(ctx, o.pgURL)
	if err != nil {
		fatal("open destination postgres: %v", err)
	}
	defer dst.Close()

	data, err := src.Export(ctx)
	if err != nil {
		fatal("export from sqlite: %v", err)
	}

	existing, err := dst.Export(ctx)
	if err != nil {
		fatal("inspect destination: %v", err)
	}
	if len(existing.Users) > 0 && !o.force {
		fatal("destination already has %d users; pass --force to replace them", len(existing.Users))
	}

	// One transaction across users, audit, roles and bindings: a failure leaves
	// the destination untouched rather than half-migrated.
	if err := dst.Restore(ctx, data, o.force); err != nil {
		fatal("migrate: %v", err)
	}

	_ = dst.RecordAudit(ctx, &store.AuditEntry{
		Actor: "cli", Action: store.AuditDBMigrated,
		Resource: "migrate", Status: "success",
		Detail: fmt.Sprintf("source=sqlite:%s users=%d audit=%d roles=%d bindings=%d force=%v",
			o.sqlitePath, len(data.Users), len(data.Audit), len(data.Roles), len(data.Bindings), o.force),
	})

	fmt.Fprintf(os.Stderr, "Migrated %d users, %d audit entries, %d roles and %d bindings from %s to postgres\n",
		len(data.Users), len(data.Audit), len(data.Roles), len(data.Bindings), o.sqlitePath)
	fmt.Fprintln(os.Stderr, "Next: set PROXY_STORE=postgres + PROXY_DATABASE_URL and redeploy, then retire the SQLite file.")
}
