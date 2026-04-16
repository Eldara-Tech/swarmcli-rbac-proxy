// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"swarm-rbac-proxy/internal/config"
	proxylog "swarm-rbac-proxy/internal/log"
	"swarm-rbac-proxy/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "user":
		if len(os.Args) < 3 {
			printUserUsage()
			os.Exit(1)
		}
		runUserCommand(os.Args[2], os.Args[3:])
	case "audit":
		if len(os.Args) < 3 {
			printAuditUsage()
			os.Exit(1)
		}
		runAuditCommand(os.Args[2], os.Args[3:])
	case "--help", "-h", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `swcproxy — RBAC proxy admin CLI

Usage:
  swcproxy user ls                         List users
  swcproxy user add <username> [--admin]   Create user + onboarding token
  swcproxy user delete <username>          Delete user
  swcproxy user regenerate-token <username> Regenerate onboarding token
  swcproxy audit ls [--limit N]            List audit log entries (default: 50)
  swcproxy --help                          Show this help
`)
}

func printUserUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  swcproxy user ls                         List users
  swcproxy user add <username> [--admin]   Create user + onboarding token
  swcproxy user delete <username>          Delete user
  swcproxy user regenerate-token <username> Regenerate onboarding token
`)
}

func runUserCommand(subcmd string, args []string) {
	switch subcmd {
	case "ls", "list":
		cmdUserList()
	case "add":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: swcproxy user add <username> [--admin]")
			os.Exit(1)
		}
		if isHelpFlag(args[0]) {
			printUserUsage()
			return
		}
		admin := false
		for _, a := range args[1:] {
			if a == "--admin" {
				admin = true
			}
		}
		cmdUserAdd(args[0], admin)
	case "delete", "rm":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: swcproxy user delete <username>")
			os.Exit(1)
		}
		if isHelpFlag(args[0]) {
			printUserUsage()
			return
		}
		cmdUserDelete(args[0])
	case "regenerate-token":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: swcproxy user regenerate-token <username>")
			os.Exit(1)
		}
		if isHelpFlag(args[0]) {
			printUserUsage()
			return
		}
		cmdUserRegenerateToken(args[0])
	case "--help", "-h", "help":
		printUserUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown user command: %s\n\n", subcmd)
		printUserUsage()
		os.Exit(1)
	}
}

func openStore() (store.UserStore, store.AuditStore) {
	cfg, err := config.Load(os.Getenv("PROXY_CONFIG"))
	if err != nil {
		fatal("load config: %v", err)
	}
	proxylog.Init(cfg.Env, cfg.LogLevel)

	ctx := context.Background()
	switch cfg.Store {
	case "sqlite":
		s, err := store.NewSQLiteStore(ctx, cfg.DatabasePath)
		if err != nil {
			fatal("open sqlite: %v", err)
		}
		return s, s
	case "postgres":
		if cfg.DatabaseURL == "" {
			fatal("database_url is required for postgres store")
		}
		s, err := store.NewPostgresStore(ctx, cfg.DatabaseURL)
		if err != nil {
			fatal("open postgres: %v", err)
		}
		return s, s
	case "memory":
		fatal("swcproxy cannot use in-memory store (data not shared with proxy process)")
	default:
		fatal("unknown store type: %s", cfg.Store)
	}
	return nil, nil
}

func getExternalURL() string {
	cfg, err := config.Load(os.Getenv("PROXY_CONFIG"))
	if err != nil {
		return "<PROXY_HOST>:<PORT>"
	}
	if cfg.ExternalURL != "" {
		return cfg.ExternalURL
	}
	return "<PROXY_HOST>:<PORT>"
}

// curlURL converts a Docker-style tcp:// URL to https:// for use in curl commands.
func curlURL(rawURL string) string {
	if after, ok := strings.CutPrefix(rawURL, "tcp://"); ok {
		return "https://" + after
	}
	return rawURL
}

func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		fatal("generate token: %v", err)
	}
	return hex.EncodeToString(b)
}

func cmdUserList() {
	s, _ := openStore()
	users, err := s.ListUsers(context.Background())
	if err != nil {
		fatal("list users: %v", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "USERNAME\tROLE\tENABLED\tCREATED")
	for _, u := range users {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%v\t%s\n", u.Username, u.Role, u.Enabled, u.CreatedAt.Format("2006-01-02 15:04"))
	}
	_ = w.Flush()
}

func cmdUserAdd(username string, admin bool) {
	s, audit := openStore()
	ctx := context.Background()

	role := "user"
	if admin {
		role = "admin"
	}

	u := &store.User{Username: username, Role: role}
	if err := s.CreateUser(ctx, u); err != nil {
		fatal("create user: %v", err)
	}

	token := generateToken()
	if err := s.SetOnboardToken(ctx, username, token); err != nil {
		fatal("set onboard token: %v", err)
	}

	_ = audit.RecordAudit(ctx, &store.AuditEntry{
		Actor: "cli", Action: store.AuditUserCreated,
		Resource: "user:" + username, Status: "success",
	})

	extURL := getExternalURL()
	fmt.Printf("User created: %s (role: %s)\n", username, role)
	fmt.Printf("Onboard token: %s\n\n", token)
	fmt.Printf("Share this command with the user:\n")
	fmt.Printf("  curl -k %s/api/v1/onboard/%s -o %s.tar\n\n", curlURL(extURL), token, username)
	fmt.Printf("Then import the context:\n")
	fmt.Printf("  docker context import %s-managed %s.tar\n", username, username)
}

func cmdUserDelete(username string) {
	s, audit := openStore()
	ctx := context.Background()
	if err := s.DeleteUser(ctx, username); err != nil {
		fatal("delete user: %v", err)
	}
	_ = audit.RecordAudit(ctx, &store.AuditEntry{
		Actor: "cli", Action: store.AuditUserDeleted,
		Resource: "user:" + username, Status: "success",
	})
	fmt.Printf("User deleted: %s\n", username)
}

func cmdUserRegenerateToken(username string) {
	s, audit := openStore()
	ctx := context.Background()

	// Verify user exists.
	if _, err := s.GetUserByUsername(ctx, username); err != nil {
		fatal("user lookup: %v", err)
	}

	token := generateToken()
	if err := s.SetOnboardToken(ctx, username, token); err != nil {
		fatal("set onboard token: %v", err)
	}

	_ = audit.RecordAudit(ctx, &store.AuditEntry{
		Actor: "cli", Action: store.AuditTokenRegenerated,
		Resource: "user:" + username, Status: "success",
	})

	extURL := getExternalURL()
	fmt.Printf("New onboard token for %s: %s\n\n", username, token)
	fmt.Printf("Share this command with the user:\n")
	fmt.Printf("  curl -k %s/api/v1/onboard/%s -o %s.tar\n\n", curlURL(extURL), token, username)
	fmt.Printf("Then import the context:\n")
	fmt.Printf("  docker context import %s-managed %s.tar\n", username, username)
}

func printAuditUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  swcproxy audit ls [--limit N]   List audit log entries (default: 50)
`)
}

func runAuditCommand(subcmd string, args []string) {
	switch subcmd {
	case "ls", "list":
		limit := 50
		for i, a := range args {
			if a == "--limit" && i+1 < len(args) {
				n, err := strconv.Atoi(args[i+1])
				if err != nil {
					fatal("invalid --limit value: %s", args[i+1])
				}
				limit = n
			}
		}
		cmdAuditList(limit)
	case "--help", "-h", "help":
		printAuditUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown audit command: %s\n\n", subcmd)
		printAuditUsage()
		os.Exit(1)
	}
}

func cmdAuditList(limit int) {
	_, audit := openStore()
	entries, err := audit.ListAuditEntries(context.Background(), limit)
	if err != nil {
		fatal("list audit entries: %v", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TIMESTAMP\tACTOR\tACTION\tRESOURCE\tSTATUS\tDETAIL")
	for _, e := range entries {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			e.Timestamp.Format("2006-01-02 15:04:05"),
			e.Actor, e.Action, e.Resource, e.Status, e.Detail)
	}
	_ = w.Flush()
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func isHelpFlag(s string) bool {
	return s == "--help" || s == "-h" || s == "help"
}
