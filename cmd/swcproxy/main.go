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
	"swarm-rbac-proxy/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println(version.String())
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
	case "role":
		if len(os.Args) < 3 {
			printRoleUsage()
			os.Exit(1)
		}
		runRoleCommand(os.Args[2], os.Args[3:])
	case "binding":
		if len(os.Args) < 3 {
			printBindingUsage()
			os.Exit(1)
		}
		runBindingCommand(os.Args[2], os.Args[3:])
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
  swcproxy version                         Show version
  swcproxy user ls                         List users
  swcproxy user add <username> [--admin]   Create user + onboarding token
  swcproxy user delete <username>          Delete user
  swcproxy user regenerate-token <username> Regenerate onboarding token
  swcproxy audit ls [--limit N]            List audit log entries (default: 50)
  swcproxy role ls                         List roles
  swcproxy role show <name>                Show a role's rules
  swcproxy binding ls                      List role bindings
  swcproxy binding add <user> <role>       Bind a user to a role
  swcproxy binding rm <id>                 Remove a role binding
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

func openStore() (store.UserStore, store.RBACStore, store.AuditStore) {
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
		return s, s, s
	case "postgres":
		if cfg.DatabaseURL == "" {
			fatal("database_url is required for postgres store")
		}
		s, err := store.NewPostgresStore(ctx, cfg.DatabaseURL)
		if err != nil {
			fatal("open postgres: %v", err)
		}
		return s, s, s
	case "memory":
		fatal("swcproxy cannot use in-memory store (data not shared with proxy process)")
	default:
		fatal("unknown store type: %s", cfg.Store)
	}
	return nil, nil, nil
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
	s, _, _ := openStore()
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
	s, rbac, audit := openStore()
	ctx := context.Background()

	role := "user"
	if admin {
		role = "admin"
	}

	u := &store.User{Username: username, Role: role}
	if err := s.CreateUser(ctx, u); err != nil {
		fatal("create user: %v", err)
	}

	// Keep the RBAC binding in sync with the legacy role: admin → admin,
	// otherwise → viewer. Best-effort (roles are seeded by the proxy at
	// startup; if absent the binding is skipped and can be added later).
	bindRole := store.RoleViewer
	if admin {
		bindRole = store.RoleAdmin
	}
	if err := rbac.CreateBinding(ctx, &store.RoleBinding{Username: username, RoleName: bindRole}); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not bind %s to role %s: %v\n", username, bindRole, err)
	}

	token := generateToken()
	if err := s.SetOnboardToken(ctx, username, token); err != nil {
		fatal("set onboard token: %v", err)
	}

	_ = audit.RecordAudit(ctx, &store.AuditEntry{
		Actor: "cli", Action: store.AuditUserCreated,
		Resource: "user:" + username, Status: "success",
		Detail: "role:" + role,
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
	s, _, audit := openStore()
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
	s, _, audit := openStore()
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
	_, _, audit := openStore()
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

func printRoleUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  swcproxy role ls            List roles
  swcproxy role show <name>   Show a role's rules
`)
}

func runRoleCommand(subcmd string, args []string) {
	switch subcmd {
	case "ls", "list":
		cmdRoleList()
	case "show", "get":
		if len(args) < 1 || isHelpFlag(args[0]) {
			printRoleUsage()
			if len(args) < 1 {
				os.Exit(1)
			}
			return
		}
		cmdRoleShow(args[0])
	case "--help", "-h", "help":
		printRoleUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown role command: %s\n\n", subcmd)
		printRoleUsage()
		os.Exit(1)
	}
}

func cmdRoleList() {
	_, rbac, _ := openStore()
	roles, err := rbac.ListRoles(context.Background())
	if err != nil {
		fatal("list roles: %v", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tBUILTIN\tRULES")
	for _, r := range roles {
		_, _ = fmt.Fprintf(w, "%s\t%v\t%d\n", r.Name, r.Builtin, len(r.Rules))
	}
	_ = w.Flush()
}

func cmdRoleShow(name string) {
	_, rbac, _ := openStore()
	r, err := rbac.GetRole(context.Background(), name)
	if err != nil {
		fatal("get role: %v", err)
	}
	fmt.Printf("Role: %s (builtin: %v)\n", r.Name, r.Builtin)
	for _, rule := range r.Rules {
		fmt.Printf("  resources=%s verbs=%s\n",
			strings.Join(rule.Resources, ","), strings.Join(rule.Verbs, ","))
	}
}

func printBindingUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  swcproxy binding ls                List role bindings
  swcproxy binding add <user> <role> Bind a user to a role
  swcproxy binding rm <id>           Remove a role binding
`)
}

func runBindingCommand(subcmd string, args []string) {
	switch subcmd {
	case "ls", "list":
		cmdBindingList()
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: swcproxy binding add <user> <role>")
			os.Exit(1)
		}
		cmdBindingAdd(args[0], args[1])
	case "rm", "delete":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: swcproxy binding rm <id>")
			os.Exit(1)
		}
		cmdBindingRemove(args[0])
	case "--help", "-h", "help":
		printBindingUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown binding command: %s\n\n", subcmd)
		printBindingUsage()
		os.Exit(1)
	}
}

func cmdBindingList() {
	_, rbac, _ := openStore()
	bindings, err := rbac.ListBindings(context.Background())
	if err != nil {
		fatal("list bindings: %v", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tUSER\tROLE\tCREATED")
	for _, b := range bindings {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", b.ID, b.Username, b.RoleName, b.CreatedAt.Format("2006-01-02 15:04"))
	}
	_ = w.Flush()
}

func cmdBindingAdd(username, roleName string) {
	users, rbac, audit := openStore()
	ctx := context.Background()
	if _, err := users.GetUserByUsername(ctx, username); err != nil {
		fatal("user lookup: %v", err)
	}
	b := &store.RoleBinding{Username: username, RoleName: roleName}
	if err := rbac.CreateBinding(ctx, b); err != nil {
		fatal("create binding: %v", err)
	}
	_ = audit.RecordAudit(ctx, &store.AuditEntry{
		Actor: "cli", Action: store.AuditBindingCreated,
		Resource: "binding:" + username + "/" + roleName, Status: "success",
	})
	fmt.Printf("Bound %s to role %s (id: %s)\n", username, roleName, b.ID)
}

func cmdBindingRemove(id string) {
	users, rbac, audit := openStore()
	ctx := context.Background()
	if err := store.DeleteBindingChecked(ctx, users, rbac, id); err != nil {
		fatal("remove binding: %v", err)
	}
	_ = audit.RecordAudit(ctx, &store.AuditEntry{
		Actor: "cli", Action: store.AuditBindingDeleted,
		Resource: "binding:" + id, Status: "success",
	})
	fmt.Printf("Binding removed: %s\n", id)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func isHelpFlag(s string) bool {
	return s == "--help" || s == "-h" || s == "help"
}
