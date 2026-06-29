// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"swarm-rbac-proxy/internal/backup"
	"swarm-rbac-proxy/internal/config"
	"swarm-rbac-proxy/internal/store"
	"swarm-rbac-proxy/internal/version"
)

type backupOpts struct {
	outFile       string
	includeCA     bool
	includeTokens bool
}

type restoreOpts struct {
	inFile string
	force  bool
	caOut  string
}

// parseBackupArgs parses `swcproxy backup` flags.
func parseBackupArgs(args []string) (backupOpts, error) {
	var o backupOpts
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o", "--out":
			if i+1 >= len(args) {
				return o, fmt.Errorf("%s requires a file path", args[i])
			}
			i++
			o.outFile = args[i]
		case "--include-ca":
			o.includeCA = true
		case "--include-tokens":
			o.includeTokens = true
		default:
			return o, fmt.Errorf("unknown flag: %s", args[i])
		}
	}
	return o, nil
}

// parseRestoreArgs parses `swcproxy restore` flags.
func parseRestoreArgs(args []string) (restoreOpts, error) {
	var o restoreOpts
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i", "--in":
			if i+1 >= len(args) {
				return o, fmt.Errorf("%s requires a file path", args[i])
			}
			i++
			o.inFile = args[i]
		case "--force":
			o.force = true
		case "--ca-out":
			if i+1 >= len(args) {
				return o, fmt.Errorf("--ca-out requires a directory path")
			}
			i++
			o.caOut = args[i]
		default:
			return o, fmt.Errorf("unknown flag: %s", args[i])
		}
	}
	return o, nil
}

func printBackupUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  swcproxy backup [-o <file>] [--include-ca] [--include-tokens]
                     Export users + audit log + RBAC roles/bindings as JSON

  -o, --out <file>   Write to file (mode 0600). Without -o, an interactive
                     terminal writes a timestamped file under the default
                     backup dir (<db-dir>/backup, e.g. /data/backup); a piped
                     or redirected stdout streams the JSON instead.
  --include-tokens   Also export pending onboarding tokens. These are bearer
                     credentials (a live token mints a client cert), so they
                     are redacted by default; opt in only for full-fidelity DR.
  --include-ca       Also embed the client CA cert+key (DR bundle). Requires a
                     file destination (-o or the default dir); the CA can mint a
                     cert for ANY user — store the resulting file like a key.
`)
}

// outputMode selects where `swcproxy backup` writes when no explicit -o is set.
type outputMode int

const (
	outputStdout outputMode = iota
	outputFile
	outputDefaultDir
)

// resolveBackupOutput decides the backup destination: an explicit -o always
// wins; otherwise an interactive terminal writes to the default dir (avoiding a
// JSON/CA dump on the tty) while a piped stdout streams the artifact.
func resolveBackupOutput(outFile string, stdoutIsTTY bool) outputMode {
	switch {
	case outFile != "":
		return outputFile
	case stdoutIsTTY:
		return outputDefaultDir
	default:
		return outputStdout
	}
}

func printRestoreUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  swcproxy restore [-i <file>] [--force] [--ca-out <dir>]   Import a backup

  -i, --in <file>     Read from file instead of stdin
  --force             Replace existing users + audit log (DELETE then import)
  --ca-out <dir>      Required when the backup carries CA material: directory
                      to write ca-cert.pem / ca-key.pem (mode 0600)
`)
}

// loadCfg loads proxy config the same way openStore does.
func loadCfg() config.Config {
	cfg, err := config.Load(os.Getenv("PROXY_CONFIG"))
	if err != nil {
		fatal("load config: %v", err)
	}
	return cfg
}

// openBackupStore reuses openStore and asserts the BackupStore capability.
// The SQLite and PostgreSQL backends implement it; the memory backend is
// already rejected by openStore.
func openBackupStore() (store.BackupStore, store.AuditStore) {
	s, _, audit := openStore()
	bs, ok := s.(store.BackupStore)
	if !ok {
		fatal("store backend does not support backup/restore")
	}
	return bs, audit
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func runBackupCommand(args []string) {
	if len(args) > 0 && isHelpFlag(args[0]) {
		printBackupUsage()
		return
	}
	o, err := parseBackupArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
		printBackupUsage()
		os.Exit(1)
	}

	// Resolve the destination up front: --include-ca must never stream the CA
	// private key onto a redirected/piped stdout (it would land at the shell's
	// umask, not the 0600 the file paths guarantee).
	mode := resolveBackupOutput(o.outFile, isTerminal(os.Stdout))
	if o.includeCA && mode == outputStdout {
		fatal("--include-ca requires a file destination (-o <file> or an interactive terminal); refusing to stream the CA private key to stdout")
	}

	ctx := context.Background()
	bs, audit := openBackupStore()

	doc, err := backup.Create(ctx, bs, version.String(), time.Now().UTC(), o.includeTokens)
	if err != nil {
		fatal("%v", err)
	}

	if o.includeCA {
		cfg := loadCfg()
		if cfg.TLSClientCA == "" || cfg.TLSClientCAKey == "" {
			fatal("--include-ca requires PROXY_TLS_CLIENT_CA and PROXY_TLS_CLIENT_CA_KEY to be configured")
		}
		certPEM, err := os.ReadFile(cfg.TLSClientCA)
		if err != nil {
			fatal("read client CA cert: %v", err)
		}
		keyPEM, err := os.ReadFile(cfg.TLSClientCAKey)
		if err != nil {
			fatal("read client CA key: %v", err)
		}
		doc.CA = &backup.CA{CertPEM: string(certPEM), KeyPEM: string(keyPEM)}
		fmt.Fprintln(os.Stderr, "WARNING: this backup embeds the client CA private key — it can mint a")
		fmt.Fprintln(os.Stderr, "         certificate for ANY user, including admins. Protect it like a secret.")
	}

	// Destination: explicit -o wins; otherwise an interactive terminal writes
	// to the default backup dir (so we never dump JSON — or a CA key — onto the
	// tty), while a piped/redirected stdout still streams the artifact.
	var dest string
	switch mode {
	case outputFile:
		data, err := backup.Marshal(doc)
		if err != nil {
			fatal("%v", err)
		}
		if err := os.WriteFile(o.outFile, data, 0o600); err != nil {
			fatal("write %s: %v", o.outFile, err)
		}
		dest = o.outFile
	case outputDefaultDir:
		path, err := backup.WriteToDir(backup.DefaultDir(loadCfg()), doc)
		if err != nil {
			fatal("%v", err)
		}
		dest = path
	default: // outputStdout
		data, err := backup.Marshal(doc)
		if err != nil {
			fatal("%v", err)
		}
		if _, err := os.Stdout.Write(data); err != nil {
			fatal("write stdout: %v", err)
		}
		dest = "stdout"
	}

	_ = audit.RecordAudit(ctx, &store.AuditEntry{
		Actor: "cli", Action: store.AuditBackupExported,
		Resource: "backup", Status: "success",
		Detail: fmt.Sprintf("users=%d audit=%d roles=%d bindings=%d ca=%v tokens=%v",
			len(doc.Users), len(doc.Audit), len(doc.Roles), len(doc.Bindings), o.includeCA, o.includeTokens),
	})

	fmt.Fprintf(os.Stderr, "Backed up %d users, %d audit entries, %d roles and %d bindings to %s\n",
		len(doc.Users), len(doc.Audit), len(doc.Roles), len(doc.Bindings), dest)
	if !o.includeTokens {
		fmt.Fprintln(os.Stderr, "Note: pending onboarding tokens were redacted (use --include-tokens for full-fidelity DR).")
	}
	if doc.CA == nil {
		fmt.Fprintln(os.Stderr, "Note: this backup does NOT contain the client CA. On restore, the same")
		fmt.Fprintln(os.Stderr, "      rbac_client_ca / rbac_client_ca_key secret must be in place, or every")
		fmt.Fprintln(os.Stderr, "      user must be re-onboarded. See docs/backup-restore.md.")
	}
}

func runRestoreCommand(args []string) {
	if len(args) > 0 && isHelpFlag(args[0]) {
		printRestoreUsage()
		return
	}
	o, err := parseRestoreArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
		printRestoreUsage()
		os.Exit(1)
	}

	var raw []byte
	if o.inFile != "" {
		raw, err = os.ReadFile(o.inFile)
		if err != nil {
			fatal("read %s: %v", o.inFile, err)
		}
	} else {
		if isTerminal(os.Stdin) {
			fatal("no input: pipe a backup into stdin or pass -i <file>")
		}
		raw, err = io.ReadAll(os.Stdin)
		if err != nil {
			fatal("read stdin: %v", err)
		}
	}

	var doc backup.Doc
	if err := json.Unmarshal(raw, &doc); err != nil {
		fatal("parse backup: %v", err)
	}
	if doc.Schema != backup.Schema {
		fatal("unrecognised backup schema %q (want %q)", doc.Schema, backup.Schema)
	}
	if doc.Version != backup.Version {
		fatal("unsupported backup version %d (want %d)", doc.Version, backup.Version)
	}
	// Fail fast before touching the store: a DR bundle is useless without a
	// destination for the CA, and re-running after a partial import would
	// then require --force.
	if doc.CA != nil && o.caOut == "" {
		fatal("backup contains CA material: pass --ca-out <dir> to extract it")
	}
	// Prepare the CA-out destination before mutating the store, so a bad path
	// fails here rather than after the import leaves a half-restored DB.
	if doc.CA != nil {
		if err := os.MkdirAll(o.caOut, 0o700); err != nil {
			fatal("create --ca-out dir %s: %v", o.caOut, err)
		}
	}

	ctx := context.Background()
	bs, audit := openBackupStore()

	existing, err := bs.Export(ctx)
	if err != nil {
		fatal("inspect existing store: %v", err)
	}
	if len(existing.Users) > 0 && !o.force {
		fatal("store already has %d users; pass --force to replace them", len(existing.Users))
	}

	// One transaction across users, audit, roles and bindings: a failure leaves
	// the store untouched rather than half-restored.
	if err := bs.Restore(ctx, backup.ToData(&doc), o.force); err != nil {
		fatal("restore: %v", err)
	}

	_ = audit.RecordAudit(ctx, &store.AuditEntry{
		Actor: "cli", Action: store.AuditBackupRestored,
		Resource: "backup", Status: "success",
		Detail: fmt.Sprintf("users=%d audit=%d roles=%d bindings=%d ca=%v force=%v",
			len(doc.Users), len(doc.Audit), len(doc.Roles), len(doc.Bindings), doc.CA != nil, o.force),
	})

	fmt.Fprintf(os.Stderr, "Restored %d users, %d audit entries, %d roles and %d bindings\n",
		len(doc.Users), len(doc.Audit), len(doc.Roles), len(doc.Bindings))

	cfg := loadCfg()
	if doc.CA != nil {
		certPath := filepath.Join(o.caOut, "ca-cert.pem")
		keyPath := filepath.Join(o.caOut, "ca-key.pem")
		if err := os.WriteFile(certPath, []byte(doc.CA.CertPEM), 0o600); err != nil {
			fatal("write %s: %v", certPath, err)
		}
		if err := os.WriteFile(keyPath, []byte(doc.CA.KeyPEM), 0o600); err != nil {
			fatal("write %s: %v", keyPath, err)
		}
		fmt.Fprintf(os.Stderr, "\nClient CA written to %s and %s.\n", certPath, keyPath)
		fmt.Fprintln(os.Stderr, "Recreate the Swarm secrets and redeploy so existing user contexts keep working:")
		fmt.Fprintf(os.Stderr, "  docker secret rm rbac_client_ca rbac_client_ca_key\n")
		fmt.Fprintf(os.Stderr, "  docker secret create rbac_client_ca %s\n", certPath)
		fmt.Fprintf(os.Stderr, "  docker secret create rbac_client_ca_key %s\n", keyPath)
		fmt.Fprintf(os.Stderr, "  docker stack deploy -c stack.yml rbac\n")

		if cfg.TLSClientCA != "" {
			if cur, rerr := os.ReadFile(cfg.TLSClientCA); rerr == nil {
				if string(cur) == doc.CA.CertPEM {
					fmt.Fprintln(os.Stderr, "Preflight: the running deployment already uses this CA — user contexts are unaffected.")
				} else {
					fmt.Fprintln(os.Stderr, "Preflight WARNING: the running deployment uses a DIFFERENT client CA.")
					fmt.Fprintln(os.Stderr, "          Existing user contexts will fail mTLS until the CA above is deployed.")
				}
			}
		}
	} else {
		fmt.Fprintln(os.Stderr, "\nThis backup does NOT contain the client CA. Existing user contexts only keep")
		fmt.Fprintln(os.Stderr, "working if the same rbac_client_ca / rbac_client_ca_key secret is in place;")
		fmt.Fprintln(os.Stderr, "otherwise every user must be re-onboarded. See docs/backup-restore.md.")
	}
}
