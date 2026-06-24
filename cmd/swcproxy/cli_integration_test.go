// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

//go:build integration

// End-to-end tests for the `swcproxy backup` / `restore` commands. These drive
// the real CLI entrypoint as a subprocess (see TestMain) against a temporary
// SQLite store, so they exercise everything the store-level contract tests do
// not: flag dispatch, the JSON artifact + schema/version stamping, the restore
// validation and non-empty-store guards, --include-ca embedding, --ca-out
// extraction + the CA-match preflight, audit recording, file modes, stdin/stdout
// handling, and process exit codes.
//
// They run under the `integration` build tag (alongside the PostgreSQL store
// tests) so the fast `go test -race ./...` job stays free of the subprocess
// re-exec cost. No PostgreSQL is required — the backend here is SQLite.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"swarm-rbac-proxy/internal/backup"
	"swarm-rbac-proxy/internal/store"
)

// TestMain doubles as the swcproxy entrypoint: when SWC_TEST_RUN_MAIN=1 the
// process runs the real main() (consuming os.Args, which runCLI sets) and
// exits, instead of running the test suite. This lets runCLI re-exec this same
// (race-instrumented) binary as the CLI without a separate `go build`.
func TestMain(m *testing.M) {
	if os.Getenv("SWC_TEST_RUN_MAIN") == "1" {
		main()     // calls os.Exit on the fatal/error paths
		os.Exit(0) // reached only when the command succeeds
	}
	os.Exit(m.Run())
}

// runCLI re-execs the test binary as `swcproxy <args...>` with a controlled
// environment (all ambient PROXY_* vars stripped, then env applied) and the
// given stdin, returning captured stdout, stderr and the process exit code.
func runCLI(t *testing.T, env map[string]string, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)

	clean := make([]string, 0, len(os.Environ())+len(env)+1)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "PROXY_") || strings.HasPrefix(kv, "SWC_TEST_RUN_MAIN=") {
			continue
		}
		clean = append(clean, kv)
	}
	clean = append(clean, "SWC_TEST_RUN_MAIN=1")
	for k, v := range env {
		clean = append(clean, k+"="+v)
	}
	cmd.Env = clean
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	switch e := err.(type) {
	case nil:
		code = 0
	case *exec.ExitError:
		code = e.ExitCode()
	default:
		t.Fatalf("exec swcproxy %v: %v", args, err)
	}
	return so.String(), se.String(), code
}

// baseEnv is the minimal env for a SQLite-backed swcproxy invocation.
func baseEnv(dbPath string) map[string]string {
	return map[string]string{
		"PROXY_STORE":         "sqlite",
		"PROXY_DATABASE_PATH": dbPath,
		"PROXY_ENV":           "dev",
	}
}

func dbPath(t *testing.T) string { return filepath.Join(t.TempDir(), "proxy.db") }

// seedUsers populates a fresh SQLite store and closes it so the CLI subprocess
// can open the file. The second user is given an onboarding token so the
// token columns (which ListUsers/the API omit) are exercised by the round-trip.
func seedUsers(t *testing.T, path string, usernames ...string) {
	t.Helper()
	ctx := context.Background()
	s, err := store.NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("seed: open store: %v", err)
	}
	for i, u := range usernames {
		role := "user"
		if i == 0 {
			role = "admin"
		}
		if err := s.CreateUser(ctx, &store.User{Username: u, Role: role, Enabled: true}); err != nil {
			t.Fatalf("seed: create %s: %v", u, err)
		}
		if i == 1 {
			if err := s.SetOnboardToken(ctx, u, "tok-"+u); err != nil {
				t.Fatalf("seed: token %s: %v", u, err)
			}
		}
	}
	s.Close()
}

// storeUserCount opens the store read-only-ish and counts users.
func storeUserCount(t *testing.T, path string) int {
	t.Helper()
	ctx := context.Background()
	s, err := store.NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("count: open store: %v", err)
	}
	defer s.Close()
	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("count: list: %v", err)
	}
	return len(users)
}

// hasAudit reports whether the store recorded an entry with the given action.
func hasAudit(t *testing.T, path string, action store.AuditAction) bool {
	t.Helper()
	ctx := context.Background()
	s, err := store.NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("audit: open store: %v", err)
	}
	defer s.Close()
	entries, err := s.ListAuditEntries(ctx, 1000)
	if err != nil {
		t.Fatalf("audit: list: %v", err)
	}
	for _, e := range entries {
		if e.Action == action {
			return true
		}
	}
	return false
}

func readBackup(t *testing.T, path string) backup.Doc {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read backup %s: %v", path, err)
	}
	var doc backup.Doc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal backup %s: %v", path, err)
	}
	return doc
}

// genCA writes a throwaway ECDSA CA cert+key (PEM, mode 0600) under dir and
// returns the two paths plus the cert PEM bytes.
func genCA(t *testing.T, dir, cn string) (certPath, keyPath string, certPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genCA key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("genCA serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("genCA cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("genCA key marshal: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath = filepath.Join(dir, cn+"-cert.pem")
	keyPath = filepath.Join(dir, cn+"-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("genCA write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("genCA write key: %v", err)
	}
	return certPath, keyPath, certPEM
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// ---------------------------------------------------------------------------
// backup
// ---------------------------------------------------------------------------

func TestCLIBackup_ToFile_ValidAnd0600(t *testing.T) {
	db := dbPath(t)
	seedUsers(t, db, "alice", "bob", "carol")
	out := filepath.Join(t.TempDir(), "backup.json")

	stdout, stderr, code := runCLI(t, baseEnv(db), "", "backup", "-o", out)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	// stdout is reserved for command output; with -o there is none (the artifact
	// goes to the file and logs go to stderr).
	if stdout != "" {
		t.Errorf("expected empty stdout with -o, got %q", stdout)
	}
	if !strings.Contains(stderr, "Backed up 3 users") {
		t.Errorf("missing summary on stderr: %q", stderr)
	}
	if got := mode(t, out); got != 0o600 {
		t.Errorf("file mode = %o, want 600", got)
	}

	doc := readBackup(t, out)
	if doc.Schema != backup.Schema || doc.Version != backup.Version {
		t.Errorf("schema/version = %q/%d", doc.Schema, doc.Version)
	}
	if len(doc.Users) != 3 {
		t.Fatalf("got %d users, want 3", len(doc.Users))
	}
	if doc.CA != nil {
		t.Errorf("CA must be absent without --include-ca")
	}
	// bob (index 1) was given a token; it must survive the export.
	var bob *backup.User
	for i := range doc.Users {
		if doc.Users[i].Username == "bob" {
			bob = &doc.Users[i]
		}
	}
	if bob == nil || bob.OnboardToken == "" || bob.TokenIssuedAt == nil {
		t.Errorf("bob token not exported: %+v", bob)
	}
	if !hasAudit(t, db, store.AuditBackupExported) {
		t.Errorf("backup.exported not audited")
	}
}

func TestCLIBackup_EmptyStore(t *testing.T) {
	db := dbPath(t)
	seedUsers(t, db) // creates the schema, no users
	out := filepath.Join(t.TempDir(), "empty.json")

	_, stderr, code := runCLI(t, baseEnv(db), "", "backup", "-o", out)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if doc := readBackup(t, out); len(doc.Users) != 0 {
		t.Errorf("got %d users, want 0", len(doc.Users))
	}
}

func TestCLIBackup_IncludeCA(t *testing.T) {
	db := dbPath(t)
	seedUsers(t, db, "alice")
	caDir := t.TempDir()
	certPath, keyPath, certPEM := genCA(t, caDir, "ca")
	out := filepath.Join(t.TempDir(), "dr.json")

	env := baseEnv(db)
	env["PROXY_TLS_CLIENT_CA"] = certPath
	env["PROXY_TLS_CLIENT_CA_KEY"] = keyPath

	_, stderr, code := runCLI(t, env, "", "backup", "--include-ca", "-o", out)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "WARNING") || !strings.Contains(stderr, "CA private key") {
		t.Errorf("missing CA warning on stderr: %q", stderr)
	}
	doc := readBackup(t, out)
	if doc.CA == nil {
		t.Fatalf("CA block absent")
	}
	if doc.CA.CertPEM != string(certPEM) {
		t.Errorf("embedded cert != source cert")
	}
	if !strings.HasPrefix(doc.CA.KeyPEM, "-----BEGIN EC PRIVATE KEY-----") {
		t.Errorf("embedded key not PEM: %.40q", doc.CA.KeyPEM)
	}
}

func TestCLIBackup_IncludeCA_MissingEnv(t *testing.T) {
	db := dbPath(t)
	seedUsers(t, db, "alice")
	caDir := t.TempDir()
	certPath, _, _ := genCA(t, caDir, "ca")
	out := filepath.Join(t.TempDir(), "x.json")

	env := baseEnv(db)
	env["PROXY_TLS_CLIENT_CA"] = certPath // key intentionally absent

	_, stderr, code := runCLI(t, env, "", "backup", "--include-ca", "-o", out)
	if code != 1 {
		t.Fatalf("exit=%d, want 1; stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "requires PROXY_TLS_CLIENT_CA and PROXY_TLS_CLIENT_CA_KEY") {
		t.Errorf("unexpected stderr: %q", stderr)
	}
}

func TestCLIBackup_MemoryStoreRejected(t *testing.T) {
	env := baseEnv(dbPath(t))
	env["PROXY_STORE"] = "memory"
	_, stderr, code := runCLI(t, env, "", "backup", "-o", filepath.Join(t.TempDir(), "x.json"))
	if code != 1 {
		t.Fatalf("exit=%d, want 1; stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "in-memory store") {
		t.Errorf("unexpected stderr: %q", stderr)
	}
}

// TestCLIBackup_StdoutIsValidJSON verifies that `swcproxy backup` (no -o) writes
// only the JSON artifact to stdout — logs go to stderr — so a shell redirect
// (`swcproxy backup > file.json`) yields a valid backup.
func TestCLIBackup_StdoutIsValidJSON(t *testing.T) {
	db := dbPath(t)
	seedUsers(t, db, "alice")

	stdout, stderr, code := runCLI(t, baseEnv(db), "", "backup")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if !json.Valid([]byte(stdout)) {
		t.Fatalf("stdout is not valid JSON:\n%.200q", stdout)
	}
	if strings.Contains(stdout, "store initialized") {
		t.Errorf("log line leaked onto stdout: %.120q", stdout)
	}
	var doc backup.Doc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("unmarshal stdout: %v", err)
	}
	if doc.Schema != backup.Schema || len(doc.Users) != 1 {
		t.Errorf("unexpected doc: schema=%q users=%d", doc.Schema, len(doc.Users))
	}
	// The diagnostic line must still be emitted — on stderr.
	if !strings.Contains(stderr, "store initialized") {
		t.Errorf("expected store-init log on stderr, got %q", stderr)
	}
}

// ---------------------------------------------------------------------------
// restore
// ---------------------------------------------------------------------------

func TestCLIRestore_RoundTripVerbatim(t *testing.T) {
	srcDB := dbPath(t)
	seedUsers(t, srcDB, "alice", "bob", "carol")
	fileA := filepath.Join(t.TempDir(), "a.json")
	if _, stderr, code := runCLI(t, baseEnv(srcDB), "", "backup", "-o", fileA); code != 0 {
		t.Fatalf("backup A exit=%d stderr=%q", code, stderr)
	}

	dstDB := dbPath(t)
	seedUsers(t, dstDB) // schema only, empty
	_, stderr, code := runCLI(t, baseEnv(dstDB), "", "restore", "-i", fileA)
	if code != 0 {
		t.Fatalf("restore exit=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "Restored 3 users") {
		t.Errorf("missing restore summary: %q", stderr)
	}
	if !hasAudit(t, dstDB, store.AuditBackupRestored) {
		t.Errorf("backup.restored not audited")
	}

	fileB := filepath.Join(t.TempDir(), "b.json")
	if _, stderr, code := runCLI(t, baseEnv(dstDB), "", "backup", "-o", fileB); code != 0 {
		t.Fatalf("backup B exit=%d stderr=%q", code, stderr)
	}
	a, b := readBackup(t, fileA), readBackup(t, fileB)
	if !reflect.DeepEqual(a.Users, b.Users) {
		t.Errorf("users not verbatim after round-trip:\n A=%+v\n B=%+v", a.Users, b.Users)
	}
}

func TestCLIRestore_NonEmptyRefusedWithoutForce(t *testing.T) {
	srcDB := dbPath(t)
	seedUsers(t, srcDB, "alice", "bob", "carol")
	file := filepath.Join(t.TempDir(), "a.json")
	runCLI(t, baseEnv(srcDB), "", "backup", "-o", file)

	dstDB := dbPath(t)
	seedUsers(t, dstDB, "existing") // 1 user
	_, stderr, code := runCLI(t, baseEnv(dstDB), "", "restore", "-i", file)
	if code != 1 {
		t.Fatalf("exit=%d, want 1; stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "store already has 1 users; pass --force") {
		t.Errorf("unexpected stderr: %q", stderr)
	}
	if n := storeUserCount(t, dstDB); n != 1 {
		t.Errorf("store mutated: %d users, want 1", n)
	}
}

func TestCLIRestore_Force(t *testing.T) {
	srcDB := dbPath(t)
	seedUsers(t, srcDB, "alice", "bob", "carol")
	file := filepath.Join(t.TempDir(), "a.json")
	runCLI(t, baseEnv(srcDB), "", "backup", "-o", file)

	dstDB := dbPath(t)
	seedUsers(t, dstDB, "old1", "old2") // 2 users to be replaced
	_, stderr, code := runCLI(t, baseEnv(dstDB), "", "restore", "-i", file, "--force")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if n := storeUserCount(t, dstDB); n != 3 {
		t.Errorf("after --force: %d users, want 3", n)
	}
}

func TestCLIRestore_FromStdin(t *testing.T) {
	srcDB := dbPath(t)
	seedUsers(t, srcDB, "alice", "bob", "carol")
	file := filepath.Join(t.TempDir(), "a.json")
	runCLI(t, baseEnv(srcDB), "", "backup", "-o", file)
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	dstDB := dbPath(t)
	seedUsers(t, dstDB)
	_, stderr, code := runCLI(t, baseEnv(dstDB), string(data), "restore")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if n := storeUserCount(t, dstDB); n != 3 {
		t.Errorf("stdin restore: %d users, want 3", n)
	}
}

func TestCLIRestore_ValidationGuards(t *testing.T) {
	srcDB := dbPath(t)
	seedUsers(t, srcDB, "alice")
	good := filepath.Join(t.TempDir(), "good.json")
	runCLI(t, baseEnv(srcDB), "", "backup", "-o", good)
	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}

	tamper := func(mut func(m map[string]any)) string {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		mut(m)
		b, _ := json.Marshal(m)
		p := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cases := []struct {
		name, file, wantErr string
	}{
		{"BadSchema", tamper(func(m map[string]any) { m["schema"] = "evil" }), "unrecognised backup schema"},
		{"BadVersion", tamper(func(m map[string]any) { m["version"] = 99 }), "unsupported backup version"},
	}
	// Malformed JSON is a separate non-JSON file.
	malformed := filepath.Join(t.TempDir(), "malformed.json")
	if err := os.WriteFile(malformed, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases = append(cases, struct{ name, file, wantErr string }{"Malformed", malformed, "parse backup"})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dstDB := dbPath(t)
			seedUsers(t, dstDB) // empty
			_, stderr, code := runCLI(t, baseEnv(dstDB), "", "restore", "-i", tc.file)
			if code != 1 {
				t.Fatalf("exit=%d, want 1; stderr=%q", code, stderr)
			}
			if !strings.Contains(stderr, tc.wantErr) {
				t.Errorf("stderr = %q, want substring %q", stderr, tc.wantErr)
			}
			if n := storeUserCount(t, dstDB); n != 0 {
				t.Errorf("guard wrote to store: %d users, want 0", n)
			}
		})
	}
}

// makeDRBundle seeds a store, generates a CA, and writes a --include-ca backup,
// returning the bundle path and the CA cert path/PEM.
func makeDRBundle(t *testing.T) (bundle, certPath string, certPEM []byte) {
	t.Helper()
	srcDB := dbPath(t)
	seedUsers(t, srcDB, "alice", "bob", "carol")
	caDir := t.TempDir()
	cp, kp, pemb := genCA(t, caDir, "ca")
	bundle = filepath.Join(t.TempDir(), "dr.json")
	env := baseEnv(srcDB)
	env["PROXY_TLS_CLIENT_CA"] = cp
	env["PROXY_TLS_CLIENT_CA_KEY"] = kp
	if _, stderr, code := runCLI(t, env, "", "backup", "--include-ca", "-o", bundle); code != 0 {
		t.Fatalf("make DR bundle exit=%d stderr=%q", code, stderr)
	}
	return bundle, cp, pemb
}

func TestCLIRestore_CABundle_RequiresCaOut(t *testing.T) {
	bundle, _, _ := makeDRBundle(t)
	dstDB := dbPath(t)
	seedUsers(t, dstDB)

	_, stderr, code := runCLI(t, baseEnv(dstDB), "", "restore", "-i", bundle)
	if code != 1 {
		t.Fatalf("exit=%d, want 1; stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "pass --ca-out") {
		t.Errorf("unexpected stderr: %q", stderr)
	}
	if n := storeUserCount(t, dstDB); n != 0 {
		t.Errorf("fail-fast violated: %d users imported, want 0", n)
	}
}

func TestCLIRestore_CABundle_ExtractAndPreflightMatch(t *testing.T) {
	bundle, certPath, certPEM := makeDRBundle(t)
	dstDB := dbPath(t)
	seedUsers(t, dstDB)
	caOut := t.TempDir()

	env := baseEnv(dstDB)
	env["PROXY_TLS_CLIENT_CA"] = certPath // running deployment uses the bundled CA

	_, stderr, code := runCLI(t, env, "", "restore", "-i", bundle, "--ca-out", caOut)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if n := storeUserCount(t, dstDB); n != 3 {
		t.Errorf("got %d users, want 3", n)
	}
	certOut := filepath.Join(caOut, "ca-cert.pem")
	keyOut := filepath.Join(caOut, "ca-key.pem")
	if got := mode(t, certOut); got != 0o600 {
		t.Errorf("ca-cert.pem mode = %o, want 600", got)
	}
	if got := mode(t, keyOut); got != 0o600 {
		t.Errorf("ca-key.pem mode = %o, want 600", got)
	}
	if got, _ := os.ReadFile(certOut); string(got) != string(certPEM) {
		t.Errorf("extracted cert != bundled cert")
	}
	if !strings.Contains(stderr, "docker secret create") {
		t.Errorf("missing secret-recreate runbook: %q", stderr)
	}
	if !strings.Contains(stderr, "already uses this CA") {
		t.Errorf("missing preflight-match line: %q", stderr)
	}
}

func TestCLIRestore_CABundle_PreflightMismatch(t *testing.T) {
	bundle, _, _ := makeDRBundle(t)
	dstDB := dbPath(t)
	seedUsers(t, dstDB)
	caOut := t.TempDir()

	otherCert, _, _ := genCA(t, t.TempDir(), "other")
	env := baseEnv(dstDB)
	env["PROXY_TLS_CLIENT_CA"] = otherCert // running deployment uses a DIFFERENT CA

	_, stderr, code := runCLI(t, env, "", "restore", "-i", bundle, "--ca-out", caOut)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "Preflight WARNING") || !strings.Contains(stderr, "DIFFERENT client CA") {
		t.Errorf("missing preflight-mismatch warning: %q", stderr)
	}
}

// TestCLIRestore_CaOutDirAutoCreated verifies that a non-existent --ca-out
// directory is created (mode 0700) before the import, so a DR restore into a
// fresh path succeeds atomically rather than leaving a half-restored DB.
func TestCLIRestore_CaOutDirAutoCreated(t *testing.T) {
	bundle, certPath, _ := makeDRBundle(t)
	dstDB := dbPath(t)
	seedUsers(t, dstDB)

	env := baseEnv(dstDB)
	env["PROXY_TLS_CLIENT_CA"] = certPath
	missing := filepath.Join(t.TempDir(), "made", "by", "restore")

	_, stderr, code := runCLI(t, env, "", "restore", "-i", bundle, "--ca-out", missing)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	if n := storeUserCount(t, dstDB); n != 3 {
		t.Errorf("got %d users, want 3", n)
	}
	if got := mode(t, filepath.Join(missing, "ca-cert.pem")); got != 0o600 {
		t.Errorf("ca-cert.pem mode = %o, want 600", got)
	}
	if got := mode(t, filepath.Join(missing, "ca-key.pem")); got != 0o600 {
		t.Errorf("ca-key.pem mode = %o, want 600", got)
	}
}

// ---------------------------------------------------------------------------
// flag / usage handling at the CLI boundary
// ---------------------------------------------------------------------------

func TestCLIFlagAndUsageHandling(t *testing.T) {
	db := dbPath(t)
	seedUsers(t, db, "alice")
	env := baseEnv(db)

	cases := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"BackupUnknownFlag", []string{"backup", "--nope"}, 1, "unknown flag"},
		{"RestoreUnknownFlag", []string{"restore", "--nope"}, 1, "unknown flag"},
		{"BackupMissingOutArg", []string{"backup", "-o"}, 1, "requires a file path"},
		{"RestoreMissingCaOutArg", []string{"restore", "--ca-out"}, 1, "requires a directory path"},
		{"BackupHelp", []string{"backup", "--help"}, 0, ""},
		{"RestoreHelp", []string{"restore", "-h"}, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, code := runCLI(t, env, "", tc.args...)
			if code != tc.wantCode {
				t.Fatalf("exit=%d, want %d; stderr=%q", code, tc.wantCode, stderr)
			}
			if tc.wantErr != "" && !strings.Contains(stderr, tc.wantErr) {
				t.Errorf("stderr = %q, want substring %q", stderr, tc.wantErr)
			}
		})
	}
}
