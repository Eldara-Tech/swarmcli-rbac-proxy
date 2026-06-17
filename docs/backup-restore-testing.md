# Manual test guide — `swcproxy backup` / `restore`

A step-by-step QA checklist for the logical backup/restore feature
(`cmd/swcproxy/backup.go`). It exercises every branch a reviewer can reach by
hand: routine export, the `--include-ca` DR bundle, schema/version guards, the
non-empty-store guard, verbatim round-trips, CA extraction, the CA-match
preflight, and cross-backend portability.

The automated coverage lives in `internal/store/contract_test.go`
(`testBackupStoreContract`) and `cmd/swcproxy/main_test.go` (flag parsing).
This guide is the manual layer on top — run it before tagging a release that
touches backup/restore, or when reviewing PR #107.

## 0. Conventions

- `$` is your shell. Output shown is **expected**; deviations are failures.
- Human messages and fatal errors go to **stderr**, prefixed `error: ` on the
  failure path. Exit code `0` = success, `1` = failure — check `echo $?`
  whenever a step is expected to fail.
- **Use `-o <file>` to capture the artifact, not `> file`.** `openStore()`
  emits a `store initialized` INFO line on **stdout** before the JSON is
  written, so `swcproxy backup > file.json` produces a file with a log line
  prepended (invalid JSON). `-o` writes the file directly via `os.WriteFile`
  and is always clean. See the Known issue below — this guide uses `-o`
  throughout.

> ### ⚠️ Known issue — stdout redirect corrupts the artifact
> `swcproxy backup > backup.json` yields invalid JSON because the store's
> `store initialized` INFO line lands on stdout before the JSON (reproduces in
> both `PROXY_ENV=dev` and prod). Note `docs/backup-restore.md` § "Routine
> backup" still shows the `>` form. Until the CLI routes logs to stderr (or
> silences info-level logging), **always use `-o`.**

## 1. Local setup (SQLite, no Docker/Swarm needed)

Most cases run against the default SQLite backend in a scratch directory — no
proxy process, Swarm, or mTLS required. `swcproxy` talks to the store directly.

```bash
cd swarmcli-rbac-proxy
go build -o /tmp/swcproxy ./cmd/swcproxy

# Isolated scratch store. swcproxy reads the same config/env as the proxy.
export WORK=$(mktemp -d)
export PROXY_STORE=sqlite
export PROXY_DATABASE_PATH="$WORK/proxy.db"
export PROXY_ENV=dev
alias swc="/tmp/swcproxy"

# Seed a few users (each also creates a matching RBAC binding).
swc user add alice --admin
swc user add bob
swc user add carol
swc user ls          # confirm 3 users, alice=admin
swc audit ls         # confirm user.created / cert.issued entries exist
```

> Tip: to start over at any point, `rm -f "$PROXY_DATABASE_PATH"*` (the `*`
> clears the WAL/SHM sidecars too) and re-seed.

---

## 2. Routine backup (database only)

### 2.1 Backup to a file (canonical artifact for later steps)

```bash
swc backup -o "$WORK/backup.json"
```

Expected:
- stderr: `Backed up 3 users and N audit entries to $WORK/backup.json`
- stderr: the three-line "this backup does NOT contain the client CA" note.
- `$WORK/backup.json` is valid JSON. Verify:

```bash
jq '.schema, .version, (.users|length), (.ca==null)' "$WORK/backup.json"
# "swarmcli-rbac-proxy/backup"
# 1
# 3
# true
```

- Each user object carries `onboard_token` and `token_issued_at` (these are
  exported even though `swcproxy user ls` / the API hide them):

```bash
jq '.users[0] | {username, role, has_token: (.onboard_token|length>0)}' "$WORK/backup.json"
```

### 2.2 File mode is 0600, and confirm the stdout-redirect corruption

```bash
swc backup -o "$WORK/backup-o.json"
stat -c '%a' "$WORK/backup-o.json"   # 600

# Demonstrate the Known issue: a redirected backup is NOT valid JSON.
swc backup > "$WORK/redir.json" 2>/dev/null
head -c 40 "$WORK/redir.json"; echo
jq -e . "$WORK/redir.json" >/dev/null 2>&1 && echo "valid (unexpected!)" || echo "INVALID JSON (expected — use -o)"
```

Expected: `-o` file mode is `600`; the redirected file begins with a
`store initialized` log line (console-formatted under `PROXY_ENV=dev`, a
`{"level":"INFO",...}` JSON line in prod) and `jq` reports
`INVALID JSON (expected — use -o)`.

### 2.3 The export is audited

```bash
swc audit ls | grep backup.exported
```

Expected: a `backup.exported` row, actor `cli`, detail like
`users=3 audit=N ca=false`.

---

## 3. Restore round-trip (verbatim)

### 3.1 Guard: restore refuses a non-empty store

```bash
swc restore -i "$WORK/backup.json"; echo "exit=$?"
```

Expected: `error: store already has 3 users; pass --force to replace them`,
`exit=1`, store untouched.

### 3.2 Restore into a fresh store

```bash
export PROXY_DATABASE_PATH="$WORK/restored.db"
swc restore -i "$WORK/backup.json"
swc user ls
```

Expected: `Restored 3 users and N audit entries`, and `user ls` shows the same
three users. The trailing stderr note explains the CA caveat.

### 3.3 Verbatim check — IDs and timestamps preserved

Re-export the restored store and diff the user set against the original. IDs,
roles, timestamps and token state must be byte-identical (order is by
`created_at`).

```bash
swc backup -o "$WORK/reexport.json"
diff <(jq -S '.users' "$WORK/backup.json") \
     <(jq -S '.users' "$WORK/reexport.json") && echo "USERS IDENTICAL"
```

Expected: `USERS IDENTICAL` (no diff). Do the same for `.audit` if desired.

### 3.4 `--force` replaces an existing store atomically

```bash
# restored.db currently has alice/bob/carol. Make a different backup:
export PROXY_DATABASE_PATH="$WORK/other.db"
swc user add dave --admin
swc backup -o "$WORK/dave.json"

# Force-restore dave.json over the 3-user store:
export PROXY_DATABASE_PATH="$WORK/restored.db"
swc restore -i "$WORK/dave.json" --force
swc user ls          # only dave remains
```

Expected: only `dave` present — the prior alice/bob/carol are gone (DELETE +
import inside one transaction).

### 3.5 Restore is audited

```bash
swc audit ls | grep backup.restored
```

Expected: `backup.restored` row, detail like `users=1 audit=M ca=false force=true`.

### 3.6 stdin path

```bash
rm -f "$WORK/stdin.db"*; export PROXY_DATABASE_PATH="$WORK/stdin.db"
swc restore < "$WORK/backup.json"
swc user ls          # 3 users
```

Expected: piping on stdin works identically to `-i`. With no `-i` **and** a
terminal stdin (no pipe), expect `error: no input: pipe a backup into stdin or
pass -i <file>`.

---

## 4. Schema / version guards

Corrupt copies must be rejected **before** the store is touched.

```bash
# Wrong schema
jq '.schema="evil"' "$WORK/backup.json" > "$WORK/bad-schema.json"
rm -f "$WORK/g.db"*; export PROXY_DATABASE_PATH="$WORK/g.db"
swc restore -i "$WORK/bad-schema.json"; echo "exit=$?"
# error: unrecognised backup schema "evil" (want "swarmcli-rbac-proxy/backup")  exit=1

# Wrong version
jq '.version=99' "$WORK/backup.json" > "$WORK/bad-version.json"
swc restore -i "$WORK/bad-version.json"; echo "exit=$?"
# error: unsupported backup version 99 (want 1)  exit=1

# Malformed JSON
echo 'not json' > "$WORK/bad.json"
swc restore -i "$WORK/bad.json"; echo "exit=$?"
# error: parse backup: ...  exit=1
```

Expected for all three: non-zero exit, and `swc user ls` against `g.db` shows
**0 users** (the guards fire before any write).

---

## 5. DR bundle (`--include-ca`)

The CA lives outside the database; `--include-ca` embeds it. We supply a
throwaway CA via the same env vars the proxy uses.

```bash
# Generate a throwaway client CA (ECDSA, like certauth.GenerateCA).
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ca-key.pem"
openssl req -x509 -new -key "$WORK/ca-key.pem" -days 3650 \
  -subj "/CN=swarmcli-test-ca" -out "$WORK/ca-cert.pem"

export PROXY_TLS_CLIENT_CA="$WORK/ca-cert.pem"
export PROXY_TLS_CLIENT_CA_KEY="$WORK/ca-key.pem"
export PROXY_DATABASE_PATH="$WORK/proxy.db"   # back to the 3-user store
```

### 5.1 Refuses to print the key to a terminal

```bash
swc backup --include-ca; echo "exit=$?"
```

Expected (when stdout is a TTY): `error: --include-ca writes the root signing
key; redirect to a file or pipe, or use -o <file>`, `exit=1`. (Redirecting,
e.g. `swc backup --include-ca > f.json`, is allowed — the TTY check only fires
on an interactive stdout.)

### 5.2 Produces a bundle with CA material + loud warning

```bash
swc backup --include-ca -o "$WORK/dr.json"
```

Expected stderr: the two-line `WARNING: this backup embeds the client CA
private key ...`, then `Backed up 3 users ...`. Verify the CA block:

```bash
jq '.ca.cert_pem[0:27], (.ca.key_pem|length>0)' "$WORK/dr.json"
# "-----BEGIN CERTIFICATE-----"
# true
```

### 5.3 `--include-ca` requires both CA env vars

```bash
( unset PROXY_TLS_CLIENT_CA_KEY; swc backup --include-ca -o /tmp/x.json ); echo "exit=$?"
```

Expected: `error: --include-ca requires PROXY_TLS_CLIENT_CA and
PROXY_TLS_CLIENT_CA_KEY to be configured`, `exit=1`.

---

## 6. Restoring a DR bundle

### 6.1 Bundle with CA requires `--ca-out`

```bash
rm -f "$WORK/dr.db"*; export PROXY_DATABASE_PATH="$WORK/dr.db"
swc restore -i "$WORK/dr.json"; echo "exit=$?"
```

Expected: `error: backup contains CA material: pass --ca-out <dir> to extract
it`, `exit=1`, store still empty (fails fast before import).

### 6.2 Extracts CA (mode 0600) and prints the secret-recreate runbook

```bash
mkdir -p "$WORK/caout"     # NOTE: restore does NOT create --ca-out; it must exist
swc restore -i "$WORK/dr.json" --ca-out "$WORK/caout"
stat -c '%a' "$WORK/caout/ca-cert.pem" "$WORK/caout/ca-key.pem"   # 600 600
```

> Gotcha: `--ca-out <dir>` is **not** created by `restore`. If it is missing,
> the users/audit import still runs, then the CA write fails with
> `error: write .../ca-cert.pem: ... no such file or directory` and exit 1 —
> i.e. a non-atomic partial restore (DB imported, CA not extracted). Always
> `mkdir -p` the target first.

Expected stderr:
- `Restored 3 users and N audit entries`
- `Client CA written to .../ca-cert.pem and .../ca-key.pem.`
- the four `docker secret rm` / `docker secret create` / `docker stack deploy`
  lines.
- **Preflight match**: because `PROXY_TLS_CLIENT_CA` still points at the same
  cert that was bundled, expect
  `Preflight: the running deployment already uses this CA — user contexts are
  unaffected.`

Confirm the extracted cert equals the configured one:

```bash
diff "$WORK/caout/ca-cert.pem" "$WORK/ca-cert.pem" && echo "CA MATCHES"
```

### 6.3 Preflight warns on CA mismatch

Point the running config at a *different* CA, then restore the bundle again:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ca2-key.pem"
openssl req -x509 -new -key "$WORK/ca2-key.pem" -days 3650 \
  -subj "/CN=other-ca" -out "$WORK/ca2-cert.pem"
export PROXY_TLS_CLIENT_CA="$WORK/ca2-cert.pem"

mkdir -p "$WORK/caout2"
rm -f "$WORK/dr2.db"*; export PROXY_DATABASE_PATH="$WORK/dr2.db"
swc restore -i "$WORK/dr.json" --ca-out "$WORK/caout2"
```

Expected: the two-line `Preflight WARNING: the running deployment uses a
DIFFERENT client CA. ... Existing user contexts will fail mTLS until the CA
above is deployed.`

Reset for later steps: `export PROXY_TLS_CLIENT_CA="$WORK/ca-cert.pem"`.

---

## 7. Backend rejection & flag errors

```bash
# memory store is rejected (data wouldn't be shared with the proxy process)
PROXY_STORE=memory swc backup; echo "exit=$?"
# error: swcproxy cannot use in-memory store ...  exit=1

# unknown flags
swc backup --nope;  echo "exit=$?"   # error: unknown flag: --nope  + usage  exit=1
swc restore --nope; echo "exit=$?"   # error: unknown flag: --nope  + usage  exit=1

# missing flag argument
swc backup -o;        echo "exit=$?" # error: -o requires a file path
swc restore --ca-out; echo "exit=$?" # error: --ca-out requires a directory path

# help
swc backup --help     # prints backup usage, exit 0
swc restore -h        # prints restore usage, exit 0
```

---

## 8. Cross-backend portability (optional — needs PostgreSQL)

The logical export is portable between SQLite and PostgreSQL. Take a SQLite
backup, restore it into Postgres, and diff.

```bash
# Start a throwaway Postgres
docker run -d --rm --name pgtest -e POSTGRES_PASSWORD=pass -p 5432:5432 postgres:17
sleep 3

export PROXY_STORE=postgres
export PROXY_DATABASE_URL='postgres://postgres:pass@localhost:5432/postgres?sslmode=disable'

# Restore the SQLite-produced backup into Postgres
swc restore -i "$WORK/backup.json"      # 3 users
swc user ls
swc backup -o "$WORK/pg-reexport.json"

# Compare on stable identity fields (id/username/role/enabled/token). Do NOT
# diff the whole object: Postgres timestamptz keeps microseconds while SQLite
# keeps nanoseconds, so created_at/updated_at can differ in trailing digits
# across backends even for the same instant — expected, not a data loss.
proj='[.users[]|{id,username,role,enabled,tok:(.onboard_token|length>0)}]|sort_by(.username)'
diff <(jq -S "$proj" "$WORK/backup.json") \
     <(jq -S "$proj" "$WORK/pg-reexport.json") && echo "PORTABLE: USER IDENTITIES IDENTICAL"

docker rm -f pgtest
unset PROXY_STORE PROXY_DATABASE_URL
```

Expected: `PORTABLE: USER IDENTITIES IDENTICAL`. (The integration test
`TestPostgresStore_BackupContract` covers same-backend round-trips in CI; this
is the manual cross-backend confirmation.)

---

## 9. End-to-end in a real Swarm (full DR rehearsal)

The ultimate test is an onboarded user surviving a full rebuild. This mirrors
`docs/backup-restore.md` § "Full cluster rebuild".

1. Deploy the `rbac` stack with mTLS; onboard a user and save their
   `docker context` (verify `docker ps` works through the proxy).
2. `docker exec <proxy> swcproxy backup --include-ca -o /data/dr.json`.
3. Tear the stack down, delete the volume and the `rbac_client_ca*` secrets
   (simulate disaster). Redeploy on an empty volume.
4. `docker exec <proxy> mkdir -p /data/ca` (restore won't create `--ca-out`),
   then `docker exec -i <proxy> swcproxy restore -i /data/dr.json --ca-out /data/ca`.
5. Run the printed `docker secret create` + `docker stack deploy` commands.
6. From the **original** user's machine: `docker context use <ctx> && docker ps`.

Pass criteria:
- `docker ps` succeeds → both halves restored (user record **and** matching CA).
- `403 unknown user` → the user record didn't restore.
- TLS handshake failure → the deployed CA doesn't match the user's cert.

## 10. Cleanup

```bash
rm -rf "$WORK"
unset WORK PROXY_STORE PROXY_DATABASE_PATH PROXY_DATABASE_URL \
      PROXY_TLS_CLIENT_CA PROXY_TLS_CLIENT_CA_KEY PROXY_ENV
unalias swc
```
