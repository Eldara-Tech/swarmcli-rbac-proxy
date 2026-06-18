# Manual test guide — `swcproxy backup` / `restore`

A happy-path walkthrough for manually verifying the logical backup/restore
feature (`cmd/swcproxy/backup.go`): back up the user database (optionally with
the client CA), restore it, and confirm an onboarded user survives. Runs
against the default SQLite backend in a scratch directory — no proxy process,
Swarm, or mTLS required (except the end-to-end rehearsal in § 5).

Automated coverage lives in `internal/store/contract_test.go`
(`testBackupStoreContract`) and `cmd/swcproxy/main_test.go` (flag parsing); the
negative / edge-case checks are kept in an HTML comment at the end of this file.

Conventions: `$` is your shell; shown output is **expected**. Human messages go
to **stderr**. **Capture the artifact with `-o <file>`, not `> file`** — a
`store initialized` log line lands on stdout ahead of the JSON, so a shell
redirect produces invalid JSON; `-o` writes the file directly and is clean.

## 1. Setup

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
```

## 2. Back up the database

```bash
swc backup -o "$WORK/backup.json"
```

Expected:
- stderr: `Backed up 3 users and N audit entries to $WORK/backup.json`, then the
  three-line "this backup does NOT contain the client CA" note.
- the file is valid JSON, mode `0600`, and carries the onboarding-token columns
  (`swcproxy user ls` / the API hide them):

```bash
stat -c '%a' "$WORK/backup.json"   # 600
jq '.schema, .version, (.users|length), (.ca==null)' "$WORK/backup.json"
# "swarmcli-rbac-proxy/backup"
# 1
# 3
# true
jq '.users[0] | {username, role, has_token: (.onboard_token|length>0)}' "$WORK/backup.json"
```

The export is audited — `swc audit ls | grep backup.exported` shows a `cli`
row with detail `users=3 audit=N ca=false`.

## 3. Restore the database

```bash
export PROXY_DATABASE_PATH="$WORK/restored.db"   # a fresh, empty store
swc restore -i "$WORK/backup.json"
swc user ls                                       # the same three users
```

Expected: `Restored 3 users and N audit entries`, and the trailing CA caveat.
The import is **verbatim** — IDs, roles, timestamps and token state round-trip
exactly. Confirm by re-exporting and diffing:

```bash
swc backup -o "$WORK/reexport.json"
diff <(jq -S '.users' "$WORK/backup.json") \
     <(jq -S '.users' "$WORK/reexport.json") && echo "USERS IDENTICAL"
```

A backup can also be piped in (`swc restore < "$WORK/backup.json"`).

To overwrite a store that already has users, pass `--force` (DELETE + import in
one transaction):

```bash
swc restore -i "$WORK/backup.json" --force      # replaces existing users + audit
```

`restore --force` is audited as a `backup.restored` row
(`detail: ... force=true`).

## 4. Back up and restore with the CA (DR bundle)

The client CA lives in Docker secrets, **not** the database; `--include-ca`
embeds the cert+key so a single file fully restores service. Supply a CA via the
same env vars the proxy uses (here, a throwaway one):

```bash
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ca-key.pem"
openssl req -x509 -new -key "$WORK/ca-key.pem" -days 3650 \
  -subj "/CN=swarmcli-test-ca" -out "$WORK/ca-cert.pem"
export PROXY_TLS_CLIENT_CA="$WORK/ca-cert.pem"
export PROXY_TLS_CLIENT_CA_KEY="$WORK/ca-key.pem"
export PROXY_DATABASE_PATH="$WORK/proxy.db"      # the 3-user store

swc backup --include-ca -o "$WORK/dr.json"
```

Expected: a two-line `WARNING: this backup embeds the client CA private key ...`
on stderr, and a `.ca` block in the file:

```bash
jq '.ca.cert_pem[0:27], (.ca.key_pem|length>0)' "$WORK/dr.json"
# "-----BEGIN CERTIFICATE-----"
# true
```

Restore the bundle into a fresh store, extracting the CA with `--ca-out`:

```bash
mkdir -p "$WORK/caout"     # restore does NOT create --ca-out; it must exist
export PROXY_DATABASE_PATH="$WORK/dr.db"
swc restore -i "$WORK/dr.json" --ca-out "$WORK/caout"
stat -c '%a' "$WORK/caout/ca-cert.pem" "$WORK/caout/ca-key.pem"   # 600 600
```

Expected stderr:
- `Restored 3 users and N audit entries`
- `Client CA written to .../ca-cert.pem and .../ca-key.pem.`
- the `docker secret rm` / `docker secret create` / `docker stack deploy`
  runbook lines.
- a **preflight** line: because `PROXY_TLS_CLIENT_CA` still points at the
  bundled cert, `Preflight: the running deployment already uses this CA — user
  contexts are unaffected.`

## 5. End-to-end in a real Swarm (full DR rehearsal)

The ultimate test is an onboarded user surviving a full rebuild. Mirrors
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

## 6. Cross-backend portability (optional — needs PostgreSQL)

The logical export is portable between SQLite and PostgreSQL:

```bash
docker run -d --rm --name pgtest -e POSTGRES_PASSWORD=pass -p 5432:5432 postgres:17
sleep 3
export PROXY_STORE=postgres
export PROXY_DATABASE_URL='postgres://postgres:pass@localhost:5432/postgres?sslmode=disable'

swc restore -i "$WORK/backup.json"      # the SQLite backup, into Postgres
swc user ls
swc backup -o "$WORK/pg-reexport.json"

# Compare on stable identity fields. Do NOT diff the whole object: Postgres
# timestamptz keeps microseconds while SQLite keeps nanoseconds, so the
# created_at/updated_at trailing digits can differ for the same instant.
proj='[.users[]|{id,username,role,enabled,tok:(.onboard_token|length>0)}]|sort_by(.username)'
diff <(jq -S "$proj" "$WORK/backup.json") \
     <(jq -S "$proj" "$WORK/pg-reexport.json") && echo "PORTABLE: USER IDENTITIES IDENTICAL"

docker rm -f pgtest
unset PROXY_STORE PROXY_DATABASE_URL
```

## 7. Cleanup

```bash
rm -rf "$WORK"
unset WORK PROXY_STORE PROXY_DATABASE_PATH PROXY_DATABASE_URL \
      PROXY_TLS_CLIENT_CA PROXY_TLS_CLIENT_CA_KEY PROXY_ENV
unalias swc
```

<!--
========================================================================
NEGATIVE / EDGE-CASE CHECKS (not part of the happy flow)

Kept here for thorough QA / release sign-off. All commands assume the § 1
setup (WORK, PROXY_* env, `swc` alias) and the artifacts produced above
($WORK/backup.json, $WORK/dr.json). All failure messages go to stderr with
an `error: ` prefix and exit code 1.

--- Backup: stdout redirect corrupts the artifact (known issue) -------------
The `store initialized` log line lands on stdout ahead of the JSON, so a shell
redirect yields invalid JSON (reproduces in both PROXY_ENV=dev and prod). The
repo's docs/backup-restore.md § "Routine backup" still shows the `>` form.
Until the CLI routes logs to stderr (or silences info logs), always use -o.

    swc backup > "$WORK/redir.json" 2>/dev/null
    head -c 40 "$WORK/redir.json"; echo
    jq -e . "$WORK/redir.json" >/dev/null 2>&1 \
      && echo "valid (unexpected!)" || echo "INVALID JSON (expected — use -o)"
    # dev: a console "... INFO ... store initialized" line; prod: a {"level":"INFO",...} line

--- Restore: refuses a non-empty store without --force ----------------------
    export PROXY_DATABASE_PATH="$WORK/proxy.db"   # the populated store
    swc restore -i "$WORK/backup.json"; echo "exit=$?"
    # error: store already has 3 users; pass --force to replace them   exit=1  (store untouched)

--- Restore: no input on a terminal stdin ----------------------------------
    swc restore        # no -i, stdin is a TTY
    # error: no input: pipe a backup into stdin or pass -i <file>   exit=1

--- Restore: schema / version / parse guards (fire BEFORE any write) --------
    rm -f "$WORK/g.db"*; export PROXY_DATABASE_PATH="$WORK/g.db"

    jq '.schema="evil"' "$WORK/backup.json" > "$WORK/bad-schema.json"
    swc restore -i "$WORK/bad-schema.json"; echo "exit=$?"
    # error: unrecognised backup schema "evil" (want "swarmcli-rbac-proxy/backup")   exit=1

    jq '.version=99' "$WORK/backup.json" > "$WORK/bad-version.json"
    swc restore -i "$WORK/bad-version.json"; echo "exit=$?"
    # error: unsupported backup version 99 (want 1)   exit=1

    echo 'not json' > "$WORK/bad.json"
    swc restore -i "$WORK/bad.json"; echo "exit=$?"
    # error: parse backup: ...   exit=1

    swc user ls    # g.db still has 0 users — guards run before any write

--- Backup --include-ca: refuses to print the key to a terminal -------------
    swc backup --include-ca; echo "exit=$?"     # interactive stdout (no -o, no redirect)
    # error: --include-ca writes the root signing key; redirect to a file or pipe, or use -o <file>   exit=1
    # (redirecting, e.g. `swc backup --include-ca > f.json`, is allowed)

--- Backup --include-ca: requires both CA env vars --------------------------
    ( unset PROXY_TLS_CLIENT_CA_KEY; swc backup --include-ca -o /tmp/x.json ); echo "exit=$?"
    # error: --include-ca requires PROXY_TLS_CLIENT_CA and PROXY_TLS_CLIENT_CA_KEY to be configured   exit=1

--- Restore: a CA bundle requires --ca-out ----------------------------------
    rm -f "$WORK/dr.db"*; export PROXY_DATABASE_PATH="$WORK/dr.db"
    swc restore -i "$WORK/dr.json"; echo "exit=$?"
    # error: backup contains CA material: pass --ca-out <dir> to extract it   exit=1  (store still empty)

--- Restore: --ca-out directory must exist (non-atomic partial restore) -----
If the dir is missing, the users/audit import still runs, then the CA write
fails — DB imported, CA not extracted. Always `mkdir -p` the target first.
    rm -f "$WORK/dr.db"*; export PROXY_DATABASE_PATH="$WORK/dr.db"
    swc restore -i "$WORK/dr.json" --ca-out "$WORK/nope"; echo "exit=$?"
    # Restored 3 users and N audit entries
    # error: write .../nope/ca-cert.pem: ... no such file or directory   exit=1

--- Restore: preflight warns on CA mismatch ---------------------------------
    openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ca2-key.pem"
    openssl req -x509 -new -key "$WORK/ca2-key.pem" -days 3650 \
      -subj "/CN=other-ca" -out "$WORK/ca2-cert.pem"
    export PROXY_TLS_CLIENT_CA="$WORK/ca2-cert.pem"
    mkdir -p "$WORK/caout2"; rm -f "$WORK/dr2.db"*; export PROXY_DATABASE_PATH="$WORK/dr2.db"
    swc restore -i "$WORK/dr.json" --ca-out "$WORK/caout2"
    # Preflight WARNING: the running deployment uses a DIFFERENT client CA.
    #          Existing user contexts will fail mTLS until the CA above is deployed.
    export PROXY_TLS_CLIENT_CA="$WORK/ca-cert.pem"   # reset

--- Backend rejection & flag errors -----------------------------------------
    PROXY_STORE=memory swc backup; echo "exit=$?"
    # error: swcproxy cannot use in-memory store (data not shared with proxy process)   exit=1
    swc backup --nope;  echo "exit=$?"    # error: unknown flag: --nope   exit=1
    swc restore --nope; echo "exit=$?"    # error: unknown flag: --nope   exit=1
    swc backup -o;        echo "exit=$?"  # error: -o requires a file path   exit=1
    swc restore --ca-out; echo "exit=$?"  # error: --ca-out requires a directory path   exit=1
    swc backup --help     # prints usage, exit 0
    swc restore -h        # prints usage, exit 0
========================================================================
-->
