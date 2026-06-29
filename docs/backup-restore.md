# Backup and restore

This guide answers a deceptively simple question: **how do you back up the
proxy and still have every user's `docker context` keep working afterwards?**

The short answer is that two independent things must survive, and only one of
them lives in the database:

1. **The user database** — user records, onboarding-token state, and the audit
   log. Without a user's record, their certificate is valid but the proxy
   rejects them with `403 unknown user`.
2. **The client CA** (`rbac_client_ca` + `rbac_client_ca_key` Docker secrets).
   Every user certificate is signed by this CA. Lose it, restore a different
   one, and **every** existing user context fails the mTLS handshake.

`swcproxy backup` handles (1) safely and can optionally bundle (2).

## Why a plain file copy is not enough

The default SQLite store runs in WAL mode, so `cp proxy.db backup.db` while the
proxy is running can capture a torn, unrecoverable file. `swcproxy backup`
instead performs a **logical export** — it reads every row through the database
and writes a single JSON document — so it is always consistent and is portable
across the SQLite and PostgreSQL backends.

Critically, the CA is **not** in the database. It is delivered as Docker Swarm
secrets and held only in memory by the running container. Docker Swarm secrets
**cannot be read back** (`docker secret inspect` never reveals the value), so
after a full cluster rebuild the only surviving copies of the CA are whatever
PEM files you kept when you first created the secrets. `swcproxy` runs inside
the container and *can* read the mounted secret, which makes
`swcproxy backup --include-ca` the sanctioned way to get a recoverable copy.

## Routine backup (database only)

Run inside the proxy container (manager node):

```bash
docker exec "$(docker ps -q -f name=rbac_proxy)" \
  swcproxy backup > proxy-backup-$(date +%F).json
```

Or write the file inside the container's data volume / a bind mount:

```bash
docker exec "$(docker ps -q -f name=rbac_proxy)" \
  swcproxy backup -o /data/proxy-backup.json
```

The artifact contains users, the full audit log, and the RBAC roles and
bindings — everything needed to reproduce the original authorization state, not
just the user rows. By default it is **low-sensitivity** — usernames, roles,
timestamps — and safe for ordinary backup storage; schedule it like any other
database dump.

Pending **onboarding tokens are redacted by default**: a live token is a bearer
credential (it mints a client cert for that user via `GET /api/v1/onboard/...`),
so a routine backup omits them. Pass `--include-tokens` for full-fidelity DR
that preserves in-flight onboards — the resulting file is then credential-
sensitive and must be protected accordingly.

It does **not** contain the CA; `backup` reminds you of this on stderr.

### Default location

`backup` only streams JSON to stdout when stdout is **piped or redirected**
(the `> file.json` form above). With no `-o` on an **interactive terminal** it
instead writes a timestamped file to the default backup directory — derived
from the database path so it lands on the persistent `proxy-data` volume:

```
/data/proxy.db  →  /data/backup/swc-proxy-backup-<YYYYMMDD-HHMMSS>.json
```

and prints the path. The directory is derived from the database path, so on a
**PostgreSQL** backend (no database file) it falls back to `./backup` in the
proxy's working directory — set `PROXY_BACKUP_DIR` to a persistent volume path
there so the artifact survives container restarts. So a bare `swcproxy backup`
inside the container produces a durable file on the volume without you choosing
a name. The filename is
timestamped to the second; if two backups land in the same second, the later
one is written as `…-<HHMMSS>-1.json`, `…-2.json`, etc. — an existing file is
never overwritten.

### Trigger over the internal listener

When `PROXY_INTERNAL_LISTEN` is set (e.g. `127.0.0.1:2375`), the proxy serves
its control-plane endpoints under the reserved **`/_swc/`** namespace on that
**loopback, no-auth** listener — the same trusted local admin path used for
`docker stack deploy`. `/_swc/startbackup` writes a database-only backup to the
default directory above and returns the filename:

```bash
curl 127.0.0.1:2375/_swc/startbackup
{"result":"success","file":"swc-proxy-backup-20260624-070425.json","path":"/data/backup/swc-proxy-backup-20260624-070425.json"}
```

`GET` and `POST` are both accepted. (`/startbackup` without the prefix still
works as a back-compat alias.) The endpoint is **never** exposed on the external
mTLS listener, and it **never** embeds the CA — `--include-ca` stays a
deliberate, human-supervised CLI action (see below). Retrieve the saved file
from the volume (`docker cp`, a bind mount, or your volume backup tooling).

**Check the running build first.** `GET /_swc/version` reports the proxy's build
identity, and its mere presence is the signal you need:

```bash
curl 127.0.0.1:2375/_swc/version
{"version":"1.3.0","commit":"abc1234","date":"2026-06-29T…"}
```

A `200` here means the binary is current enough to carry the whole `/_swc/`
namespace (so `/_swc/startbackup` is available too). The whole namespace returns
a branded JSON `404` for an unknown control route, so it is never confused with
a Docker response.

> **Troubleshooting — a `404` on `/_swc/version` means the running build is
> stale.** Older builds have no `/_swc/` namespace at all, so the internal
> listener forwards the request to the Docker socket and the daemon answers with
> its own `404 Not Found` — that fall-through is the only reason a control route
> can return `404`. If you see it, rebuild and redeploy the proxy, and on Swarm
> force the service to adopt the new image
> (`docker service update --image <repo>:<tag> --force <stack>_rbac-proxy`) —
> `docker stack deploy` will not re-pull a tag the node has already cached.
> (A `400 Bad Request` on the *external* port, e.g. `2376`, is unrelated: that
> is the mTLS listener rejecting plaintext HTTP. The `/_swc/` namespace is
> internal-listener-only by design.)

## Disaster-recovery bundle (database + CA)

`--include-ca` embeds the client CA cert **and private key** in the artifact so
a single file can fully restore service:

```bash
docker exec "$(docker ps -q -f name=rbac_proxy)" \
  swcproxy backup --include-ca -o /data/proxy-dr.json
```

> **Security warning.** The CA private key can mint a certificate for *any*
> username, including admins. A `--include-ca` artifact is a crown-jewel
> secret: store it in a vault / password manager, encrypt it at rest, and keep
> it separate from routine database backups. `--include-ca` requires a file
> destination: with no `-o`, a terminal writes a `0600` file to the default
> backup directory, and a piped/redirected stdout is **refused** (the command
> exits non-zero) so the key is never streamed to a fd at the shell's umask.
> The `/_swc/startbackup` HTTP trigger never includes the CA.

The CA has a 10-year validity and effectively never changes, so a single
`--include-ca` capture, refreshed only when you rotate the CA, is enough.

## Restoring

`restore` reads the JSON from stdin or `-i <file>`, validates the schema, and
re-imports users, the audit log, and the RBAC roles and bindings **verbatim** —
preserving IDs, timestamps and token state — in a single transaction across all
tables, so a failed restore leaves the store untouched rather than half-applied.
Because roles and bindings are carried, a restored user keeps the exact role
they had (a `viewer` stays a `viewer`); without them the startup legacy
migration would re-derive bindings from `User.Role` and silently promote
non-admins to `operator`.

```bash
docker exec -i "$(docker ps -q -f name=rbac_proxy)" \
  swcproxy restore -i /data/proxy-backup.json
```

`restore` refuses to overwrite a non-empty store unless you pass `--force`,
which atomically replaces the existing users, audit log, roles and bindings.

### Full cluster rebuild (database + CA bundle)

After the proxy stack is redeployed on a fresh Swarm with an empty volume:

```bash
docker exec -i "$(docker ps -q -f name=rbac_proxy)" \
  swcproxy restore -i /data/proxy-dr.json --ca-out /data/ca
```

Because the bundle carries CA material, `--ca-out` is required. `restore`
writes `ca-cert.pem` and `ca-key.pem` (mode 0600) and prints the exact
commands to recreate the Swarm secrets and redeploy:

```bash
docker secret rm rbac_client_ca rbac_client_ca_key
docker secret create rbac_client_ca     /data/ca/ca-cert.pem
docker secret create rbac_client_ca_key /data/ca/ca-key.pem
docker stack deploy -c stack.yml rbac
```

`restore` also runs a preflight: if the running deployment already uses a
*different* client CA, it warns loudly that existing user contexts will fail
mTLS until the restored CA is deployed.

## Verifying a restore

The only true test is an end-to-end check from a previously-onboarded user:

```bash
docker context use <their-context>
docker ps
```

A successful `docker ps` proves both halves are intact: the user record exists
in the restored database **and** the deployed CA matches the certificate in
their context. If `docker ps` fails the mTLS handshake, the CA does not match;
if it returns `403`, the user record was not restored.

If the CA could not be recovered, existing certificates are unrecoverable —
re-onboard every user with `swcproxy user regenerate-token <username>`.

## Artifact format

A single JSON document:

```json
{
  "schema": "swarmcli-rbac-proxy/backup",
  "version": 1,
  "created_at": "2026-05-19T12:00:00Z",
  "proxy_version": "swarm-rbac-proxy v1.2.3 (...)",
  "users": [ { "id": "...", "username": "alice", "role": "user",
               "enabled": true, "created_at": "...", "updated_at": "...",
               "onboard_token": "...", "token_issued_at": "..." } ],
  "audit": [ { "id": "...", "timestamp": "...", "actor": "cli",
               "action": "user.created", "resource": "user:alice",
               "status": "success", "detail": "", "source_ip": "" } ],
  "ca": { "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
          "key_pem":  "-----BEGIN EC PRIVATE KEY-----\n..." }
}
```

`ca` is present only when the backup was taken with `--include-ca`.
