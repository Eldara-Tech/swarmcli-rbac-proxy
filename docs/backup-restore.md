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

The artifact contains users (including pending onboarding tokens) and the full
audit log. It is low-sensitivity — usernames, roles, timestamps — so it is safe
for ordinary backup storage. Schedule it like any other database dump.

It does **not** contain the CA; `backup` reminds you of this on stderr.

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
> it separate from routine database backups. `swcproxy` refuses to write it to
> an interactive terminal — redirect to a file or pipe, or use `-o`.

The CA has a 10-year validity and effectively never changes, so a single
`--include-ca` capture, refreshed only when you rotate the CA, is enough.

## Restoring

`restore` reads the JSON from stdin or `-i <file>`, validates the schema, and
re-imports users and the audit log **verbatim** — preserving IDs, timestamps
and token state.

```bash
docker exec -i "$(docker ps -q -f name=rbac_proxy)" \
  swcproxy restore -i /data/proxy-backup.json
```

`restore` refuses to overwrite a non-empty store unless you pass `--force`,
which atomically replaces the existing users and audit log.

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
