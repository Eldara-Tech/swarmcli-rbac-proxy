# Migrating from SQLite to PostgreSQL

The proxy defaults to an embedded SQLite store, which is fine for a single
node. To run multiple proxy replicas, share state across a redeployment, or
simply operate a managed database, move the store onto PostgreSQL.

`swcproxy migrate` copies an existing SQLite database into PostgreSQL in one
transaction. It is a **logical** copy built on the same export/import machinery
as [backup and restore](backup-restore.md), so it is portable across backends
rather than a file copy.

## What moves, and what does not

Migrated (everything in the database):

- **Users** — including `enabled` state and **pending onboarding tokens** (so a
  user who is mid-onboarding is not broken). Unlike `swcproxy backup`, migrate
  copies tokens verbatim: it is a direct store-to-store transfer with no
  artifact written to disk.
- **Audit log** — full history.
- **RBAC roles and bindings** — including custom roles and non-default bindings.

Not in the database, and therefore unaffected by migration:

- **The client CA** (`rbac_client_ca` / `rbac_client_ca_key` Docker secrets).
  Every user certificate is signed by it and it lives in Docker secrets, not the
  store. Because migration does not touch it, **existing `docker context`
  connections keep working with no re-onboarding** — you are only changing where
  the proxy reads its user/role data from.

## Prerequisites

- A reachable PostgreSQL database and a connection URL. Use a verified-TLS DSN
  in production: `postgres://user:pass@host:5432/db?sslmode=verify-full`
  (`sslmode=disable` only on a trusted private network).
- The `swcproxy` CLI, which ships in the proxy image. Run it inside the proxy
  container via `docker exec`.
- A maintenance window. Run the migration while the proxy is stopped (or briefly
  read-only) so no writes are lost between the export and the cut-over.

The destination schema is created automatically — point migrate at an empty
database.

## Steps

1. **Provision** the PostgreSQL database and confirm connectivity.

2. **Migrate** the data. From a context with the SQLite file and the destination
   URL (defaults are read from `PROXY_DATABASE_PATH` and `PROXY_DATABASE_URL`):

   ```bash
   swcproxy migrate \
     --sqlite   /data/proxy.db \
     --postgres 'postgres://proxy:secret@db:5432/rbac?sslmode=verify-full'
   ```

   migrate refuses a non-empty destination unless you pass `--force` (which
   clears the destination tables first). On success it prints the row counts and
   records a `db.migrated` audit entry in the destination.

3. **Verify** the destination, pointing the CLI at PostgreSQL:

   ```bash
   export PROXY_STORE=postgres
   export PROXY_DATABASE_URL='postgres://proxy:secret@db:5432/rbac?sslmode=verify-full'
   swcproxy user ls
   swcproxy role ls
   swcproxy binding ls
   swcproxy audit ls --limit 5   # shows the db.migrated entry
   ```

   The counts should match the SQLite source.

4. **Cut over** the proxy: set `PROXY_STORE=postgres` and `PROXY_DATABASE_URL`
   (and, for Swarm, `PROXY_BACKUP_DIR` to a volume path since Postgres has no DB
   file) in the stack and redeploy. On startup the proxy re-seeds the built-in
   roles idempotently and waits up to `PROXY_DATABASE_CONNECT_TIMEOUT`
   (default 30s) for the database to become reachable.

5. **Retire** the SQLite file once you have confirmed the Postgres-backed proxy
   is serving traffic and authorizing users correctly.

## Rollback

`swcproxy migrate` never writes user, role, or audit data back to the SQLite
source, so rolling back is just reverting `PROXY_STORE`/`PROXY_DATABASE_*` to the
SQLite settings and redeploying. (Opening the source does switch it to WAL mode
and create `-wal`/`-shm` sidecar files, so it must sit on a writable filesystem;
copy the `.db` beforehand if you want a byte-identical rollback artifact.) Any
writes made against PostgreSQL after cut-over are not reflected back into the
SQLite file — keep the maintenance window tight.

## Notes

- migrate is one-directional (SQLite → PostgreSQL); it is the documented path
  the issue calls for. The underlying export/import is symmetric, so the reverse
  is mechanically possible via [backup/restore](backup-restore.md) if ever
  needed.
- `swcproxy` commands always **fail fast** on an unreachable database (no
  retry). The connection wait applies only to the long-running proxy server.
