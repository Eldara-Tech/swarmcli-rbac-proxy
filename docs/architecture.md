# Architecture

A transparent reverse proxy in front of the Docker API. It terminates mTLS,
resolves an identity from the client certificate, applies RBAC, enforces the
protected-stack guards, and relays what survives to the daemon's Unix socket.

This page maps the code. For the permission model see [rbac.md](rbac.md), for the
configuration surface [configuration.md](configuration.md), for the wire contract
[api.md](api.md), and for the threat model [security.md](security.md).

## The request path

Every external request runs the same chain, in this order:

```
RequireClientCert → RBACMiddleware.Wrap → ExecGuard → ResourceGuard.Wrap → proxy
```

RBAC is a no-op on the internal listener and when mTLS is off, because there is
no identity to authorize. That is deliberate — the internal listener exists so an
operator on the manager node can work without a certificate — and it is why the
exec guard stays active on the external listener regardless: with no mTLS
configured, nobody can prove admin, so every exec into a protected-stack
container is denied. That is fail-closed, not a broken deployment.

## Dual listener

When `PROXY_INTERNAL_LISTEN` is set, the proxy runs two listeners:
- **Internal** (`PROXY_INTERNAL_LISTEN`, e.g. `127.0.0.1:2375`): plain TCP, no mTLS, for admin access inside the container. Bypasses all auth and resource guards.
- **External** (`PROXY_LISTEN`, e.g. `:2376`): TLS with `VerifyClientCertIfGiven`. Proxy routes require client cert; onboard endpoint does not.

**Design note**: `isInternalListener()` identifies internal requests by the presence of `ContextKeyInternal` in the request context, set by `MarkInternalRequest` middleware applied exclusively on the internal listener mux. This positive-signal approach ensures an auth bypass on the external listener cannot be misread as an internal request.

## Layout

```
swarm-rbac-proxy/
  main.go               — reverse proxy + dual listener routing (internal plain TCP + external mTLS), --version flag, `healthcheck` subcommand (Docker healthcheck self-probe: GETs the internal listener's /_swc/version for a 200), internal-only /_swc/ control-plane (startbackup + version, branded 404) via mountControlPlane
  main_test.go          — unit tests against mock Unix socket
  integration_test.go   — TLS integration tests (plain→TLS, mTLS, upgrade through TLS, frontend mTLS)
  .goreleaser.yml       — GoReleaser config: Linux binary releases (amd64/arm64) for proxy + swcproxy
  Dockerfile            — multi-stage build (golang:1.27-alpine → alpine:3.24), version injection via build args + ldflags, OCI labels
  welcome.sh            — container login banner with dynamic version display (COPY'd to /etc/profile.d/welcome.sh)
  stack.yml             — Docker Swarm stack definition
  cmd/
    swcproxy/
      main.go           — Admin CLI: version, user ls/add/delete/regenerate-token, audit ls (direct store access)
      backup.go         — Admin CLI: backup/restore (delegates artifact assembly to internal/backup; optional CA bundle; default-location output resolution)
      main_test.go      — CLI unit tests (flag parsing, helpers)
  internal/
    backup/
      backup.go         — Logical backup artifact (Doc/User/CA schema incl. roles+bindings, Create with token-redaction, Marshal/ToData/WriteToDir [O_EXCL, no overwrite]/DefaultDir/Filename), shared by the swcproxy CLI and the server's /startbackup handler
      backup_test.go    — backup package unit tests (export, marshal, filename, dir perms, default dir)
    version/
      version.go        — Build-time version vars (Version/Commit/Date), shared by both binaries
      version_test.go   — version package tests
    certauth/
      certauth.go       — CA loading, generation (GenerateCA), client certificate issuance (ECDSA P-256)
      certauth_test.go  — unit tests (load, issue, serial uniqueness, round-trip)
    config/
      config.go         — Config struct, Load(path) merges JSON file + env vars + defaults
      config_test.go    — config loading unit tests
    log/
      logger.go         — proxylog package: zap-based structured logging (Init/L/Sync/With)
      logger_test.go    — logger unit tests (mode detection, level defaults, noop safety)
    store/
      store.go          — UserStore + AuditStore + BackupStore interfaces, User/AuditEntry/BackupData types, AuditAction constants, sentinel errors (BackupStore: Export → all tables incl. roles/bindings + token columns; Restore → verbatim, single transaction, replace clears all tables)
      rbac.go           — RBACStore interface, Role/RoleBinding/PermissionRule types, resource/verb vocabulary, built-in roles, effective-permission resolver, seeding, legacy migration, last-admin lockout helpers
      memory.go         — in-memory UserStore + AuditStore + RBACStore + BackupStore (dev/testing)
      sqlite.go         — SQLite UserStore + AuditStore + RBACStore + BackupStore (modernc.org/sqlite, default, with migrations; rules stored as JSON)
      postgres.go       — PostgreSQL UserStore + AuditStore + RBACStore + BackupStore (pgx/v5, with migrations; rules stored as JSONB)
      contract_test.go  — shared contract tests for all store implementations (user + audit)
      rbac_contract_test.go — shared RBAC contract tests (roles, bindings, resolver, seeding, migration, lockout)
      memory_test.go    — memory store unit tests
      sqlite_test.go    — SQLite store unit tests (contract + WAL)
      postgres_test.go  — postgres integration tests (//go:build integration)
    api/
      auth.go           — RequireToken middleware (bearer token validation)
      auth_test.go      — auth middleware tests
      adminauth.go      — RequireAdminOrToken: management-plane authz (admin bearer token OR mTLS-authenticated admin); lets an admin manage users from the TUI, which has a client cert but no bearer token
      adminauth_test.go — admin-auth middleware tests (bearer / mTLS-admin / non-admin / no-identity)
      mtls.go           — RequireClientCert middleware (mTLS client cert → user lookup)
      mtls_test.go      — mTLS middleware unit tests
      users.go          — UserHandler: GET/POST /api/v1/users, DELETE/PATCH /api/v1/users/{username}, POST .../regenerate-token (create binds a role + returns a one-time onboard token; delete/disable/demote guard self + last-admin)
      users_test.go     — handler tests using MemoryStore
      roles.go          — RoleHandler: CRUD /api/v1/roles (admin-token protected)
      bindings.go       — BindingHandler: list/create/delete /api/v1/bindings (admin-token protected)
      rbac.go           — RBACMiddleware: per-role resource/verb authorization on the data plane (default-deny, stacks-label OR)
      rbac_test.go      — RBAC middleware matrix tests (viewer/operator/admin × resources/verbs)
      rbacmap.go        — mapRequest: HTTP {method,path} → {resource,verb}; stripDockerVersion shared helper
      rbacmap_test.go   — request-mapping table tests
      me.go             — MeHandler: GET /api/v1/me → caller's own {username, role} from mTLS cert
      me_test.go        — me handler tests (admin/user/no-user/method)
      onboard.go        — OnboardHandler: GET /api/v1/onboard/{token} → Docker-context tar
      onboard_test.go   — onboard handler tests
      guard.go          — ResourceGuard middleware: protects bootstrap stack from non-admin mutation; ExecGuard: admin-only exec/attach; resourceStackLabel/stackLabelFromBody label resolvers shared with RBAC
      guard_test.go     — guard middleware tests (path parsing, admin check, back-query, body inspection)
      volumeguard.go    — volume management policy: stack-scoped admin gate for /v1/volumes mutations, agent-manager back-query for ownership, success auditing
      volumeguard_test.go — volume guard tests (GET allowed, protected/non-protected mutation, fail-closed, audit)
      stackdetect.go    — DetectStackName: auto-discovers stack name from container labels via Docker API
      stackdetect_test.go — stack detection tests
```

## Related

- [rbac.md](rbac.md) — roles, bindings, the permission matrix, the audit vocabulary
- [configuration.md](configuration.md) — every `PROXY_*` variable and the protected-stack matrix
- [api.md](api.md) — the management API and the agent-manager verbs
- [security.md](security.md) — threat model, authentication layers, certificate lifecycle
- [troubleshooting.md](troubleshooting.md) — symptoms and what they actually mean
