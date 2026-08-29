# swarmcli-rbac-proxy

Transparent reverse proxy that relays Docker API requests from TCP to a Unix socket, with multi-user mTLS authentication and role-based access control.

## Maintaining this file

When adding files, endpoints, env vars, CI jobs or dependencies, update the
relevant section here in the same change — but **update the doc, not this file,
whenever `docs/` already owns the subject.** Operator-facing reference — the API,
the configuration surface, the role model, the audit vocabulary — belongs in
`docs/`, and this file should point at it rather than carry a second copy.

That distinction is not stylistic. Both hand-synced tables in here drifted out of
`docs/`: `docs/api.md` documented a two-role model (`"role": "user"`) long after
the code moved to `admin`/`operator`/`viewer`, and `docs/configuration.md`'s
protection matrix was missing the overlay-pivot, port-forward and volume rows —
in both cases because a security-relevant change shipped and only this file was
updated. An operator never reads this file, so the copy that mattered was the one
left stale.

What stays here is the half an operator never needs: why a rule exists, what a
test is defending, which invariants a change must not cross.

## Build / Test / Run

```bash
go build .                           # compile
go test -v -race ./...               # run unit tests
gofmt -l .                           # check formatting
go vet ./...                         # lint
golangci-lint run                    # lint (superset, used by CI)
./swarm-rbac-proxy                   # run (needs docker.sock)
docker build -t swarmcli-rbac-proxy .   # container image
docker stack deploy -c stack.yml rbac  # deploy to Swarm

# Integration tests (requires PostgreSQL)
TEST_DATABASE_URL=postgres://user:pass@localhost:5432/testdb?sslmode=disable \
  go test -race -tags=integration ./...
```

## Go Version & Build

Go 1.26. No Makefile. GoReleaser handles binary releases with `-trimpath -s -w` ldflags and version injection (`internal/version`).

Version metadata is injected at build time via ldflags:
- `-X swarm-rbac-proxy/internal/version.Version=...` — git tag
- `-X swarm-rbac-proxy/internal/version.Commit=...` — commit hash
- `-X swarm-rbac-proxy/internal/version.Date=...` — build timestamp

For local development, defaults are `dev`/`none`/`unknown`. See `RELEASING.md` for full release process.

When updating the Go version, keep these in sync:
- `go.mod` — `go` and `toolchain` directives
- `.devcontainer/Dockerfile` — `mcr.microsoft.com/devcontainers/go` image tag (tracks major.minor; patch versions are handled by `GOTOOLCHAIN=auto`)
- `govulncheck` CI step — bump suppressed vuln IDs if the new toolchain resolves them, or add new ones if it introduces new unfixed stdlib vulns

## Configuration

See [docs/configuration.md](docs/configuration.md) for all environment variables and config.json reference.

Key env vars: `PROXY_TLS_CERT`, `PROXY_TLS_KEY` (frontend TLS), `PROXY_TLS_CLIENT_CA` (frontend mTLS — enables client certificate authentication), `PROXY_TLS_CLIENT_CA_KEY` (CA private key — enables issuing client certs when a user redeems their onboard token at `GET /api/v1/onboard/{token}`), `PROXY_ADMIN_TOKEN` (management API bearer token; `PROXY_ADMIN_TOKEN_FILE` reads it from a file path — for Docker secrets mounted at `/run/secrets/...`), `PROXY_SEED_USERNAME` (bootstrap first user at startup), `PROXY_SEED_ROLE` (role for seed user, default "user"), `PROXY_EXTERNAL_URL` (external proxy URL for onboarding curl instructions), `PROXY_INTERNAL_LISTEN` (internal plain TCP listener address, e.g. "127.0.0.1:2375"), `PROXY_BACKUP_DIR` (default-location backup dir for `swcproxy backup`/`/startbackup`; derived from the DB path when unset — set explicitly for postgres, which has no DB file), `PROXY_PROTECTED_STACK` (stack name to protect; auto-detected from container labels if unset), `PROXY_AGENT_MANAGER_TLS_BUNDLE` (consolidated single-PEM client cert+key+CA, the `internal-client` secret; supersedes the trio) or `PROXY_AGENT_MANAGER_TLS_CERT`/`PROXY_AGENT_MANAGER_TLS_KEY`/`PROXY_AGENT_MANAGER_TLS_CA` (mutual TLS to the agent-manager; the bundle or all three required when `PROXY_AGENT_MANAGER_URL` is `wss://`).

## Agent-manager Forwarding

When `PROXY_AGENT_MANAGER_URL` (env) or `agent_manager_url` (JSON config) is set, all `/v1/*` requests are forwarded to the specified backend. This covers `/v1/exec`, `/v1/logs`, `/v1/forward`, and other agent endpoints. Both normal HTTP and WebSocket upgrade (hijack) connections are supported via the same `newProxy` handler used for the Docker backend.

A `wss://` (or `https://`) URL secures this hop with **mutual TLS**: the proxy presents the bootstrap-issued internal-client cert and verifies the agent-manager's internal-server cert. Set `PROXY_AGENT_MANAGER_TLS_BUNDLE` (a single PEM with the internal-client cert, key, and internal CA cert — the consolidated `internal-client` secret) or, as a fallback, `PROXY_AGENT_MANAGER_TLS_CERT`, `PROXY_AGENT_MANAGER_TLS_KEY`, and `PROXY_AGENT_MANAGER_TLS_CA` together (the bundle or all three are required when the URL is `wss://`; startup fails closed otherwise). `ServerName` is derived by `tls.Dial` from the stack-qualified host (`<stack>_agent-manager`), which the internal-server cert carries as a SAN. This is what lets the `agent-net` overlay be a plain (non-`encrypted`) overlay — an encrypted overlay needs IPsec ESP between every node pair, which clusters that block IP-protocol-50 to a worker silently drop, breaking worker-node shells. A plaintext `tcp://` URL keeps the old unauthenticated behaviour (standalone dev only).

The `/v1/exec` and `/v1/forward` endpoints on the external listener are both stack-aware via `isAgentControlPath` in `internal/api/guard.go`:
- **Exec**: targeting a container in the protected stack requires admin role; non-protected is allowed for all authenticated users.
- **Forward**: targeting a task in the protected stack is denied for **every external role, including admin** — admin-cert compromise must not yield an exfil channel. Non-protected forwarding is allowed for all authenticated users. The `dest_addr` query parameter is rejected at the proxy edge with HTTP 400 (SSRF mitigation).
- **Volumes** (`/v1/volumes...`, `guardVolume` in `internal/api/volumeguard.go`): reads (GET) are allowed for all authenticated users; mutations (create / delete volume / delete file / rename file / upload file) on a volume that belongs to the protected stack require admin, others are allowed for all. Prune (`POST /v1/volumes/prune`) is a node-wide bulk delete not tied to one volume, so it is **admin-only outright** (no per-volume back-query). The volume's stack is resolved server-side via an agent-manager back-query (`GET /v1/volumes?node_id=`) — volumes are node-local so a client-supplied label can't be trusted and the Docker-socket back-query can't see worker-node volumes. Back-query failure fails closed (503); successful mutations are audited (`volume.*`).

The internal listener (wired with `noExecGuard`) bypasses these checks entirely.

## RBAC (roles & bindings)

The external listener authorizes every proxied request against the caller's
**roles** (`internal/api/rbac.go`), the primary authorization layer. The
protected-stack guards below are an additional, narrower layer that composes
with it (deny-wins).

- **Model** (dynamic, Kubernetes-style, additive — no deny rules): a `Role` is a
  named set of `PermissionRule{resources[], verbs[]}` (`*` wildcards allowed); a
  `RoleBinding` maps a user → role. A user's effective permission is the union
  of all bound roles' rules. **Default-deny.** Persisted in all three stores
  (`internal/store/rbac.go`).
- **Built-in roles** `viewer`/`operator`/`admin` are seeded idempotently on
  startup (`SeedDefaultRoles`) and never overwritten if edited. Legacy users are
  migrated on startup (`MigrateLegacyRoles`): `User.Role` admin→admin, else
  →operator (operator, not viewer, so an upgraded non-admin keeps the
  non-protected create/update/exec it had pre-RBAC). `User.Role` is retained as the source for the protected-stack
  `isAdmin` gate (a separate axis from RBAC).
- **Mapping**: `internal/api/rbacmap.go` maps each request to one
  `{resource, verb}` (e.g. `GET /services`→`services:list`,
  `POST /services/{id}/update`→`services:update`, `/v1/exec`→`exec:create`,
  `GET /swarm`→`swarm:get`, `GET /v1/containers`→`services:list` — the
  read-only per-container health/ports inventory, which the agent-manager
  scopes to swarm service-task containers, so its disclosure matches
  `GET /tasks` (also `services:list`); non-GET `/v1/containers` falls through
  to unmapped/admin-only). Reads are authorized too. Unmapped/raw ops
  (`POST /containers/create`) map to the `unmapped` sentinel → admin-only.
- **Stacks via label**: there is no `/stacks` Docker endpoint — a stack deploy
  is labeled `services`/`networks`/`configs`/`secrets` creates. A **mutating**
  request whose target carries `com.docker.stack.namespace` (create: body;
  update/delete: Docker back-query) is authorized under `stacks` OR the concrete
  resource. So `operator` (with `stacks: create,update`) can deploy a full stack
  incl. its networks/configs/secrets, but cannot create *standalone* infra
  resources, delete stacks (no `stacks:delete`), enumerate secrets, or touch the
  protected stack. Reads use the concrete resource only (no stacks-OR), so
  `viewer`'s `secrets:—` is not bypassable via a stack label.
- **Chain order** (external): `RequireClientCert` → `RBACMiddleware.Wrap` →
  `ExecGuard` → `ResourceGuard.Wrap` → proxy. RBAC is a no-op on the internal
  listener and when mTLS is off (no identity to authorize).
- **Permission matrix**: the built-in role/verb table is
  [docs/rbac.md § Permission matrix](docs/rbac.md#permission-matrix). It used to be
  duplicated here byte-for-byte; a hand-synced table is exactly what drifted in
  `docs/api.md` and `docs/configuration.md`, so it is a pointer now. The shape worth
  keeping in mind while editing `internal/api/rbacmap.go`: `viewer` is read-only and
  has no access at all to volumes, configs or secrets; `operator` adds create/update
  on stacks and services plus `exec`/`port-forward` create; only `admin` reaches
  secrets, swarm, roles/bindings and raw containers.

- **Management**: `/api/v1/users`, `/api/v1/roles` and `/api/v1/bindings`
  (`internal/api/users.go`, `roles.go`, `bindings.go`) and the `swcproxy
  user`/`role`/`binding` CLI. **Authorization** (`RequireAdminOrToken`,
  `internal/api/adminauth.go`): the admin bearer token (`PROXY_ADMIN_TOKEN`) OR,
  on the external listener, an **mTLS-authenticated admin** — a caller whose
  effective permissions grant `*`/`*` (`store.UserIsAdmin`). The mTLS path is
  what lets an admin manage users from the TUI (which carries a client cert but
  no bearer token); the bearer path keeps CLI/bootstrap/internal-listener access.
  The internal (loopback) listener stays bearer-only. The admin predicate is the
  same one the lockout logic uses, so "who may manage" and "who counts as admin"
  never diverge — and a future migration to a first-class `users` RBAC resource
  only changes that predicate, not the wire contract.
- **Last-admin lockout** is enforced (`ErrLastAdmin`) across every path that
  could remove admin: the last admin binding cannot be deleted, a role update
  that would remove the last admin is refused, and (new) deleting / disabling /
  demoting the last admin user is refused. A user delete cascades the user's
  bindings (`DeleteUserChecked`), and a user cannot delete/disable/demote
  **themselves** (the issue #230 restriction).

## Stack Resource Protection

When running inside a Docker Swarm stack, the proxy auto-detects its own stack name from container labels (`com.docker.stack.namespace`). Override with `PROXY_PROTECTED_STACK`.

**The full 21-row permission matrix and the rationale for every row now live in
[docs/configuration.md](docs/configuration.md#permission-matrix).** They were kept
here for a while and the operator doc carried a 6-row subset, which meant the rows
that matter most to a reviewer — the overlay-pivot block, port-forward, volumes,
the `dest_addr` rejection — existed only in a file operators do not read. Change
the doc, not this section.

What matters when changing code here: the guard keys on `admin` specifically, not
on a role ranking, and three of the rules deny **every external role including
admin** — overlay-membership mutation (T1/T2), port-forward to a protected-stack
task, and `swarm/leave`. Those three are the anti-pivot boundary; if a change
would let an admin certificate through any of them, it is a security change, not a
convenience one. `internal/api/guard.go` (`bodyHasProtectedNetworkAttachment`) and
`internal/api/volumeguard.go` (`guardVolume`, the prune gate) are where they live.

## Architecture

```
swarm-rbac-proxy/
  main.go               — reverse proxy + dual listener routing (internal plain TCP + external mTLS), --version flag, `healthcheck` subcommand (Docker healthcheck self-probe: GETs the internal listener's /_swc/version for a 200), internal-only /_swc/ control-plane (startbackup + version, branded 404) via mountControlPlane
  main_test.go          — unit tests against mock Unix socket
  integration_test.go   — TLS integration tests (plain→TLS, mTLS, upgrade through TLS, frontend mTLS)
  .goreleaser.yml       — GoReleaser config: Linux binary releases (amd64/arm64) for proxy + swcproxy
  Dockerfile            — multi-stage build (golang:1.26-alpine → alpine:3.23), version injection via build args + ldflags, OCI labels
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

## Dual Listener

When `PROXY_INTERNAL_LISTEN` is set, the proxy runs two listeners:
- **Internal** (`PROXY_INTERNAL_LISTEN`, e.g. `127.0.0.1:2375`): plain TCP, no mTLS, for admin access inside the container. Bypasses all auth and resource guards.
- **External** (`PROXY_LISTEN`, e.g. `:2376`): TLS with `VerifyClientCertIfGiven`. Proxy routes require client cert; onboard endpoint does not.

**Design note**: `isInternalListener()` identifies internal requests by the presence of `ContextKeyInternal` in the request context, set by `MarkInternalRequest` middleware applied exclusively on the internal listener mux. This positive-signal approach ensures an auth bypass on the external listener cannot be misread as an internal request.

## Exec Guard Prerequisites

`ResourceGuard.ExecGuard` is applied on the external listener. It performs a Docker API back-query to determine which stack the exec target belongs to. Exec on a protected-stack container requires admin role; exec on any other container is allowed for all authenticated users.

Without mTLS (`PROXY_TLS_CLIENT_CA` not set), no caller can prove identity. Exec on protected-stack containers is still blocked (no user = not admin). Non-protected containers are accessible without identity — use `PROXY_INTERNAL_LISTEN` when unathenticated local exec is needed. Bootstrap always configures mTLS.

A back-query error (Docker daemon unreachable) causes fail-closed (503) rather than allowing exec through.

## API Endpoints

- `POST /api/v1/users` — Create user (`{"username":"alice","role":"operator"}`; role ∈ {admin, operator, viewer}, default operator) → 201 `{"user":{…},"onboard_token":"<hex>","onboard_url":"<external>/api/v1/onboard/<token>"}`. Also creates the matching RBAC binding (admin→admin, operator→operator, viewer→viewer) so the legacy `User.Role` and the RBAC binding stay in sync. The private key is **not** returned — it is generated on the user's machine when they redeem the token at the onboard endpoint.
- `GET /api/v1/users` — List all users (200, always returns array)
- `PATCH /api/v1/users/{username}` — Update user (`{"enabled":false}` and/or `{"role":"viewer"}`) → 200 with the updated user. Refuses self-disable / self-role-change (409) and any change that would remove the last admin (409); a role change replaces the user's bindings and updates `User.Role` atomically.
- `POST /api/v1/users/{username}/regenerate-token` — Issue a fresh one-time onboard token → 200 `{"onboard_token":…,"onboard_url":…}` (404 if user not found)
- `DELETE /api/v1/users/{username}` — Delete user (204 on success, 404 if not found). Refuses to delete the caller themselves (409) or the last admin (409), and cascades the user's role bindings.
- `GET|POST /api/v1/roles`, `GET|PUT|DELETE /api/v1/roles/{name}` — RBAC role CRUD (admin-authorized: bearer token OR mTLS admin). Built-in roles can't be deleted (409); in-use roles can't be deleted (409); updates that would remove the last admin are refused (409)
- `GET|POST /api/v1/bindings`, `DELETE /api/v1/bindings/{id}` — user→role bindings (admin-authorized). Deleting the last admin binding is refused (409)
- `GET /api/v1/onboard/{token}` — One-time onboarding: consumes token, issues client cert, returns Docker-context-compatible tar (no auth required, token is the auth)
- `GET /api/v1/me` — Returns the authenticated caller's own `{"username","role"}`, derived from their mTLS client cert (cert-authenticated via `RequireClientCert`, not the admin token). Lets a client learn its own role without attempting a mutating operation. Returns 401 on the internal listener / when no client identity is present. (Used by the CLI's proactive infra-update prompt to decide whether to offer an upgrade.)
- `GET|POST /_swc/startbackup` (alias `/startbackup`) — **Internal listener only.** Triggers a database-only logical backup (never the CA, onboarding tokens always redacted), writes it to the default backup dir on the `proxy-data` volume (`<db-dir>/backup/swc-proxy-backup-<datetime>.json`; `-N` suffix on same-second collision), and returns `{"result":"success","file":...,"path":...}`. Audited as `backup.exported` (actor `internal`). See [docs/backup-restore.md](docs/backup-restore.md).
- `GET /_swc/version` — **Internal listener only.** Reports build identity `{"version","commit","date"}`. Its presence (200 vs a Docker-fall-through 404 on an older build) is the "is this binary current?" signal.
- The whole `/_swc/` control-plane namespace is gated by `mountControlPlane(mux, internal, …)` so it is absent from the external mux; unknown `/_swc/*` paths get a branded JSON 404 instead of falling through to the Docker proxy (PR #107).
- `/v1/*` — Forwarded to agent-manager (when `PROXY_AGENT_MANAGER_URL` is set; supports HTTP and WebSocket upgrade)
- `/*` — Proxied to Docker daemon

## Admin CLI (`swcproxy`)

Runs inside the proxy container via `docker exec`. Accesses the store directly (no HTTP).

```bash
swcproxy version                          # Show version
swcproxy user ls                          # List users
swcproxy user add <username> [--admin]    # Create user + onboarding token
swcproxy user delete <username>           # Delete user
swcproxy user regenerate-token <username> # New onboarding token
swcproxy audit ls [--limit N]             # List audit log entries (default: 50)
swcproxy role ls                          # List roles
swcproxy role show <name>                 # Show a role's rules
swcproxy binding ls                       # List role bindings
swcproxy binding add <user> <role>        # Bind a user to a role
swcproxy binding rm <id>                  # Remove a role binding (last-admin protected)
swcproxy backup [-o <file>] [--include-ca] [--include-tokens] # Logical JSON export of users + audit + RBAC roles/bindings. Onboarding tokens redacted unless --include-tokens; optional CA bundle (--include-ca requires a file dest). Without -o: a terminal writes a timestamped file to <db-dir>/backup; a pipe streams JSON to stdout
swcproxy restore [-i <file>] [--force] [--ca-out <dir>] # Import a backup verbatim (single transaction across all tables)
swcproxy --help                           # Usage info
```

`swcproxy user add` also creates a matching role binding (`--admin` → `admin`, else `operator`) so the legacy role and RBAC binding stay in sync.

Backup/restore is a logical export (portable across sqlite/postgres), not a
file copy. The client CA lives in Docker secrets, **not** the database — see
[docs/backup-restore.md](docs/backup-restore.md) for why a DB restore alone
does not preserve user connections, and the `--include-ca` DR bundle.

## Logging

zap, via `internal/log` (package `proxylog`): `Init(mode, level)` for the
server, `InitTo(w, mode, level)` for the `swcproxy` CLI so that command output
on stdout (a `backup` JSON artifact) stays clean. `dev` mode is a console
encoder, anything else is JSON; the level is `debug|info|warn|error`, defaulting
to debug in dev and info in prod. `L()` returns a no-op logger if `Init` was
never called, so a missed initialisation is silence rather than a nil panic.

This already meets the ecosystem logging contract, and nothing here needs to
change — the note exists so the next person does not "fix" it into slog for
consistency's sake. What the daemons across the repos agree on is the contract,
not the library:

- structured key/value pairs, never a formatted sentence
- an ISO-8601 timestamp, a level, and a message field
- the level and the output format both selectable at deploy time
- JSON available for whatever ships the logs, human-readable the default
- one logger per process, on one stream

One line per request goes through the same logger (`accessLog`, `accesslog.go`):
method, path, status, bytes, duration, remote IP and the mTLS caller. A **served**
request logs at **debug** and anything the proxy refused or could not complete
logs at **info** — so the default level shows only failures, and a full request
trace is one `PROXY_LOG_LEVEL=debug` away. The onboarding token is a path
segment, so `redactPath` keeps it out of the log; it is the only path that is
redacted, because Docker resource IDs and filters are what make a line useful.

The standard library's own loggers are wired into this one too, via
`proxylog.StdErrorLogger` — `http.Server.ErrorLog` on every listener and
`httputil.ReverseProxy.ErrorLog`. Unset, they write to `log.Default()`, which is
a second stream in a second format that `PROXY_LOG_LEVEL` cannot reach, and is
how the proxy used to emit unstructured `http: proxy error: …` lines alongside
its JSON.

swarmcli-cd meets it with `log/slog` and `--log-level` / `--log-format` flags;
swarmcli-agent meets it with `log/slog` and `AGENT_LOG_*` environment variables
(it parses no flags). swarmcli and swarmcli-be stay on zap with lumberjack file
rotation under `~/.local/state`, because a TUI cannot log to the terminal it
owns — that is the one deliberate exception to "on one stream".

## Audit Log

All business actions are persisted to an `audit_log` table (same database as users). **The full action vocabulary and the record shape are in [docs/rbac.md § Auditing](docs/rbac.md#auditing)** — that is where someone writing a SIEM rule will look, so add new actions there, not only here.

Two things to hold on to when adding an action: `rbac.denied` and `guard.blocked` are deliberately distinct (policy engine vs protected-stack guard, and volume denials use `guard.blocked`), and mTLS auth events go to zap only and are never persisted — so the table cannot answer an authentication question.

The `AuditStore` interface (`internal/store/store.go`) is implemented by all three store backends. Recording is nil-safe — handlers pass `nil` in tests. Audit write failures are logged but never block requests.

## CI

GitHub Actions — all six of `.github/workflows/`:
- `ci.yml`: three jobs. `ci` (no DB) runs four steps — gofmt check, **`go mod tidy` + diff check**, `go test -race`, golangci-lint; `docker-build` builds the image and depends on `ci`; `integration` runs the PostgreSQL 17 suite.
- `licence.yml`: SPDX license header check (`.go` and `.sh` files).
- `check_labels.yml`: enforces the A/B/C label triple on every PR. It reads labels from the `pull_request` **event payload**, not the API, so a run queued from `opened` sees none and only a new event fixes it — never a job re-run.
- `govulncheck.yml`: scheduled vulnerability scan.
- `dependabot-tidy.yml`: keeps `go.sum` tidy on Dependabot PRs.
- `release.yml`: see [Release](#release) below.

## Release

GitHub Actions (`.github/workflows/release.yml`): triggered on `v*` tags. Three parallel jobs:
1. **release-drafter**: Creates draft release notes from PR labels.
2. **goreleaser**: Builds Linux binaries (amd64/arm64) for both `proxy` and `swcproxy`, publishes GitHub release with archives.
3. **docker**: Builds and pushes Docker image to Docker Hub as `eldaratech/swarmcli-rbac-proxy` with version injection via `--build-arg`.

Docker image tags: `{version}` and `{major}.{minor}` (via `docker/metadata-action`).
Requires `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets.

See `RELEASING.md` for local testing and manual release process.

**Versioning.** A `C1-breaking-change` PR merged since the last GA forces a **major** tag (`vX.0.0`); the pushed tag is authoritative (it overrides release-drafter's `$RESOLVED_VERSION`). The published release notes are type-only (no dedicated "Breaking" section); the customer-facing upgrade story for proxy changes that reach BE users is captured in swarmcli-be's `.github/UPGRADE_NOTES.md` when BE bumps its compat pin across an rbac-proxy major.

## Pre-push Checklist

Always run before pushing:
```bash
go build . && go test -race ./... && gofmt -l . && go vet ./... && golangci-lint run
```

## Known Gaps

Only what is still open. Resolved audit findings (#55, #56, #57, #59, #60, #63)
were struck through here for a while, which made this a changelog; the resulting
behaviour is documented where it belongs — the inter-service mTLS chain that
closed #63 is [docs/security.md § Overlay network
trust](docs/security.md#overlay-network-trust), and `git log` is the record of
the rest.

- **#62**: no certificate rotation mechanism — client certs are valid for 1 year and there is no CRL or OCSP. Revocation means deleting the user, after which the proxy rejects the cert because its CN no longer matches an enabled user. Stated for operators in [docs/security.md § Certificate lifecycle](docs/security.md).
- **#64** (partial): the proxy now refuses to start when `PROXY_ADMIN_TOKEN` is empty and the store holds ≥1 admin, but persisting the token across redeploys is still operator responsibility.
- **#75**: the Dockerfile runs as root — accepted. The proxy needs Docker socket access, which is root-equivalent, so a non-root image would need a root-start entrypoint for negligible benefit.

## Dependencies

- `modernc.org/sqlite` — Pure Go SQLite driver (used by `internal/store/sqlite.go`)
- `github.com/jackc/pgx/v5` — PostgreSQL driver (used only by `internal/store/postgres.go`)
- `go.uber.org/zap` — Structured logging (used by `internal/log/logger.go`)
