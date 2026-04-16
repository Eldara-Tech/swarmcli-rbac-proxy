# swarmcli-rbac-proxy

Transparent reverse proxy that relays Docker API requests from TCP to a Unix socket, with multi-user mTLS authentication and role-based access control.

## Maintaining this file

Keep CLAUDE.md up to date. When adding new files, endpoints, env vars, CI jobs, or dependencies, update the relevant sections here as part of the same change.

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

Go 1.26. No Makefile.

When updating the Go version, keep these in sync:
- `go.mod` — `go` and `toolchain` directives
- `.devcontainer/Dockerfile` — `mcr.microsoft.com/devcontainers/go` image tag (tracks major.minor; patch versions are handled by `GOTOOLCHAIN=auto`)
- `govulncheck` CI step — bump suppressed vuln IDs if the new toolchain resolves them, or add new ones if it introduces new unfixed stdlib vulns

## Configuration

See [docs/configuration.md](docs/configuration.md) for all environment variables and config.json reference.

Key env vars: `PROXY_TLS_CERT`, `PROXY_TLS_KEY` (frontend TLS), `PROXY_TLS_CLIENT_CA` (frontend mTLS — enables client certificate authentication), `PROXY_TLS_CLIENT_CA_KEY` (CA private key — enables auto-generating client certs on user creation), `PROXY_ADMIN_TOKEN` (management API bearer token), `PROXY_SEED_USERNAME` (bootstrap first user at startup), `PROXY_SEED_ROLE` (role for seed user, default "user"), `PROXY_EXTERNAL_URL` (external proxy URL for onboarding curl instructions), `PROXY_INTERNAL_LISTEN` (internal plain TCP listener address, e.g. "127.0.0.1:2375"), `PROXY_PROTECTED_STACK` (stack name to protect; auto-detected from container labels if unset).

## Agent Proxy Forwarding

When `PROXY_AGENT_URL` (env) or `agent_proxy_url` (JSON config) is set, all `/v1/*` requests are forwarded to the specified backend (e.g. `tcp://agent-host:9090`). This covers `/v1/exec`, `/v1/logs`, and other agent endpoints. Both normal HTTP and WebSocket upgrade (hijack) connections are supported via the same `newProxy` handler used for the Docker backend.

The `/v1/exec` endpoint on the external listener is stack-aware: exec/attach targeting a container in the protected stack requires admin role; exec/attach targeting any other stack is allowed for all authenticated users. The internal listener (wired with `noExecGuard`) bypasses this check entirely.

## Stack Resource Protection

When running inside a Docker Swarm stack, the proxy auto-detects its own stack name from container labels (`com.docker.stack.namespace`). Override with `PROXY_PROTECTED_STACK`.

### Permission matrix

| Operation | Internal listener | External admin | External user |
|-----------|-------------------|----------------|---------------|
| Read (GET) — any resource | allowed | allowed | allowed |
| Create (POST .../create) — protected stack | allowed | blocked (403) | blocked (403) |
| Create (POST .../create) — other stack | allowed | allowed | allowed |
| Update (POST .../update) — protected stack | allowed | allowed | blocked (403) |
| Update (POST .../update) — other stack | allowed | allowed | allowed |
| Delete (DELETE .../{id}) — protected stack | allowed | blocked (403) | blocked (403) |
| Delete (DELETE .../{id}) — other stack | allowed | allowed | allowed |
| Exec/attach — protected stack container | allowed | allowed | blocked (403) |
| Exec/attach — non-protected container | allowed | allowed | allowed |
| Swarm leave (POST /swarm/leave) | allowed | blocked (403) | blocked (403) |

If auto-detection fails (e.g. running outside Docker) and `PROXY_PROTECTED_STACK` is not set, the guard is disabled and all operations are allowed.

### Rationale

- **Create blocked for all external users on protected stack**: prevents namespace pollution — injecting resources into the infrastructure namespace could interfere with stack operations (name collisions, label conflicts). Legitimate deployments use `docker stack deploy` via the internal listener.
- **Update allowed for admins on protected stack**: routine operations (image deploys, scaling, secret rotation) require updating protected services through the proxy.
- **Delete blocked for all external users on protected stack**: destructive — removing infrastructure services can make the cluster unmanageable. Only recoverable via direct container access (internal listener).
- **Exec/attach admin-only for protected stack**: shell access to infrastructure containers enables privilege escalation (e.g. direct database access via `swcproxy` CLI). Regular users may exec into their own service containers freely.
- **Swarm leave blocked for all external users**: destructive — tears down the entire cluster. Only via internal listener.

## Architecture

```
swarm-rbac-proxy/
  main.go               — reverse proxy + dual listener routing (internal plain TCP + external mTLS)
  main_test.go          — unit tests against mock Unix socket
  integration_test.go   — TLS integration tests (plain→TLS, mTLS, upgrade through TLS, frontend mTLS)
  Dockerfile            — multi-stage build (golang:1.26-alpine → alpine:3.23), builds proxy + swcproxy (/usr/local/bin), welcome banner via profile.d, CMD so /bin/sh stays usable
  welcome.sh            — container login banner (COPY'd to /etc/profile.d/welcome.sh)
  stack.yml             — Docker Swarm stack definition
  cmd/
    swcproxy/
      main.go           — Admin CLI: user ls/add/delete/regenerate-token (direct store access)
  internal/
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
      store.go          — UserStore + AuditStore interfaces, User/AuditEntry types, AuditAction constants, sentinel errors
      memory.go         — in-memory UserStore + AuditStore (dev/testing)
      sqlite.go         — SQLite UserStore + AuditStore (modernc.org/sqlite, default, with migrations)
      postgres.go       — PostgreSQL UserStore + AuditStore (pgx/v5, with migrations)
      contract_test.go  — shared contract tests for all store implementations (user + audit)
      memory_test.go    — memory store unit tests
      sqlite_test.go    — SQLite store unit tests (contract + WAL)
      postgres_test.go  — postgres integration tests (//go:build integration)
    api/
      auth.go           — RequireToken middleware (bearer token validation)
      auth_test.go      — auth middleware tests
      mtls.go           — RequireClientCert middleware (mTLS client cert → user lookup)
      mtls_test.go      — mTLS middleware unit tests
      users.go          — UserHandler: POST/GET /api/v1/users, DELETE /api/v1/users/{username}
      users_test.go     — handler tests using MemoryStore
      onboard.go        — OnboardHandler: GET /api/v1/onboard/{token} → Docker-context tar
      onboard_test.go   — onboard handler tests
      guard.go          — ResourceGuard middleware: protects bootstrap stack from non-admin mutation; RequireAdminForExec: admin-only exec/attach
      guard_test.go     — guard middleware tests (path parsing, admin check, back-query, body inspection)
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

- `POST /api/v1/users` — Create user (`{"username":"alice","role":"admin"}` → 201 with user object; includes `certificate` bundle when `PROXY_TLS_CLIENT_CA_KEY` is set)
- `GET /api/v1/users` — List all users (200, always returns array)
- `DELETE /api/v1/users/{username}` — Delete user (204 on success, 404 if not found)
- `GET /api/v1/onboard/{token}` — One-time onboarding: consumes token, issues client cert, returns Docker-context-compatible tar (no auth required, token is the auth)
- `/v1/*` — Forwarded to agent proxy (when `PROXY_AGENT_URL` is set; supports HTTP and WebSocket upgrade)
- `/*` — Proxied to Docker daemon

## Admin CLI (`swcproxy`)

Runs inside the proxy container via `docker exec`. Accesses the store directly (no HTTP).

```bash
swcproxy user ls                          # List users
swcproxy user add <username> [--admin]    # Create user + onboarding token
swcproxy user delete <username>           # Delete user
swcproxy user regenerate-token <username> # New onboarding token
swcproxy audit ls [--limit N]             # List audit log entries (default: 50)
swcproxy --help                           # Usage info
```

## Audit Log

All business actions are persisted to an `audit_log` table (same database as users). Audited actions: `user.created`, `user.deleted`, `cert.issued`, `onboard.completed`, `guard.blocked`, `token.regenerated`. Auth events (mTLS success/failure) are logged via zap only, not persisted.

Each entry records: id, timestamp, actor (username/"cli"/"anonymous"), action, resource (`type:id` format), status ("success"/"denied"), detail, source\_ip.

The `AuditStore` interface (`internal/store/store.go`) is implemented by all three store backends. Recording is nil-safe — handlers pass `nil` in tests. Audit write failures are logged but never block requests.

## CI

GitHub Actions (`.github/workflows/`):
- `ci.yml`: three jobs — gofmt check, `go test -race`, golangci-lint (fast, no DB); Docker image build (depends on `ci`); PostgreSQL 17 integration tests.
- `licence.yml`: SPDX license header check (`.go` and `.sh` files).

## Release

GitHub Actions (`.github/workflows/release.yml`): triggered on `v*` tags.
- Builds and pushes Docker image to Docker Hub as `eldaratech/swarmcli-rbac-proxy`.
- Tags: `{version}` and `{major}.{minor}` (via `docker/metadata-action`).
- Requires `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets.

## Pre-push Checklist

Always run before pushing:
```bash
go build . && go test -race ./... && gofmt -l . && go vet ./... && golangci-lint run
```

## Known Gaps

Tracked issues from architecture audit:

- **#55**: `isExecPath` missed `GET /containers/{id}/attach/ws` (WebSocket attach) — fixed
- **#56**: ~~`isInternalListener` uses absence of user context as signal~~ — fixed: now uses positive `ContextKeyInternal` flag set by `MarkInternalRequest`
- **#57**: ~~Integration tests use `RequireAndVerifyClientCert` but production uses `VerifyClientCertIfGiven`~~ — fixed: all frontend tests now use `VerifyClientCertIfGiven`, added no-cert client tests
- **#59**: ~~Exec guard silently disabled without mTLS~~ — fixed: always applied on external listener (fail-closed)
- **#60**: ~~`ResourceGuard` fails open on back-query errors (including delete operations)~~ — fixed: deletes now fail closed (503) on back-query errors
- **#62**: No certificate rotation mechanism (client certs expire after 1 year)
- **#63**: No inter-service authentication — accepted risk: overlay network isolation (`internal: true`, `encrypted: "true"`) is sufficient; see `docs/security.md` § "Overlay network trust"
- **#64**: Admin token not persisted across redeployments
- **#75**: Dockerfile runs as root — accepted risk: proxy requires Docker socket access, which is root-equivalent. Non-root would need root-start entrypoint for negligible benefit. Same reasoning as #63.

## Dependencies

- `modernc.org/sqlite` — Pure Go SQLite driver (used by `internal/store/sqlite.go`)
- `github.com/jackc/pgx/v5` — PostgreSQL driver (used only by `internal/store/postgres.go`)
- `go.uber.org/zap` — Structured logging (used by `internal/log/logger.go`)
