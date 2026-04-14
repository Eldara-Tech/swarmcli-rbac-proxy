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

## Configuration

See [docs/configuration.md](docs/configuration.md) for all environment variables and config.json reference.

Key env vars: `PROXY_TLS_CERT`, `PROXY_TLS_KEY` (frontend TLS), `PROXY_TLS_CLIENT_CA` (frontend mTLS — enables client certificate authentication), `PROXY_TLS_CLIENT_CA_KEY` (CA private key — enables auto-generating client certs on user creation), `PROXY_ADMIN_TOKEN` (management API bearer token), `PROXY_SEED_USERNAME` (bootstrap first user at startup), `PROXY_SEED_ROLE` (role for seed user, default "user"), `PROXY_EXTERNAL_URL` (external proxy URL for onboarding curl instructions), `PROXY_INTERNAL_LISTEN` (internal plain TCP listener address, e.g. "127.0.0.1:2375"), `PROXY_PROTECTED_STACK` (stack name to protect; auto-detected from container labels if unset).

## Agent Proxy Forwarding

When `PROXY_AGENT_URL` (env) or `agent_proxy_url` (JSON config) is set, all `/v1/*` requests are forwarded to the specified backend (e.g. `tcp://agent-host:9090`). This covers `/v1/exec`, `/v1/logs`, and other agent endpoints. Both normal HTTP and WebSocket upgrade (hijack) connections are supported via the same `newProxy` handler used for the Docker backend.

The `/v1/exec` endpoint is restricted to admin users on the external listener. Non-admin users receive 403. The internal listener bypasses this check.

## Stack Resource Protection

When running inside a Docker Swarm stack, the proxy auto-detects its own stack name from container labels (`com.docker.stack.namespace`). Override with `PROXY_PROTECTED_STACK`.

### Permission matrix

| Operation on protected resource | Internal listener | External admin | External user |
|---------------------------------|-------------------|----------------|---------------|
| Read (GET)                      | allowed           | allowed        | allowed       |
| Create (POST .../create)        | allowed           | blocked (403)  | blocked (403) |
| Update (POST .../update)        | allowed           | allowed        | blocked (403) |
| Delete (DELETE .../{id})        | allowed           | blocked (403)  | blocked (403) |
| Exec/attach (all containers)    | allowed           | allowed        | blocked (403) |
| Swarm leave (POST /swarm/leave) | allowed           | blocked (403)  | blocked (403) |

All operations on **non-protected** resources are allowed for all roles.

If auto-detection fails (e.g. running outside Docker) and `PROXY_PROTECTED_STACK` is not set, the guard is disabled and all operations are allowed.

### Rationale

- **Create blocked for all external users**: prevents namespace pollution — injecting resources into the infrastructure namespace could interfere with stack operations (name collisions, label conflicts). Legitimate deployments use `docker stack deploy` via the internal listener.
- **Update allowed for admins**: routine operations (image deploys, scaling, secret rotation) require updating protected services through the proxy.
- **Delete blocked for all external users**: destructive — removing infrastructure services can make the cluster unmanageable. Only recoverable via direct container access (internal listener).
- **Exec/attach admin-only**: shell access enables privilege escalation (e.g. direct database access via `swcproxy` CLI). Non-admin users are blocked from all exec/attach — both Docker API and agent API (`/v1/exec`).
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
      store.go          — UserStore interface (CRUD + DeleteUser + onboard tokens), User type (with Role), sentinel errors
      memory.go         — in-memory UserStore (dev/testing)
      sqlite.go         — SQLite UserStore (modernc.org/sqlite, default, with migrations)
      postgres.go       — PostgreSQL UserStore (pgx/v5, with migrations)
      contract_test.go  — shared contract tests for all store implementations
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

**Design note**: `isInternalListener()` identifies internal requests by the *absence* of a user in the request context. This works because the internal listener does not apply `RequireClientCert`, so no user is ever set. See #56 for planned improvement to use a positive context signal instead.

## Exec Guard Prerequisites

The `RequireAdminForExec` middleware requires `PROXY_TLS_CLIENT_CA` to be set — without mTLS there is no user identity, so the guard is disabled (no-op). When deploying via bootstrap (`stack.yaml.tmpl`), this is always configured. The dev `stack.yml` in this repo does **not** set TLS and therefore has no exec protection.

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
swcproxy --help                           # Usage info
```

## CI

GitHub Actions (`.github/workflows/ci.yml`): three jobs.
- `ci`: gofmt check, `go test -race`, golangci-lint (fast, no DB).
- `docker-build`: builds Docker image (depends on `ci`).
- `integration`: PostgreSQL 17 service container, `go test -race -tags=integration`.

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
- **#56**: `isInternalListener` uses absence of user context as signal — planned positive-signal improvement
- **#57**: Integration tests use `RequireAndVerifyClientCert` but production uses `VerifyClientCertIfGiven`
- **#60**: `ResourceGuard` fails open on back-query errors (including delete operations)
- **#62**: No certificate rotation mechanism (client certs expire after 1 year)
- **#63**: No authentication between rbac-proxy, agent-proxy, and agent (relies on overlay network isolation)
- **#64**: Admin token not persisted across redeployments

## Dependencies

- `modernc.org/sqlite` — Pure Go SQLite driver (used by `internal/store/sqlite.go`)
- `github.com/jackc/pgx/v5` — PostgreSQL driver (used only by `internal/store/postgres.go`)
- `go.uber.org/zap` — Structured logging (used by `internal/log/logger.go`)
