# swarmcli-rbac-proxy

Transparent reverse proxy that relays Docker API requests from TCP to a Unix socket. Includes a management API for user CRUD, the foundation for future RBAC.

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

Key env vars: `PROXY_TLS_CERT`, `PROXY_TLS_KEY` (frontend TLS), `PROXY_TLS_CLIENT_CA` (frontend mTLS — enables client certificate authentication), `PROXY_TLS_CLIENT_CA_KEY` (CA private key — enables auto-generating client certs on user creation), `PROXY_ADMIN_TOKEN` (management API bearer token), `PROXY_SEED_USERNAME` (bootstrap first user at startup), `PROXY_SEED_ROLE` (role for seed user, default "user"), `PROXY_EXTERNAL_URL` (external proxy URL for onboarding curl instructions), `PROXY_INTERNAL_LISTEN` (internal plain TCP listener address, e.g. "127.0.0.1:2375").

## Agent Proxy Forwarding

When `PROXY_AGENT_URL` (env) or `agent_proxy_url` (JSON config) is set, all `/v1/*` requests are forwarded to the specified backend (e.g. `tcp://agent-host:9090`). This covers `/v1/exec`, `/v1/logs`, and other agent endpoints. Both normal HTTP and WebSocket upgrade (hijack) connections are supported via the same `newProxy` handler used for the Docker backend.

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
```

## Dual Listener

When `PROXY_INTERNAL_LISTEN` is set, the proxy runs two listeners:
- **Internal** (`PROXY_INTERNAL_LISTEN`, e.g. `127.0.0.1:2375`): plain TCP, no mTLS, for admin access inside the container.
- **External** (`PROXY_LISTEN`, e.g. `:2376`): TLS with `VerifyClientCertIfGiven`. Proxy routes require client cert; onboard endpoint does not.

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

## Dependencies

- `modernc.org/sqlite` — Pure Go SQLite driver (used by `internal/store/sqlite.go`)
- `github.com/jackc/pgx/v5` — PostgreSQL driver (used only by `internal/store/postgres.go`)
- `go.uber.org/zap` — Structured logging (used by `internal/log/logger.go`)
