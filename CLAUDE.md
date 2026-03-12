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

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PROXY_CONFIG` | _(none)_ | Path to a `config.json` file. When set, values are loaded from the file first, then overridden by any env vars that are set |
| `PROXY_LISTEN` | `:2375` (`:2376` with frontend TLS) | TCP listen address |
| `PROXY_DOCKER_URL` | _(none)_ | Docker endpoint URL (`unix:///path` or `tcp://host:port`). Mutually exclusive with `PROXY_DOCKER_SOCKET` |
| `PROXY_DOCKER_SOCKET` | `/var/run/docker.sock` | Path to Docker socket (legacy; prefer `PROXY_DOCKER_URL`) |
| `PROXY_TLS_CERT` | _(none)_ | Frontend TLS certificate path |
| `PROXY_TLS_KEY` | _(none)_ | Frontend TLS key path |
| `PROXY_DOCKER_TLS_CA` | _(none)_ | CA cert to verify remote Docker server |
| `PROXY_DOCKER_TLS_CERT` | _(none)_ | Client cert for backend mTLS |
| `PROXY_DOCKER_TLS_KEY` | _(none)_ | Client key for backend mTLS |
| `PROXY_STORE` | `sqlite` | Store backend: `sqlite`, `memory`, or `postgres` |
| `PROXY_DATABASE_PATH` | `proxy.db` | SQLite database file path (used when `PROXY_STORE=sqlite`) |
| `PROXY_DATABASE_URL` | _(none)_ | PostgreSQL connection string (required when `PROXY_STORE=postgres`) |
| `PROXY_ADMIN_TOKEN` | _(none)_ | Bearer token for management API auth. When set, `/api/v1/*` requires `Authorization: Bearer <token>` |
| `PROXY_ENV` | `prod` | Logging mode: `dev` (console encoder) or `prod` (JSON encoder) |
| `PROXY_LOG_LEVEL` | `debug` (dev) / `info` (prod) | Minimum log level: `debug`, `info`, `warn`, `error` |

## Architecture

```
swarm-rbac-proxy/
  main.go               — reverse proxy + mux routing (/api/v1/ → handlers, / → Docker proxy)
  main_test.go          — unit tests against mock Unix socket
  integration_test.go   — TLS integration tests (plain→TLS, mTLS, upgrade through TLS)
  Dockerfile            — multi-stage build (golang:1.25-alpine → alpine:3.21)
  stack.yml             — Docker Swarm stack definition
  internal/
    config/
      config.go         — Config struct, Load(path) merges JSON file + env vars + defaults
      config_test.go    — config loading unit tests
    log/
      logger.go         — proxylog package: zap-based structured logging (Init/L/Sync/With)
      logger_test.go    — logger unit tests (mode detection, level defaults, noop safety)
    store/
      store.go          — UserStore interface, User type, sentinel errors, UUID helper
      memory.go         — in-memory UserStore (dev/testing)
      sqlite.go         — SQLite UserStore (modernc.org/sqlite, default)
      postgres.go       — PostgreSQL UserStore (pgx/v5)
      contract_test.go  — shared contract tests for all store implementations
      memory_test.go    — memory store unit tests
      sqlite_test.go    — SQLite store unit tests (contract + WAL)
      postgres_test.go  — postgres integration tests (//go:build integration)
    api/
      auth.go           — RequireToken middleware (bearer token validation)
      auth_test.go      — auth middleware tests
      users.go          — UserHandler: POST/GET /api/v1/users
      users_test.go     — handler tests using MemoryStore
```

## API Endpoints

- `POST /api/v1/users` — Create user (`{"username":"alice"}` → 201 with user object)
- `GET /api/v1/users` — List all users (200, always returns array)
- `/*` — Proxied to Docker daemon

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
