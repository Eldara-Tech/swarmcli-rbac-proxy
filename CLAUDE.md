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
