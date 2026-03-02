# swarm-rbac-proxy

Transparent reverse proxy that relays Docker API requests from TCP to a Unix socket. Designed to sit between `docker context` clients and the Docker daemon, with RBAC enrichment planned for later.

## Build / Test / Run

```bash
go build .                           # compile
go test -v -race ./...               # run tests
gofmt -l .                           # check formatting
go vet ./...                         # lint
golangci-lint run                    # lint (superset, used by CI)
./swarm-rbac-proxy                   # run (needs docker.sock)
docker build -t swarm-rbac-proxy .   # container image
docker stack deploy -c stack.yml rbac  # deploy to Swarm
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PROXY_LISTEN` | `:2375` (`:2376` with frontend TLS) | TCP listen address |
| `PROXY_DOCKER_URL` | _(none)_ | Docker endpoint URL (`unix:///path` or `tcp://host:port`). Mutually exclusive with `PROXY_DOCKER_SOCKET` |
| `PROXY_DOCKER_SOCKET` | `/var/run/docker.sock` | Path to Docker socket (legacy; prefer `PROXY_DOCKER_URL`) |
| `PROXY_TLS_CERT` | _(none)_ | Frontend TLS certificate path |
| `PROXY_TLS_KEY` | _(none)_ | Frontend TLS key path |
| `PROXY_DOCKER_TLS_CA` | _(none)_ | CA cert to verify remote Docker server |
| `PROXY_DOCKER_TLS_CERT` | _(none)_ | Client cert for backend mTLS |
| `PROXY_DOCKER_TLS_KEY` | _(none)_ | Client key for backend mTLS |

## Architecture

```
swarm-rbac-proxy/
  main.go               — reverse proxy: TCP → docker.sock/remote, with HTTP upgrade and backend TLS support
  main_test.go          — unit tests against mock Unix socket
  integration_test.go   — TLS integration tests (plain→TLS, mTLS, upgrade through TLS)
  Dockerfile            — multi-stage build (golang:1.25-alpine → alpine:3.21)
  stack.yml             — Docker Swarm stack definition
```

## CI

GitHub Actions (`.github/workflows/ci.yml`): gofmt check, `go test -race`, golangci-lint. Runs on push to `main` and PRs. Single job to conserve private-repo minutes.

Single-file stdlib-only Go proxy. `httputil.ReverseProxy` handles normal requests; a custom hijack handler covers `Connection: Upgrade` (exec, attach). No external dependencies.
