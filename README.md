# swarm-rbac-proxy

Transparent reverse proxy that relays Docker API requests from TCP to a Unix socket. Sits between `docker context` clients and the Docker daemon, with RBAC enrichment planned for later.

## Quick start

```bash
go build .
./swarm-rbac-proxy
```

Listens on `:2375` and forwards to `/var/run/docker.sock` by default.

## Configuration

All configuration is via environment variables.

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
| `PROXY_STORE` | `sqlite` | Store backend: `sqlite`, `memory`, or `postgres` |
| `PROXY_DATABASE_PATH` | `proxy.db` | SQLite database file path (when `PROXY_STORE=sqlite`) |
| `PROXY_DATABASE_URL` | _(none)_ | PostgreSQL connection string (required when `PROXY_STORE=postgres`) |
| `PROXY_ADMIN_TOKEN` | _(none)_ | Bearer token for management API auth. When set, `/api/v1/*` requires `Authorization: Bearer <token>` |

### Remote Docker (TCP)

Point the proxy at a remote Docker daemon instead of a local socket:

```bash
PROXY_DOCKER_URL=tcp://remote-host:2375 ./swarm-rbac-proxy
```

### Remote Docker with TLS

Connect to a TLS-protected Docker daemon:

```bash
PROXY_DOCKER_URL=tcp://remote-host:2376 \
  PROXY_DOCKER_TLS_CA=/path/to/ca.pem \
  PROXY_DOCKER_TLS_CERT=/path/to/client-cert.pem \
  PROXY_DOCKER_TLS_KEY=/path/to/client-key.pem \
  ./swarm-rbac-proxy
```

The proxy serves plain HTTP on `:2375` while connecting to the backend over TLS.

### Frontend TLS

Set both `PROXY_TLS_CERT` and `PROXY_TLS_KEY` to serve TLS to clients (default port switches to `:2376`):

```bash
PROXY_TLS_CERT=/path/to/cert.pem PROXY_TLS_KEY=/path/to/key.pem ./swarm-rbac-proxy
```

### Data Store

The proxy stores user data in one of three backends, selected via `PROXY_STORE`.

**SQLite (default)** — no configuration required. Creates `proxy.db` in the working directory:

```bash
./swarm-rbac-proxy  # uses proxy.db in current directory
```

Override the file location:

```bash
PROXY_DATABASE_PATH=/data/rbac.db ./swarm-rbac-proxy
```

**PostgreSQL** — set `PROXY_STORE=postgres` and provide a connection string:

```bash
PROXY_STORE=postgres \
  PROXY_DATABASE_URL="postgres://user:password@db-host:5432/rbac?sslmode=disable" \
  ./swarm-rbac-proxy
```

The connection string follows the standard PostgreSQL URI format: `postgres://user:password@host:port/database?options`. The proxy creates the `users` table automatically if it does not exist (in the default `public` schema).

**In-memory** — data is lost on restart, useful for development:

```bash
PROXY_STORE=memory ./swarm-rbac-proxy
```

### Management API Authentication

Protect the management API with a bearer token:

```bash
PROXY_ADMIN_TOKEN=my-secret-token ./swarm-rbac-proxy
```

All `/api/v1/*` requests must then include the token:

```bash
curl -s http://localhost:2375/api/v1/users \
  -H "Authorization: Bearer my-secret-token"
```

Without the token, requests return `401 Unauthorized`. Docker proxy routes are unaffected.

If `PROXY_ADMIN_TOKEN` is not set, the management API is open (a warning is logged at startup).

## Docker

```bash
docker build -t swarm-rbac-proxy .
docker run -d \
  -p 2376:2376 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  swarm-rbac-proxy
```

## Swarm deployment

A `stack.yml` is included for Docker Swarm. It constrains the proxy to manager nodes and mounts the Docker socket:

```bash
docker stack deploy -c stack.yml rbac
```

## Docker context

Point a Docker client at the proxy:

```bash
docker context create via-proxy --docker "host=tcp://<proxy-host>:2375"
docker context use via-proxy
docker ps  # routed through the proxy
```

## Development

See [CLAUDE.md](CLAUDE.md) for build, test, lint commands and architecture details.

See [API.md](API.md) for management API usage and curl examples.

## Dev Container

This repository includes a VS Code Dev Container in `.devcontainer/`.

1. Open the repo in VS Code.
2. Run **Dev Containers: Reopen in Container**.

The container mounts `/var/run/docker.sock` for local Docker access and supports optional corporate proxy certs via `.devcontainer/certs/corporate-proxy.crt`.
