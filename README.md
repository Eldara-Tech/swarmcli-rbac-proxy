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
