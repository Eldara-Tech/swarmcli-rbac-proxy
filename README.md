# swarm-rbac-proxy

Transparent reverse proxy that relays Docker API requests from TCP to a Unix socket. Sits between `docker context` clients and the Docker daemon, with RBAC enrichment planned for later.

## Quick start

```bash
go build .
./swarm-rbac-proxy
```

Listens on `:2376` and forwards to `/var/run/docker.sock` by default.

## Configuration

All configuration is via environment variables.

| Variable | Default | Description |
|---|---|---|
| `PROXY_LISTEN` | `:2376` | TCP listen address |
| `PROXY_DOCKER_SOCKET` | `/var/run/docker.sock` | Path to Docker socket |
| `PROXY_TLS_CERT` | _(none)_ | TLS certificate path |
| `PROXY_TLS_KEY` | _(none)_ | TLS key path |

### TLS

Set both `PROXY_TLS_CERT` and `PROXY_TLS_KEY` to enable TLS:

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
docker context create via-proxy --docker "host=tcp://<proxy-host>:2376"
docker context use via-proxy
docker ps  # routed through the proxy
```

## Development

See [CLAUDE.md](CLAUDE.md) for build, test, lint commands and architecture details.

## Dev Container

This repository includes a VS Code Dev Container in `.devcontainer/`.

1. Open the repo in VS Code.
2. Run **Dev Containers: Reopen in Container**.

The container mounts `/var/run/docker.sock` for local Docker access and supports optional corporate proxy certs via `.devcontainer/certs/corporate-proxy.crt`.
