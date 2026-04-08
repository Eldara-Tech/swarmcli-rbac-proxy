# swarm-rbac-proxy

Transparent reverse proxy that relays Docker API requests from TCP to a Unix socket. Sits between `docker context` clients and the Docker daemon, with RBAC enrichment planned for later.

## Quick start

```bash
go build .
./swarm-rbac-proxy
```

Listens on `:2375` and forwards to `/var/run/docker.sock` by default.

## Configuration

Configure via environment variables or an optional JSON config file. See [docs/configuration.md](docs/configuration.md) for the full reference.

## Docker

```bash
docker build -t swarm-rbac-proxy .
docker run -d \
  -p 2376:2376 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  swarm-rbac-proxy

# Open a shell in the image when needed.
docker run --rm -it swarm-rbac-proxy sh
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

See [docs/api.md](docs/api.md) for management API usage and curl examples.

## Dev Container

This repository includes a VS Code Dev Container in `.devcontainer/`.

1. Open the repo in VS Code.
2. Run **Dev Containers: Reopen in Container**.

The container mounts `/var/run/docker.sock` for local Docker access and supports optional corporate proxy certs via `.devcontainer/certs/corporate-proxy.crt`.
