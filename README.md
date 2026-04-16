# swarmcli-rbac-proxy

Multi-user access control for Docker Swarm. Sits between Docker CLI clients and the daemon, authenticating users via mTLS client certificates and enforcing role-based permissions on every API call.

**Problem it solves**: Docker Swarm has no built-in multi-user access control. Anyone with network access to the Docker socket or TCP endpoint gets full admin privileges. This proxy adds per-user authentication, role-based authorization, and infrastructure protection without modifying the Docker daemon or client.

## How it works

```
Docker CLI ──mTLS──> swarmcli-rbac-proxy ──> Docker daemon (unix socket or TCP)
                            │
                            ├── Authenticates via client certificate (CN/SAN)
                            ├── Authorizes by role (admin / user)
                            └── Blocks mutations to infrastructure stack
```

## Features

- **mTLS client certificates** -- each user gets a unique certificate; no shared credentials
- **Two roles** -- `admin` and `user` with different permissions on protected resources
- **Infrastructure stack protection** -- auto-detects the proxy's own Swarm stack and blocks external users from creating or deleting its services, secrets, networks, and configs
- **Exec/attach guard** -- non-admin users cannot exec into protected containers
- **Automated certificate issuance** -- generates client certificates on user creation (no manual openssl)
- **One-command user onboarding** -- new users run a single `curl` + `docker context import` to get access
- **Dual listener** -- external (mTLS) for users, internal (plain TCP) for admin automation
- **Admin CLI (`swcproxy`)** -- manage users from inside the container without HTTP calls
- **Agent proxy forwarding** -- transparently forwards `/v1/*` requests to a backend agent service (designed for [SwarmCLI](https://swarmcli.io/), coming soon)
- **Three storage backends** -- SQLite (default), PostgreSQL, or in-memory (dev)
- **Structured logging** -- JSON (prod) or console (dev) via zap

## Quick start

Pull the image from Docker Hub:

```bash
docker run -d \
  -p 2375:2375 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  eldaratech/swarmcli-rbac-proxy:latest
```

The proxy listens on `:2375` and forwards to `/var/run/docker.sock`. Point a Docker client at it:

```bash
docker context create via-proxy --docker "host=tcp://<proxy-host>:2375"
docker --context via-proxy ps
```

This runs without TLS or authentication -- suitable for evaluation only. For production, enable mTLS and set an admin token. See [Configuration](docs/configuration.md).

## Production deployment

### Docker Compose

```yaml
services:
  proxy:
    image: eldaratech/swarmcli-rbac-proxy:latest
    ports:
      - "2376:2376"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./certs:/certs:ro
      - proxy-data:/data
    environment:
      PROXY_TLS_CERT: /certs/server-cert.pem
      PROXY_TLS_KEY: /certs/server-key.pem
      PROXY_TLS_CLIENT_CA: /certs/client-ca.pem
      PROXY_TLS_CLIENT_CA_KEY: /certs/client-ca-key.pem
      PROXY_ADMIN_TOKEN: change-me
      PROXY_SEED_USERNAME: admin
      PROXY_SEED_ROLE: admin
      PROXY_DATABASE_PATH: /data/proxy.db
      PROXY_EXTERNAL_URL: "https://proxy.example.com:2376"
      PROXY_INTERNAL_LISTEN: "127.0.0.1:2375"

volumes:
  proxy-data:
```

Place your TLS certificates in a `./certs/` directory on the host. See [Configuration](docs/configuration.md#docker-compose-local-no-swarm) for a PostgreSQL variant.

### Docker Swarm

A `stack.yml` is included for Docker Swarm. It constrains the proxy to manager nodes and mounts the Docker socket:

```bash
docker stack deploy -c stack.yml rbac
```

## Admin CLI

The `swcproxy` CLI is included in the container image. Use it via `docker exec`:

```bash
docker exec -it <container> swcproxy user ls
docker exec -it <container> swcproxy user add alice
docker exec -it <container> swcproxy user add bob --admin
docker exec -it <container> swcproxy user delete alice
docker exec -it <container> swcproxy user regenerate-token alice
```

When a user is created, `swcproxy` prints a curl command to share with the user for one-command onboarding. See [User onboarding](docs/configuration.md#user-onboarding) for the full flow.

## Connecting with Docker CLI

Point a Docker client at the proxy (plain TCP, no auth):

```bash
docker context create via-proxy --docker "host=tcp://<proxy-host>:2375"
docker context use via-proxy
docker ps  # routed through the proxy
```

With mTLS enabled, use client certificates:

```bash
docker context create via-proxy \
  --docker "host=tcp://<proxy-host>:2376,ca=ca.pem,cert=alice.pem,key=alice-key.pem"
```

See [User onboarding](docs/configuration.md#user-onboarding) for the automated onboarding flow using `swcproxy user add`.

## Documentation

- [Configuration reference](docs/configuration.md) -- environment variables, config file, Docker Compose examples
- [API reference](docs/api.md) -- management API endpoints with curl examples
- [Security model](docs/security.md) -- threat model, authentication layers, certificate lifecycle

## Development

- [Architecture and build commands](CLAUDE.md)
- [Contributing guidelines](CONTRIBUTING.md)

## License

Copyright 2026 Eldara Tech. Licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).

If you modify this software or use it to provide a network service, you must make the complete source available to your users under the same license.

## Dev Container

This repository includes a VS Code Dev Container in `.devcontainer/`.

1. Open the repo in VS Code.
2. Run **Dev Containers: Reopen in Container**.

The container mounts `/var/run/docker.sock` for local Docker access and supports optional corporate proxy certs via `.devcontainer/certs/corporate-proxy.crt`.
