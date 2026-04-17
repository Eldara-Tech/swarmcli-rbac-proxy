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
- **Persisted audit log** -- all business actions (user CRUD, certificate issuance, guard blocks, onboarding) are recorded to the database and queryable via CLI
- **Admin CLI (`swcproxy`)** -- manage users and query audit logs from inside the container without HTTP calls
- **Agent proxy forwarding** -- transparently forwards `/v1/*` requests to a backend agent service (designed for [SwarmCLI](https://swarmcli.io/), coming soon)
- **Three storage backends** -- SQLite (default), PostgreSQL, or in-memory (dev)
- **Structured logging** -- JSON (prod) or console (dev) via zap

## Getting started

For a complete end-to-end setup — generating certificates, starting the proxy with mTLS, onboarding users, and verifying the exec guard — follow [docs/getting-started.md](docs/getting-started.md).

## Production deployment

The proxy reads its TLS material from file paths given in `PROXY_TLS_CERT`, `PROXY_TLS_KEY`, `PROXY_TLS_CLIENT_CA`, and `PROXY_TLS_CLIENT_CA_KEY`. Point those at `/run/secrets/...` and deliver the files via Docker secrets — in Swarm they are encrypted at rest in the raft log and delivered in-memory to containers. The admin token (`PROXY_ADMIN_TOKEN`) is read as a string env var; inject it from your CI or secret manager at deploy time, do not commit it to `stack.yml`.

### Docker Swarm (recommended)

The bundled `stack.yml` wires up the proxy with four secrets — server cert + key and client CA + key — plus a named volume for the database. Create the secrets from your cert files, export the admin token, then deploy:

```bash
docker secret create rbac_server_cert    certs/server-cert.pem
docker secret create rbac_server_key     certs/server-key.pem
docker secret create rbac_client_ca      certs/client-ca.pem
docker secret create rbac_client_ca_key  certs/client-ca-key.pem

export PROXY_ADMIN_TOKEN='choose-a-strong-token'
docker stack deploy -c stack.yml rbac
```

Secrets are mounted at `/run/secrets/<name>` inside the container; `stack.yml` already points each `PROXY_TLS_*` at the right path. See [docs/configuration.md](docs/configuration.md) for the full environment-variable reference and [docs/getting-started.md § 1](docs/getting-started.md#1-generate-the-server-certificate-and-client-ca) for how to generate the certs.

### Single host (Docker Compose)

For a single-host deployment without Swarm, Compose can still deliver files via its `secrets:` block (backed by files on disk rather than the raft log):

```yaml
services:
  proxy:
    image: eldaratech/swarmcli-rbac-proxy:latest
    ports:
      - "2376:2376"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - proxy-data:/data
    environment:
      PROXY_LISTEN: ":2376"
      PROXY_TLS_CERT: /run/secrets/server_cert
      PROXY_TLS_KEY: /run/secrets/server_key
      PROXY_TLS_CLIENT_CA: /run/secrets/client_ca
      PROXY_TLS_CLIENT_CA_KEY: /run/secrets/client_ca_key
      PROXY_ADMIN_TOKEN: ${PROXY_ADMIN_TOKEN}
      PROXY_SEED_USERNAME: admin
      PROXY_SEED_ROLE: admin
      PROXY_DATABASE_PATH: /data/proxy.db
      PROXY_EXTERNAL_URL: "https://proxy.example.com:2376"
      PROXY_INTERNAL_LISTEN: "127.0.0.1:2375"
    secrets:
      - server_cert
      - server_key
      - client_ca
      - client_ca_key

secrets:
  server_cert:    { file: ./certs/server-cert.pem }
  server_key:     { file: ./certs/server-key.pem }
  client_ca:      { file: ./certs/client-ca.pem }
  client_ca_key:  { file: ./certs/client-ca-key.pem }

volumes:
  proxy-data:
```

Export `PROXY_ADMIN_TOKEN` in the shell before `docker compose up`. Real encrypted-at-rest distribution requires Swarm — Compose secrets are only a delivery shape. See [docs/configuration.md](docs/configuration.md#data-store) for a PostgreSQL variant.

## Admin CLI

The `swcproxy` CLI ships inside the container image. For the Swarm deployment above, the proxy runs as service `rbac_proxy` — Docker Swarm prefixes each service with its stack name, so the `proxy` service in stack `rbac` becomes `rbac_proxy`:

```bash
# Resolve the container ID of the running proxy service and exec into it
docker exec -it "$(docker ps -q -f name=rbac_proxy)" swcproxy user ls
```

Common commands:

```bash
swcproxy user ls
swcproxy user add alice
swcproxy user add bob --admin
swcproxy user delete alice
swcproxy user regenerate-token alice
swcproxy audit ls --limit 10
```

When a user is created, `swcproxy` prints the `curl` command to share with the user for one-command onboarding — see [the walkthrough](docs/getting-started.md#4-create-and-onboard-a-regular-user).

## Documentation

- [Getting started](docs/getting-started.md) — end-to-end walkthrough: cert generation, mTLS bootstrap, user onboarding, audit log
- [Configuration reference](docs/configuration.md) — environment variables, JSON config, listener topology, stack protection
- [API reference](docs/api.md) — management API endpoints with curl examples
- [Security model](docs/security.md) — threat model, authentication layers, certificate lifecycle

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
