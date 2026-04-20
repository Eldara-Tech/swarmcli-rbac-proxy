# Configuration reference

- [How the proxy is configured](#how-the-proxy-is-configured)
- [Environment variables](#environment-variables)
  - [Proxy TLS and listeners](#proxy-tls-and-listeners)
  - [Docker backend](#docker-backend)
  - [User identity and management API](#user-identity-and-management-api)
  - [Data store](#data-store)
  - [Integrations and observability](#integrations-and-observability)
- [JSON config file](#json-config-file)
- [Dual listener](#dual-listener)
- [Agent-manager forwarding](#agent-manager-forwarding)
- [Stack resource protection](#stack-resource-protection)
- [User onboarding](#user-onboarding)
- [Docker Compose examples](#docker-compose-examples)

## How the proxy is configured

The proxy reads configuration in this order, each layer overriding the previous:

1. Built-in defaults.
2. JSON file at `PROXY_CONFIG` (optional).
3. Environment variables.

```bash
PROXY_CONFIG=/etc/swarm-rbac-proxy/config.json ./swarm-rbac-proxy
```

If you're setting up the proxy for the first time, follow [the walkthrough](getting-started.md) first — this document is a reference, not a tutorial.

## Environment variables

### Proxy TLS and listeners

These control how the proxy listens for incoming requests and which certificates it presents to — and demands from — clients.

| Variable | Default | Description |
|---|---|---|
| `PROXY_LISTEN` | `:2375` (`:2376` with TLS) | Address for the external TCP listener. |
| `PROXY_TLS_CERT` | _(none)_ | Path to the proxy's TLS certificate (presented to clients so they can authenticate the proxy). |
| `PROXY_TLS_KEY` | _(none)_ | Path to the private key for `PROXY_TLS_CERT`. |
| `PROXY_TLS_CLIENT_CA` | _(none)_ | CA certificate used to verify incoming client certificates. When set together with `PROXY_TLS_CERT`/`PROXY_TLS_KEY`, mTLS is enabled: every external request must present a certificate signed by this CA. The proxy extracts the username from the certificate (SAN email if present, otherwise Subject CN) and looks it up in the user store. |
| `PROXY_TLS_CLIENT_CA_KEY` | _(none)_ | Private key for the client CA. When set, the proxy auto-issues a client certificate (ECDSA P-256, 1-year validity) for each new user created via `POST /api/v1/users` or `swcproxy user add`, and returns it in the response. Requires `PROXY_TLS_CLIENT_CA`. |
| `PROXY_INTERNAL_LISTEN` | _(none)_ | Address for a second, plain-TCP listener that bypasses mTLS and role checks. Intended for `docker exec`-style admin access from inside the container (e.g. `127.0.0.1:2375`). See [Dual listener](#dual-listener). |
| `PROXY_EXTERNAL_URL` | _(none)_ | Base URL for onboarding `curl` instructions printed by `swcproxy user add` (e.g. `https://proxy.example.com:2376`). |
| `PROXY_ALLOW_INSECURE` | _(none)_ | When set to the exact string `true`, bypasses the startup safety check that requires mTLS (both `PROXY_TLS_CERT` and `PROXY_TLS_CLIENT_CA`) for the external listener. Without mTLS, every caller can drive the full Docker API through the proxy passthrough — `PROXY_ADMIN_TOKEN` alone only protects the management routes, not the Docker API. Intended only for tests and deployments where network-level isolation (e.g. an internal-only Swarm overlay) provides the security boundary. Any value other than `true` — empty, `1`, `yes`, `TRUE` — leaves the guard active. |

### Docker backend

Where the proxy forwards Docker API requests. Use either a URL (TCP or Unix socket) or the legacy socket path.

| Variable | Default | Description |
|---|---|---|
| `PROXY_DOCKER_URL` | _(none)_ | Docker endpoint URL (`unix:///path` or `tcp://host:port`). Mutually exclusive with `PROXY_DOCKER_SOCKET`. |
| `PROXY_DOCKER_SOCKET` | `/var/run/docker.sock` | Path to the Docker Unix socket (legacy; prefer `PROXY_DOCKER_URL`). |
| `PROXY_DOCKER_TLS_CA` | _(none)_ | CA certificate used to verify a remote Docker daemon over TLS. |
| `PROXY_DOCKER_TLS_CERT` | _(none)_ | Client certificate for backend mTLS to the Docker daemon. |
| `PROXY_DOCKER_TLS_KEY` | _(none)_ | Private key for `PROXY_DOCKER_TLS_CERT`. |

### User identity and management API

These control the seed user created at startup and the bearer token that protects the management API.

| Variable | Default | Description |
|---|---|---|
| `PROXY_ADMIN_TOKEN` | _(none)_ | Bearer token required on `/api/v1/*` requests. When unset and TLS is enabled, the proxy refuses to start. When unset without TLS, a warning is logged and the API is open. |
| `PROXY_SEED_USERNAME` | _(none)_ | Username to create at startup if it does not exist. Used to bootstrap the first user so that the very first mTLS client has a matching identity in the store. |
| `PROXY_SEED_ROLE` | `user` | Role assigned to the seed user: `user` or `admin`. See [the walkthrough](getting-started.md#2-start-the-proxy-with-mtls) for when to seed an admin versus a regular user. |

### Data store

The proxy persists users, onboarding tokens, and the audit log in one of three backends.

| Variable | Default | Description |
|---|---|---|
| `PROXY_STORE` | `sqlite` | Backend: `sqlite`, `postgres`, or `memory` (dev only; data lost on restart). |
| `PROXY_DATABASE_PATH` | `proxy.db` | SQLite file path (used when `PROXY_STORE=sqlite`). |
| `PROXY_DATABASE_URL` | _(none)_ | PostgreSQL connection string (required when `PROXY_STORE=postgres`), e.g. `postgres://user:pass@host:5432/db?sslmode=disable`. |

### Integrations and observability

| Variable | Default | Description |
|---|---|---|
| `PROXY_CONFIG` | _(none)_ | Path to a JSON config file. Values loaded from the file are overridden by any environment variables that are set. |
| `PROXY_AGENT_MANAGER_URL` | _(none)_ | Backend URL for `/v1/*` agent-manager forwarding (e.g. `tcp://agent-manager:9090`). HTTP and WebSocket upgrade are supported. See [Agent-manager forwarding](#agent-manager-forwarding). |
| `PROXY_PROTECTED_STACK` | _(auto-detected)_ | Name of the Docker Swarm stack containing the rbac-proxy itself — the stack whose resources should be protected from external mutation. Auto-detected from the container label `com.docker.stack.namespace` when the proxy runs as part of a Swarm stack. Set explicitly if auto-detection is not available (e.g. when running outside Swarm) and you still want the guard active. See [Stack resource protection](#stack-resource-protection). |
| `PROXY_ENV` | `prod` | Logging mode: `dev` (console encoder) or `prod` (JSON encoder). |
| `PROXY_LOG_LEVEL` | `debug` (dev) / `info` (prod) | Minimum log level: `debug`, `info`, `warn`, `error`. |

## JSON config file

JSON keys use snake_case (matching the Go struct tags). Unknown keys are rejected at startup.

```json
{
  "listen":            ":2376",
  "docker_url":        "tcp://remote-host:2376",
  "docker_socket":     "/var/run/docker.sock",
  "tls_cert":          "/path/to/server-cert.pem",
  "tls_key":           "/path/to/server-key.pem",
  "tls_client_ca":     "/path/to/client-ca.pem",
  "tls_client_ca_key": "/path/to/client-ca-key.pem",
  "docker_tls_ca":     "/path/to/ca.pem",
  "docker_tls_cert":   "/path/to/client-cert.pem",
  "docker_tls_key":    "/path/to/client-key.pem",
  "store":             "sqlite",
  "database_path":     "proxy.db",
  "database_url":      "postgres://user:pass@host:5432/db",
  "admin_token":       "my-secret-token",
  "seed_username":     "admin",
  "seed_role":         "admin",
  "external_url":      "https://proxy.example.com:2376",
  "internal_listen":   "127.0.0.1:2375",
  "protected_stack":   "my-stack",
  "agent_manager_url": "tcp://agent-manager:9090",
  "env":               "prod",
  "log_level":         "info"
}
```

All fields are optional. Omitted fields fall back to their defaults above.

## Dual listener

When `PROXY_INTERNAL_LISTEN` is set, the proxy runs two listeners:

- **Internal** (`PROXY_INTERNAL_LISTEN`, e.g. `127.0.0.1:2375`): plain TCP, no mTLS, no role checks. Intended for admin access from inside the container or host (`docker exec`, localhost tools).
- **External** (`PROXY_LISTEN`, e.g. `:2376`): TLS with optional client certificate verification (`VerifyClientCertIfGiven`). Proxy and agent routes require a valid client cert when `PROXY_TLS_CLIENT_CA` is set; the onboarding endpoint does not.

This is the recommended production setup: the internal listener handles automation and the admin CLI (`swcproxy`), while the external listener faces users with mTLS.

## Agent-manager forwarding

When `PROXY_AGENT_MANAGER_URL` is set, all requests to `/v1/*` are forwarded to the specified backend. This feature is designed for use with [SwarmCLI](https://swarmcli.io/) (coming soon), which routes agent commands (exec, logs) through the RBAC proxy, applying the same authentication and exec guard rules. It is not intended for standalone use.

```bash
PROXY_AGENT_MANAGER_URL=tcp://agent-manager:9090 ./swarm-rbac-proxy
```

Both standard HTTP requests and WebSocket upgrade (hijack) connections are supported. The exec guard applies to `/v1/exec` on the external listener: exec targeting a container in the protected stack requires admin role.

If `PROXY_AGENT_MANAGER_URL` is not set, `/v1/*` requests are forwarded to the Docker daemon like any other path.

## Stack resource protection

When running inside a Docker Swarm stack, the proxy auto-detects its own stack name from container labels (`com.docker.stack.namespace`). Override with `PROXY_PROTECTED_STACK`.

Protected resource types: `services`, `secrets`, `networks`, `volumes`, `configs`, plus `swarm/leave`. Container `exec` and `attach` on protected-stack containers are restricted to admins.

**Note**: The exec/attach guard is always active on the external listener. Without `PROXY_TLS_CLIENT_CA` (no mTLS), all exec/attach requests to protected containers are blocked — no user can prove admin status. Use `PROXY_INTERNAL_LISTEN` for local exec access without mTLS. See [security.md](security.md#exec-guard-limitations) for details.

### Permission matrix

| Operation on protected resource | Internal listener | External admin | External user |
|---------------------------------|-------------------|----------------|---------------|
| Read (GET)                      | allowed           | allowed        | allowed       |
| Create (POST .../create)        | allowed           | blocked (403)  | blocked (403) |
| Update (POST .../update)        | allowed           | allowed        | blocked (403) |
| Delete (DELETE .../{id})        | allowed           | blocked (403)  | blocked (403) |
| Exec/attach (protected stack)   | allowed           | allowed        | blocked (403) |
| Swarm leave (POST /swarm/leave) | allowed           | blocked (403)  | blocked (403) |

All operations on **non-protected** resources are allowed for all roles.

**Why these restrictions:**

- **Create blocked for all external users**: prevents namespace pollution — injecting resources into the infrastructure namespace could interfere with stack operations.
- **Update allowed for admins**: routine operations (image deploys, scaling, secret rotation) require updating protected services through the proxy.
- **Delete blocked for all external users**: removing infrastructure services can make the cluster unmanageable. Only via internal listener.
- **Exec/attach admin-only on protected stack**: shell access to infrastructure containers enables privilege escalation (e.g. direct database access via `swcproxy` CLI). Regular users may still exec into non-protected containers.
- **Swarm leave blocked for all external users**: tears down the entire cluster. Only via internal listener.

If auto-detection fails (e.g. running outside Docker) and `PROXY_PROTECTED_STACK` is not set, the guard is disabled and all operations are allowed.

## User onboarding

The proxy supports a one-time onboarding flow to provision new users with Docker CLI access:

1. **Admin creates user** via `swcproxy user add <username>` (inside the container) or `POST /api/v1/users`. A one-time onboarding token is generated.
2. **Admin shares the curl command** with the user (printed by `swcproxy user add` or constructed from the token).
3. **User fetches the tar archive**:
   ```bash
   curl -k https://proxy.example.com:2376/api/v1/onboard/<token> -o myname.tar
   ```
4. **User imports the Docker context**:
   ```bash
   docker context import myname-managed myname.tar
   docker context use myname-managed
   docker ps
   ```
5. **Token is consumed** — it cannot be reused. If lost, the admin runs `swcproxy user regenerate-token <username>` to issue a new one.

The tar archive contains `meta.json` (Docker context metadata) and `tls/docker/{ca,cert,key}.pem` (client certificate bundle). The private key is generated in memory and **never stored** on the server.

See [api.md § Onboard a user](api.md#onboard-a-user) for the endpoint reference, and [the walkthrough](getting-started.md#4-create-and-onboard-a-regular-user) for a live example.

## Docker Compose examples

These examples deploy the proxy on a single host using Docker Compose, without Docker Swarm. For a Swarm deployment with encrypted-at-rest secrets, see [README § Production deployment](../README.md#docker-swarm-recommended).

### SQLite with named volume

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
      PROXY_LISTEN: ":2376"
      PROXY_TLS_CERT: /certs/server-cert.pem
      PROXY_TLS_KEY: /certs/server-key.pem
      PROXY_TLS_CLIENT_CA: /certs/client-ca.pem
      PROXY_TLS_CLIENT_CA_KEY: /certs/client-ca-key.pem
      PROXY_ADMIN_TOKEN: change-me
      PROXY_SEED_USERNAME: admin
      PROXY_SEED_ROLE: admin
      PROXY_DATABASE_PATH: /data/proxy.db
      PROXY_EXTERNAL_URL: "https://localhost:2376"
      PROXY_INTERNAL_LISTEN: "127.0.0.1:2375"

volumes:
  proxy-data:
```

`PROXY_DATABASE_PATH` points to `/data/proxy.db` inside the named volume `proxy-data`, so user data persists across container restarts. Place your TLS certificates in a `./certs/` directory on the host.

### PostgreSQL

```yaml
services:
  proxy:
    image: eldaratech/swarmcli-rbac-proxy:latest
    ports:
      - "2376:2376"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./certs:/certs:ro
    environment:
      PROXY_LISTEN: ":2376"
      PROXY_TLS_CERT: /certs/server-cert.pem
      PROXY_TLS_KEY: /certs/server-key.pem
      PROXY_TLS_CLIENT_CA: /certs/client-ca.pem
      PROXY_TLS_CLIENT_CA_KEY: /certs/client-ca-key.pem
      PROXY_ADMIN_TOKEN: change-me
      PROXY_SEED_USERNAME: admin
      PROXY_SEED_ROLE: admin
      PROXY_STORE: postgres
      PROXY_DATABASE_URL: "postgres://proxy:secret@db:5432/rbac?sslmode=disable"
      PROXY_EXTERNAL_URL: "https://localhost:2376"
      PROXY_INTERNAL_LISTEN: "127.0.0.1:2375"
    depends_on:
      - db

  db:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: proxy
      POSTGRES_PASSWORD: secret
      POSTGRES_DB: rbac
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

The proxy creates the `users` and `audit_log` tables automatically on first startup.
