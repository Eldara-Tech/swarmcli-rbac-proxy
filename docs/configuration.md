# Configuration

The proxy can be configured via environment variables, an optional JSON config file, or both. When both are used, environment variables always override JSON file values.

To use a config file, set the `PROXY_CONFIG` environment variable to its path:

```bash
PROXY_CONFIG=/etc/swarm-rbac-proxy/config.json ./swarm-rbac-proxy
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PROXY_CONFIG` | _(none)_ | Path to a JSON config file. Values are loaded from the file first, then overridden by any env vars that are set |
| `PROXY_LISTEN` | `:2375` (`:2376` with frontend TLS) | TCP listen address |
| `PROXY_DOCKER_URL` | _(none)_ | Docker endpoint URL (`unix:///path` or `tcp://host:port`). Mutually exclusive with `PROXY_DOCKER_SOCKET` |
| `PROXY_DOCKER_SOCKET` | `/var/run/docker.sock` | Path to Docker socket (legacy; prefer `PROXY_DOCKER_URL`) |
| `PROXY_TLS_CERT` | _(none)_ | Frontend TLS certificate path |
| `PROXY_TLS_KEY` | _(none)_ | Frontend TLS key path |
| `PROXY_TLS_CLIENT_CA` | _(none)_ | CA certificate to verify client certificates. When set (along with `PROXY_TLS_CERT` and `PROXY_TLS_KEY`), enables frontend mTLS: clients must present a certificate signed by this CA. The proxy extracts the username from the certificate (SAN email if present, otherwise Subject CN) and looks it up in the user store |
| `PROXY_TLS_CLIENT_CA_KEY` | _(none)_ | Private key for the client CA certificate. When set, the proxy auto-generates a client certificate (ECDSA P-256, 1-year validity) for each new user created via `POST /api/v1/users` and returns it in the response. Requires `PROXY_TLS_CLIENT_CA` to also be set |
| `PROXY_DOCKER_TLS_CA` | _(none)_ | CA cert to verify remote Docker server |
| `PROXY_DOCKER_TLS_CERT` | _(none)_ | Client cert for backend mTLS |
| `PROXY_DOCKER_TLS_KEY` | _(none)_ | Client key for backend mTLS |
| `PROXY_STORE` | `sqlite` | Store backend: `sqlite`, `memory`, or `postgres` |
| `PROXY_DATABASE_PATH` | `proxy.db` | SQLite database file path (used when `PROXY_STORE=sqlite`) |
| `PROXY_DATABASE_URL` | _(none)_ | PostgreSQL connection string (required when `PROXY_STORE=postgres`) |
| `PROXY_ADMIN_TOKEN` | _(none)_ | Bearer token for management API auth. When set, `/api/v1/*` requires `Authorization: Bearer <token>` |
| `PROXY_SEED_USERNAME` | _(none)_ | Username to create at startup if it does not already exist. Used to bootstrap the first user for mTLS access |
| `PROXY_ENV` | `prod` | Logging mode: `dev` (console encoder) or `prod` (JSON encoder) |
| `PROXY_LOG_LEVEL` | `debug` (dev) / `info` (prod) | Minimum log level: `debug`, `info`, `warn`, `error` |

## Config file reference

JSON keys must use snake_case (matching the Go struct tags). Unknown keys are rejected at startup.

```json
{
  "listen":          ":2375",
  "docker_url":      "tcp://remote-host:2376",
  "docker_socket":   "/var/run/docker.sock",
  "tls_cert":        "/path/to/server-cert.pem",
  "tls_key":         "/path/to/server-key.pem",
  "tls_client_ca":     "/path/to/client-ca.pem",
  "tls_client_ca_key": "/path/to/client-ca-key.pem",
  "docker_tls_ca":   "/path/to/ca.pem",
  "docker_tls_cert": "/path/to/client-cert.pem",
  "docker_tls_key":  "/path/to/client-key.pem",
  "store":           "sqlite",
  "database_path":   "proxy.db",
  "database_url":    "postgres://user:pass@host:5432/db",
  "admin_token":     "my-secret-token",
  "seed_username":   "admin",
  "env":             "prod",
  "log_level":       "info"
}
```

All fields are optional. Omitted fields fall back to their defaults (see table above).

## Usage examples

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

### Frontend mTLS (multi-user Docker CLI access)

Enable client certificate authentication by setting `PROXY_TLS_CLIENT_CA` alongside the server TLS cert/key. Use `PROXY_SEED_USERNAME` to bootstrap the first admin user:

```bash
PROXY_TLS_CERT=/path/to/server-cert.pem \
  PROXY_TLS_KEY=/path/to/server-key.pem \
  PROXY_TLS_CLIENT_CA=/path/to/client-ca.pem \
  PROXY_ADMIN_TOKEN=my-secret-token \
  PROXY_SEED_USERNAME=admin \
  ./swarm-rbac-proxy
```

With mTLS enabled, all connections require a valid client certificate — including the management API. The admin uses their cert (whose CN matches the seed username) plus the bearer token to create additional users:

```bash
curl -s -X POST https://localhost:2376/api/v1/users \
  --cacert ca.pem \
  --cert admin.pem --key admin-key.pem \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-secret-token" \
  -d '{"username":"alice"}'
```

Each user creates a Docker context with their client certificate:

```bash
docker context create rbac-proxy \
  --docker "host=tcp://proxy.example.com:2376,ca=ca.pem,cert=alice.pem,key=alice-key.pem"

docker --context rbac-proxy ps
```

### Auto-generating user certificates

When `PROXY_TLS_CLIENT_CA_KEY` is set alongside the mTLS config, the proxy automatically generates a client certificate for each new user. The admin no longer needs to run openssl manually:

```bash
PROXY_TLS_CERT=/path/to/server-cert.pem \
  PROXY_TLS_KEY=/path/to/server-key.pem \
  PROXY_TLS_CLIENT_CA=/path/to/client-ca.pem \
  PROXY_TLS_CLIENT_CA_KEY=/path/to/client-ca-key.pem \
  PROXY_ADMIN_TOKEN=my-secret-token \
  PROXY_SEED_USERNAME=admin \
  ./swarm-rbac-proxy
```

Creating a user now returns the certificate bundle in the response:

```bash
curl -s -X POST https://localhost:2376/api/v1/users \
  --cacert ca.pem \
  --cert admin.pem --key admin-key.pem \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-secret-token" \
  -d '{"username":"alice"}'
```

Response:

```json
{
  "id": "a1b2c3d4-...",
  "username": "alice",
  "enabled": true,
  "created_at": "2026-04-02T12:00:00Z",
  "updated_at": "2026-04-02T12:00:00Z",
  "certificate": {
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "key_pem": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----\n",
    "ca_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
  }
}
```

The private key is generated in memory and **never stored** on the server. The certificate bundle is only available in this response.

### Forwarding a certificate to a user

After creating a user, the admin needs to securely deliver the three PEM files to the user. Here is a step-by-step guide:

**1. Extract the PEM files from the API response**

Save the JSON response to a file, then extract each field:

```bash
# Create user and save the full response
curl -s -X POST https://localhost:2376/api/v1/users \
  --cacert ca.pem --cert admin.pem --key admin-key.pem \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-secret-token" \
  -d '{"username":"alice"}' > alice-response.json

# Extract the three PEM files
jq -r '.certificate.cert_pem' alice-response.json > alice-cert.pem
jq -r '.certificate.key_pem'  alice-response.json > alice-key.pem
jq -r '.certificate.ca_pem'   alice-response.json > ca.pem

# Delete the response file (contains the private key)
rm alice-response.json
```

**2. Deliver the files securely to the user**

The three files (`alice-cert.pem`, `alice-key.pem`, `ca.pem`) must reach the user through a secure channel. Some options:

- **Password-protected archive**: Bundle the files and share via a corporate file sharing tool.
  ```bash
  zip -e alice-certs.zip alice-cert.pem alice-key.pem ca.pem
  # Share the zip via one channel, the password via another (e.g. chat + phone)
  ```
- **Direct transfer**: Copy files to the user's machine via `scp` or a secure corporate tool.
- **Secrets manager**: Store temporarily in a shared vault (e.g. 1Password, Vault) and revoke after the user retrieves them.

**3. User sets up their Docker context**

Once the user has the three files, they configure Docker CLI:

```bash
# Create a Docker context pointing at the proxy
docker context create my-cluster \
  --docker "host=tcp://proxy.example.com:2376,ca=ca.pem,cert=alice-cert.pem,key=alice-key.pem"

# Verify access
docker --context my-cluster ps

# Optionally set as default
docker context use my-cluster
```

**4. Clean up admin-side copies**

After confirming the user can authenticate, the admin should delete their local copies of the user's private key:

```bash
rm alice-cert.pem alice-key.pem
```

**Important**: If the certificate is lost, there is no way to re-download it. The admin must disable the user and create a new one to issue a fresh certificate.

### Data store

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

### Management API authentication

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
