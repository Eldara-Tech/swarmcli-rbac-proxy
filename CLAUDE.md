# swarmcli-rbac-proxy

Transparent reverse proxy that relays Docker API requests from TCP to a Unix socket, with multi-user mTLS authentication and role-based access control.

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

## Go Version & Build

Go 1.26. No Makefile. GoReleaser handles binary releases with `-trimpath -s -w` ldflags and version injection (`internal/version`).

Version metadata is injected at build time via ldflags:
- `-X swarm-rbac-proxy/internal/version.Version=...` — git tag
- `-X swarm-rbac-proxy/internal/version.Commit=...` — commit hash
- `-X swarm-rbac-proxy/internal/version.Date=...` — build timestamp

For local development, defaults are `dev`/`none`/`unknown`. See `RELEASING.md` for full release process.

When updating the Go version, keep these in sync:
- `go.mod` — `go` and `toolchain` directives
- `.devcontainer/Dockerfile` — `mcr.microsoft.com/devcontainers/go` image tag (tracks major.minor; patch versions are handled by `GOTOOLCHAIN=auto`)
- `govulncheck` CI step — bump suppressed vuln IDs if the new toolchain resolves them, or add new ones if it introduces new unfixed stdlib vulns

## Configuration

See [docs/configuration.md](docs/configuration.md) for all environment variables and config.json reference.

Key env vars: `PROXY_TLS_CERT`, `PROXY_TLS_KEY` (frontend TLS), `PROXY_TLS_CLIENT_CA` (frontend mTLS — enables client certificate authentication), `PROXY_TLS_CLIENT_CA_KEY` (CA private key — enables auto-generating client certs on user creation), `PROXY_ADMIN_TOKEN` (management API bearer token; `PROXY_ADMIN_TOKEN_FILE` reads it from a file path — for Docker secrets mounted at `/run/secrets/...`), `PROXY_SEED_USERNAME` (bootstrap first user at startup), `PROXY_SEED_ROLE` (role for seed user, default "user"), `PROXY_EXTERNAL_URL` (external proxy URL for onboarding curl instructions), `PROXY_INTERNAL_LISTEN` (internal plain TCP listener address, e.g. "127.0.0.1:2375"), `PROXY_PROTECTED_STACK` (stack name to protect; auto-detected from container labels if unset), `PROXY_AGENT_MANAGER_TLS_BUNDLE` (consolidated single-PEM client cert+key+CA, the `internal-client` secret; supersedes the trio) or `PROXY_AGENT_MANAGER_TLS_CERT`/`PROXY_AGENT_MANAGER_TLS_KEY`/`PROXY_AGENT_MANAGER_TLS_CA` (mutual TLS to the agent-manager; the bundle or all three required when `PROXY_AGENT_MANAGER_URL` is `wss://`).

## Agent-manager Forwarding

When `PROXY_AGENT_MANAGER_URL` (env) or `agent_manager_url` (JSON config) is set, all `/v1/*` requests are forwarded to the specified backend. This covers `/v1/exec`, `/v1/logs`, `/v1/forward`, and other agent endpoints. Both normal HTTP and WebSocket upgrade (hijack) connections are supported via the same `newProxy` handler used for the Docker backend.

A `wss://` (or `https://`) URL secures this hop with **mutual TLS**: the proxy presents the bootstrap-issued internal-client cert and verifies the agent-manager's internal-server cert. Set `PROXY_AGENT_MANAGER_TLS_BUNDLE` (a single PEM with the internal-client cert, key, and internal CA cert — the consolidated `internal-client` secret) or, as a fallback, `PROXY_AGENT_MANAGER_TLS_CERT`, `PROXY_AGENT_MANAGER_TLS_KEY`, and `PROXY_AGENT_MANAGER_TLS_CA` together (the bundle or all three are required when the URL is `wss://`; startup fails closed otherwise). `ServerName` is derived by `tls.Dial` from the stack-qualified host (`<stack>_agent-manager`), which the internal-server cert carries as a SAN. This is what lets the `agent-net` overlay be a plain (non-`encrypted`) overlay — an encrypted overlay needs IPsec ESP between every node pair, which clusters that block IP-protocol-50 to a worker silently drop, breaking worker-node shells. A plaintext `tcp://` URL keeps the old unauthenticated behaviour (standalone dev only).

The `/v1/exec` and `/v1/forward` endpoints on the external listener are both stack-aware via `isAgentControlPath` in `internal/api/guard.go`:
- **Exec**: targeting a container in the protected stack requires admin role; non-protected is allowed for all authenticated users.
- **Forward**: targeting a task in the protected stack is denied for **every external role, including admin** — admin-cert compromise must not yield an exfil channel. Non-protected forwarding is allowed for all authenticated users. The `dest_addr` query parameter is rejected at the proxy edge with HTTP 400 (SSRF mitigation).
- **Volumes** (`/v1/volumes...`, `guardVolume` in `internal/api/volumeguard.go`): reads (GET) are allowed for all authenticated users; mutations (create / delete volume / delete file / rename file) on a volume that belongs to the protected stack require admin, others are allowed for all. The volume's stack is resolved server-side via an agent-manager back-query (`GET /v1/volumes?node_id=`) — volumes are node-local so a client-supplied label can't be trusted and the Docker-socket back-query can't see worker-node volumes. Back-query failure fails closed (503); successful mutations are audited (`volume.*`).

The internal listener (wired with `noExecGuard`) bypasses these checks entirely.

## Stack Resource Protection

When running inside a Docker Swarm stack, the proxy auto-detects its own stack name from container labels (`com.docker.stack.namespace`). Override with `PROXY_PROTECTED_STACK`.

### Permission matrix

| Operation | Internal listener | External admin | External user |
|-----------|-------------------|----------------|---------------|
| Read (GET) — any resource | allowed | allowed | allowed |
| Create (POST .../create) — protected stack | allowed | blocked (403) | blocked (403) |
| Create (POST .../create) — other stack | allowed | allowed | allowed |
| Create service — `TaskTemplate.Networks` attaches to protected overlay | allowed | blocked (403) | blocked (403) |
| Update (POST .../update) — protected stack | allowed | allowed | blocked (403) |
| Update (POST .../update) — other stack | allowed | allowed | allowed |
| Update service — attaches a non-protected service to the protected overlay | allowed | blocked (403) | blocked (403) |
| Network connect/disconnect (POST /networks/{id}/{connect,disconnect}) — protected overlay | allowed | blocked (403) | blocked (403) |
| Network connect/disconnect — other network | allowed | allowed | allowed |
| Delete (DELETE .../{id}) — protected stack | allowed | blocked (403) | blocked (403) |
| Delete (DELETE .../{id}) — other stack | allowed | allowed | allowed |
| Exec/attach — protected stack container | allowed | allowed | blocked (403) |
| Exec/attach — non-protected container | allowed | allowed | allowed |
| Port-forward (`GET /v1/forward`) — protected stack task | allowed | blocked (403) | blocked (403) |
| Port-forward (`GET /v1/forward`) — non-protected task | allowed | allowed | allowed |
| Port-forward with `dest_addr` query param | allowed | blocked (400) | blocked (400) |
| Volume read (`GET /v1/volumes...`) | allowed | allowed | allowed |
| Volume mutate (create/delete/file delete/rename) — protected-stack volume | allowed | allowed | blocked (403) |
| Volume mutate — non-protected volume | allowed | allowed | allowed |
| Swarm leave (POST /swarm/leave) | allowed | blocked (403) | blocked (403) |

If auto-detection fails (e.g. running outside Docker) and `PROXY_PROTECTED_STACK` is not set, the guard is disabled and all operations are allowed.

### Rationale

- **Create blocked for all external users on protected stack**: prevents namespace pollution — injecting resources into the infrastructure namespace could interfere with stack operations (name collisions, label conflicts). Legitimate deployments use `docker stack deploy` via the internal listener.
- **Update allowed for admins on protected stack**: routine operations (image deploys, scaling, secret rotation) require updating protected services through the proxy.
- **Overlay-membership mutations blocked for every external role — including admin**: `TaskTemplate.Networks` attaches to the protected overlay on `create`/`update`, and `POST /networks/{id}/{connect,disconnect}` against the protected overlay, all return `403` regardless of role. An admin-cert compromise therefore cannot bootstrap a pivot onto `agent-net`. The only legitimate paths to mutate overlay membership are the host Docker socket on a manager node or the internal loopback listener (`PROXY_INTERNAL_LISTEN`). In-place updates of protected-stack services whose spec re-affirms the existing overlay attachment continue to work (pivot-only T1: the check fires only when the target service is not itself on the protected stack).
- **Delete blocked for all external users on protected stack**: destructive — removing infrastructure services can make the cluster unmanageable. Only recoverable via direct container access (internal listener).
- **Exec/attach admin-only for protected stack**: shell access to infrastructure containers enables privilege escalation (e.g. direct database access via `swcproxy` CLI). Regular users may exec into their own service containers freely. Admin `exec`/`attach` into an already-overlay-resident container is unaffected by the overlay-membership block above — the guard scope is membership, not traffic.
- **Port-forward to protected stack blocked for every role — including admin**: raw-TCP relay through the proxy to an infrastructure container is an exfil channel that survives the per-request authorization model (a forwarded socket can be reused indefinitely). Symmetric to the T2 connect/disconnect block. Legitimate admin port-forwarding into infrastructure must use the host Docker socket or the internal listener.
- **Port-forward `dest_addr` query rejected (400)**: the agent computes the destination from `container_id` itself; honouring a client-supplied IP would defeat the protected-stack `task_id` check. SSRF mitigation. Both `agent-manager` and `agent` reject `dest_addr` defensively.
- **Swarm leave blocked for all external users**: destructive — tears down the entire cluster. Only via internal listener.

## Architecture

```
swarm-rbac-proxy/
  main.go               — reverse proxy + dual listener routing (internal plain TCP + external mTLS), --version flag
  main_test.go          — unit tests against mock Unix socket
  integration_test.go   — TLS integration tests (plain→TLS, mTLS, upgrade through TLS, frontend mTLS)
  .goreleaser.yml       — GoReleaser config: Linux binary releases (amd64/arm64) for proxy + swcproxy
  Dockerfile            — multi-stage build (golang:1.26-alpine → alpine:3.23), version injection via build args + ldflags, OCI labels
  welcome.sh            — container login banner with dynamic version display (COPY'd to /etc/profile.d/welcome.sh)
  stack.yml             — Docker Swarm stack definition
  cmd/
    swcproxy/
      main.go           — Admin CLI: version, user ls/add/delete/regenerate-token (direct store access)
  internal/
    version/
      version.go        — Build-time version vars (Version/Commit/Date), shared by both binaries
      version_test.go   — version package tests
    certauth/
      certauth.go       — CA loading, generation (GenerateCA), client certificate issuance (ECDSA P-256)
      certauth_test.go  — unit tests (load, issue, serial uniqueness, round-trip)
    config/
      config.go         — Config struct, Load(path) merges JSON file + env vars + defaults
      config_test.go    — config loading unit tests
    log/
      logger.go         — proxylog package: zap-based structured logging (Init/L/Sync/With)
      logger_test.go    — logger unit tests (mode detection, level defaults, noop safety)
    store/
      store.go          — UserStore + AuditStore interfaces, User/AuditEntry types, AuditAction constants, sentinel errors
      memory.go         — in-memory UserStore + AuditStore (dev/testing)
      sqlite.go         — SQLite UserStore + AuditStore (modernc.org/sqlite, default, with migrations)
      postgres.go       — PostgreSQL UserStore + AuditStore (pgx/v5, with migrations)
      contract_test.go  — shared contract tests for all store implementations (user + audit)
      memory_test.go    — memory store unit tests
      sqlite_test.go    — SQLite store unit tests (contract + WAL)
      postgres_test.go  — postgres integration tests (//go:build integration)
    api/
      auth.go           — RequireToken middleware (bearer token validation)
      auth_test.go      — auth middleware tests
      mtls.go           — RequireClientCert middleware (mTLS client cert → user lookup)
      mtls_test.go      — mTLS middleware unit tests
      users.go          — UserHandler: POST/GET /api/v1/users, DELETE /api/v1/users/{username}
      users_test.go     — handler tests using MemoryStore
      me.go             — MeHandler: GET /api/v1/me → caller's own {username, role} from mTLS cert
      me_test.go        — me handler tests (admin/user/no-user/method)
      onboard.go        — OnboardHandler: GET /api/v1/onboard/{token} → Docker-context tar
      onboard_test.go   — onboard handler tests
      guard.go          — ResourceGuard middleware: protects bootstrap stack from non-admin mutation; RequireAdminForExec: admin-only exec/attach
      guard_test.go     — guard middleware tests (path parsing, admin check, back-query, body inspection)
      volumeguard.go    — volume management policy: stack-scoped admin gate for /v1/volumes mutations, agent-manager back-query for ownership, success auditing
      volumeguard_test.go — volume guard tests (GET allowed, protected/non-protected mutation, fail-closed, audit)
      stackdetect.go    — DetectStackName: auto-discovers stack name from container labels via Docker API
      stackdetect_test.go — stack detection tests
```

## Dual Listener

When `PROXY_INTERNAL_LISTEN` is set, the proxy runs two listeners:
- **Internal** (`PROXY_INTERNAL_LISTEN`, e.g. `127.0.0.1:2375`): plain TCP, no mTLS, for admin access inside the container. Bypasses all auth and resource guards.
- **External** (`PROXY_LISTEN`, e.g. `:2376`): TLS with `VerifyClientCertIfGiven`. Proxy routes require client cert; onboard endpoint does not.

**Design note**: `isInternalListener()` identifies internal requests by the presence of `ContextKeyInternal` in the request context, set by `MarkInternalRequest` middleware applied exclusively on the internal listener mux. This positive-signal approach ensures an auth bypass on the external listener cannot be misread as an internal request.

## Exec Guard Prerequisites

`ResourceGuard.ExecGuard` is applied on the external listener. It performs a Docker API back-query to determine which stack the exec target belongs to. Exec on a protected-stack container requires admin role; exec on any other container is allowed for all authenticated users.

Without mTLS (`PROXY_TLS_CLIENT_CA` not set), no caller can prove identity. Exec on protected-stack containers is still blocked (no user = not admin). Non-protected containers are accessible without identity — use `PROXY_INTERNAL_LISTEN` when unathenticated local exec is needed. Bootstrap always configures mTLS.

A back-query error (Docker daemon unreachable) causes fail-closed (503) rather than allowing exec through.

## API Endpoints

- `POST /api/v1/users` — Create user (`{"username":"alice","role":"admin"}` → 201 with user object; includes `certificate` bundle when `PROXY_TLS_CLIENT_CA_KEY` is set)
- `GET /api/v1/users` — List all users (200, always returns array)
- `DELETE /api/v1/users/{username}` — Delete user (204 on success, 404 if not found)
- `GET /api/v1/onboard/{token}` — One-time onboarding: consumes token, issues client cert, returns Docker-context-compatible tar (no auth required, token is the auth)
- `GET /api/v1/me` — Returns the authenticated caller's own `{"username","role"}`, derived from their mTLS client cert (cert-authenticated via `RequireClientCert`, not the admin token). Lets a client learn its own role without attempting a mutating operation. Returns 401 on the internal listener / when no client identity is present. (Used by the CLI's proactive infra-update prompt to decide whether to offer an upgrade.)
- `/v1/*` — Forwarded to agent-manager (when `PROXY_AGENT_MANAGER_URL` is set; supports HTTP and WebSocket upgrade)
- `/*` — Proxied to Docker daemon

## Admin CLI (`swcproxy`)

Runs inside the proxy container via `docker exec`. Accesses the store directly (no HTTP).

```bash
swcproxy version                          # Show version
swcproxy user ls                          # List users
swcproxy user add <username> [--admin]    # Create user + onboarding token
swcproxy user delete <username>           # Delete user
swcproxy user regenerate-token <username> # New onboarding token
swcproxy audit ls [--limit N]             # List audit log entries (default: 50)
swcproxy --help                           # Usage info
```

## Audit Log

All business actions are persisted to an `audit_log` table (same database as users). Audited actions: `user.created`, `user.deleted`, `cert.issued`, `onboard.completed`, `guard.blocked`, `token.regenerated`, `volume.created`, `volume.deleted`, `volume.file.deleted`, `volume.file.renamed` (the `volume.*` actions are recorded on **success**; volume denials use `guard.blocked` like every other guarded op). Auth events (mTLS success/failure) are logged via zap only, not persisted.

Each entry records: id, timestamp, actor (username/"cli"/"anonymous"), action, resource (`type:id` format), status ("success"/"denied"), detail, source\_ip.

The `AuditStore` interface (`internal/store/store.go`) is implemented by all three store backends. Recording is nil-safe — handlers pass `nil` in tests. Audit write failures are logged but never block requests.

## CI

GitHub Actions (`.github/workflows/`):
- `ci.yml`: three jobs — gofmt check, `go test -race`, golangci-lint (fast, no DB); Docker image build (depends on `ci`); PostgreSQL 17 integration tests.
- `licence.yml`: SPDX license header check (`.go` and `.sh` files).

## Release

GitHub Actions (`.github/workflows/release.yml`): triggered on `v*` tags. Three parallel jobs:
1. **release-drafter**: Creates draft release notes from PR labels.
2. **goreleaser**: Builds Linux binaries (amd64/arm64) for both `proxy` and `swcproxy`, publishes GitHub release with archives.
3. **docker**: Builds and pushes Docker image to Docker Hub as `eldaratech/swarmcli-rbac-proxy` with version injection via `--build-arg`.

Docker image tags: `{version}` and `{major}.{minor}` (via `docker/metadata-action`).
Requires `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets.

See `RELEASING.md` for local testing and manual release process.

**Versioning.** A `C1-breaking-change` PR merged since the last GA forces a **major** tag (`vX.0.0`); the pushed tag is authoritative (it overrides release-drafter's `$RESOLVED_VERSION`). The published release notes are type-only (no dedicated "Breaking" section); the customer-facing upgrade story for proxy changes that reach BE users is captured in swarmcli-be's `.github/UPGRADE_NOTES.md` when BE bumps its compat pin across an rbac-proxy major.

## Pre-push Checklist

Always run before pushing:
```bash
go build . && go test -race ./... && gofmt -l . && go vet ./... && golangci-lint run
```

## Known Gaps

Tracked issues from architecture audit:

- **#55**: `isExecPath` missed `GET /containers/{id}/attach/ws` (WebSocket attach) — fixed
- **#56**: ~~`isInternalListener` uses absence of user context as signal~~ — fixed: now uses positive `ContextKeyInternal` flag set by `MarkInternalRequest`
- **#57**: ~~Integration tests use `RequireAndVerifyClientCert` but production uses `VerifyClientCertIfGiven`~~ — fixed: all frontend tests now use `VerifyClientCertIfGiven`, added no-cert client tests
- **#59**: ~~Exec guard silently disabled without mTLS~~ — fixed: always applied on external listener (fail-closed)
- **#60**: ~~`ResourceGuard` fails open on back-query errors (including delete operations)~~ — fixed: deletes now fail closed (503) on back-query errors
- **#62**: No certificate rotation mechanism (client certs expire after 1 year)
- **#63**: ~~No inter-service authentication — accepted risk: overlay network isolation is sufficient~~ — **fixed**: the `rbac-proxy → agent-manager → agent` hops now use mutual TLS (bootstrap-issued internal-server / internal-client certs from the same CA). This both replaces the confidentiality the `encrypted: "true"` overlay used to provide and adds the inter-service authentication the overlay never had, so `agent-net` is now a plain overlay (an encrypted overlay's IPsec/ESP requirement broke worker-node shells on clusters that block IP-protocol-50). The T1/T2 overlay-pivot vectors remain closed by `ResourceGuard` for every external role including admin (legitimate overlay-membership mutations go through the host Docker socket or the internal listener); mTLS now additionally means a rogue workload that does reach `agent-net` cannot invoke the agent/agent-manager without a CA-signed client cert. See `docs/security.md` § "Overlay network trust".
- **#64**: ~~Admin token not persisted across redeployments~~ — partially fixed: proxy now refuses to start when `PROXY_ADMIN_TOKEN` is empty and the user store contains ≥1 admin. Persistence across redeploys is still operator responsibility.
- **#75**: Dockerfile runs as root — accepted risk: proxy requires Docker socket access, which is root-equivalent. Non-root would need root-start entrypoint for negligible benefit. Same reasoning as #63.

## Dependencies

- `modernc.org/sqlite` — Pure Go SQLite driver (used by `internal/store/sqlite.go`)
- `github.com/jackc/pgx/v5` — PostgreSQL driver (used only by `internal/store/postgres.go`)
- `go.uber.org/zap` — Structured logging (used by `internal/log/logger.go`)
