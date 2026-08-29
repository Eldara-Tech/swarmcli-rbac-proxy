# API Reference

The proxy exposes a management API alongside the Docker proxy. The proxy listens on `:2375` by default, or `:2376` when frontend TLS is enabled.

## Authentication

When `PROXY_ADMIN_TOKEN` is set, all `/api/v1/*` management requests require a bearer token:

```bash
curl -s http://localhost:2375/api/v1/users \
  -H "Authorization: Bearer <token>"
```

With mTLS enabled, include client certificate flags on all requests:

```bash
curl -s https://localhost:2376/api/v1/users \
  --cacert ca.pem --cert admin.pem --key admin-key.pem \
  -H "Authorization: Bearer <token>"
```

Missing or invalid token (`401 Unauthorized`):

```json
{"message": "unauthorized"}
```

When `PROXY_ADMIN_TOKEN` is not set, the API is open (no authentication required).

## Create a user

```bash
curl -s -X POST http://localhost:2375/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "role": "operator"}'
```

The `role` field is optional and defaults to `"operator"`. It must be one of the
three built-in roles — `admin`, `operator`, `viewer` — and anything else is
rejected with `400`. See [rbac.md](rbac.md) for what each one grants.

`username` must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`: it becomes the client
certificate CN and appears in onboard URLs and audit records, so it is held to a
conservative shell/URL/log-safe charset.

Response (`201 Created`). The user is created **without credentials** — the
response carries a single-use onboarding token instead, which the user redeems
for their certificate bundle via [Onboard a user](#onboard-a-user):

```json
{
  "user": {
    "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "username": "alice",
    "role": "operator",
    "enabled": true,
    "created_at": "2026-03-06T12:00:00Z",
    "updated_at": "2026-03-06T12:00:00Z"
  },
  "onboard_token": "3f2b1c…",
  "onboard_url": "https://proxy.example.com:2376/api/v1/onboard/3f2b1c…"
}
```

`onboard_url` is present only when the proxy knows its own external address.

When `PROXY_TLS_CLIENT_CA_KEY` is set, the response includes an auto-generated client certificate bundle (fields `certificate.cert_pem`, `certificate.key_pem`, `certificate.ca_pem`). The private key is generated in memory and never stored on the server — if lost, the user must be deleted and recreated. See [the walkthrough](getting-started.md#2-start-the-proxy-with-mtls) for a full example.

### Error: duplicate username

Response (`409 Conflict`):

```json
{"message": "username already exists"}
```

### Error: missing username

Response (`400 Bad Request`):

```json
{"message": "username is required"}
```

## List users

```bash
curl -s http://localhost:2375/api/v1/users
```

Response (`200 OK`):

```json
[
  {
    "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "username": "alice",
    "role": "operator",
    "enabled": true,
    "created_at": "2026-03-06T12:00:00Z",
    "updated_at": "2026-03-06T12:00:00Z"
  }
]
```

The onboarding token and its issued/consumed timestamps are held on the record
but never serialised, so they cannot leak through a list.

## Update a user

`PATCH /api/v1/users/{username}` changes the role, the enabled flag, or both.

```bash
curl -s -X PATCH http://localhost:2375/api/v1/users/alice \
  -H "Content-Type: application/json" \
  -d '{"role": "viewer", "enabled": false}'
```

Both fields are optional, but at least one must be present — an empty body is
`400 nothing to update`. `role` is validated against the same three built-ins as
create, deliberately: the protected-stack gate tests `User.Role == "admin"`, so an
arbitrary string here would be misread rather than rejected.

Two lockout guards return `409 Conflict`:

- You cannot change **your own** role.
- You cannot disable **yourself**.

A third guard refuses to demote or disable the **last remaining admin**, so the
instance can never be left without one. When a request sets both fields, the role
lands first, so a combined change still applies even if the enable toggle is a
no-op.

## Regenerate an onboarding token

`POST /api/v1/users/{username}/regenerate-token` issues a fresh single-use token,
invalidating any previous one. Use it when a token was lost, leaked, or expired
before the user redeemed it.

```bash
curl -s -X POST http://localhost:2375/api/v1/users/alice/regenerate-token
```

Response (`200 OK`) carries the token only — no user object:

```json
{
  "onboard_token": "9d4e7a…",
  "onboard_url": "https://proxy.example.com:2376/api/v1/onboard/9d4e7a…"
}
```

`404` if the user does not exist.

## Who am I

`GET /api/v1/me` returns the identity the proxy resolved from the caller's client
certificate. It is the cheapest way for a client to discover its own role.

```bash
curl -s --cert alice.crt --key alice.key https://localhost:2376/api/v1/me
```

```json
{ "username": "alice", "role": "operator" }
```

It requires an mTLS identity, so it answers only on the external listener — a
request on the internal listener, which carries no client certificate, is
rejected rather than answered with an empty identity.

## Delete a user

```bash
curl -s -X DELETE http://localhost:2375/api/v1/users/alice
```

Response (`204 No Content`): empty body.

### Error: user not found

Response (`404 Not Found`):

```json
{"message": "user not found"}
```

## RBAC: roles and bindings

The proxy authorizes every proxied Docker/agent request against the caller's
**roles**. A role is a named set of permission rules (`{resources, verbs}` with
`*` wildcards); a **binding** maps a user to a role. The built-in roles
`viewer`, `operator`, and `admin` are seeded on startup. These management
endpoints are admin-token protected like the user API.

### List / inspect roles

```bash
curl -s http://localhost:2375/api/v1/roles -H "Authorization: Bearer <token>"
curl -s http://localhost:2375/api/v1/roles/operator -H "Authorization: Bearer <token>"
```

A role (`200 OK`):

```json
{
  "id": "…", "name": "operator", "builtin": true,
  "rules": [
    {"resources": ["stacks","services","nodes","networks","system","stack logs","volumes","configs"], "verbs": ["get","list"]},
    {"resources": ["stacks","services"], "verbs": ["create","update"]},
    {"resources": ["exec","port-forward"], "verbs": ["create"]}
  ],
  "created_at": "…", "updated_at": "…"
}
```

### Create / update / delete a role

```bash
curl -s -X POST http://localhost:2375/api/v1/roles \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"name":"deployer","rules":[{"resources":["stacks"],"verbs":["get","list","create","update"]}]}'

curl -s -X PUT http://localhost:2375/api/v1/roles/deployer \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"rules":[{"resources":["stacks","services"],"verbs":["*"]}]}'

curl -s -X DELETE http://localhost:2375/api/v1/roles/deployer -H "Authorization: Bearer <token>"
```

Built-in roles cannot be deleted (`409`), a role still referenced by a binding
cannot be deleted (`409`), and an update that would leave the cluster with no
admin is refused (`409`).

### List / create / delete bindings

```bash
curl -s http://localhost:2375/api/v1/bindings -H "Authorization: Bearer <token>"

curl -s -X POST http://localhost:2375/api/v1/bindings \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"username":"alice","role_name":"operator"}'

curl -s -X DELETE http://localhost:2375/api/v1/bindings/<binding-id> -H "Authorization: Bearer <token>"
```

Deleting the last binding that grants admin is refused (`409`).

## Onboard a user

One-time endpoint that consumes a token and returns a Docker-context-compatible tar archive. No authentication required — the token itself is the credential.

```bash
curl -k https://proxy.example.com:2376/api/v1/onboard/<token> -o alice.tar
docker context import alice-managed alice.tar
```

Response (`200 OK`): `application/x-tar` containing `meta.json`, `tls/docker/ca.pem`, `tls/docker/cert.pem`, `tls/docker/key.pem`.

### Error: invalid token

Response (`404 Not Found`):

```json
{"message": "invalid token"}
```

### Error: token already consumed

Response (`410 Gone`):

```json
{"message": "token already consumed"}
```

## Control plane (`/_swc/`)

The proxy reserves `/_swc/` on the **internal** listener for its own endpoints, so
they can never be shadowed by, or fall through to, the Docker API — `GET
/_swc/version` for build identity and `/_swc/startbackup` to trigger a
database-only backup. An unknown path under the prefix returns a branded JSON
404 rather than reaching Docker. Full usage, including why a `404` on
`/_swc/version` means a stale build, is in
[backup-restore.md](backup-restore.md#trigger-over-the-internal-listener).

## Agent-manager forwarding

When `PROXY_AGENT_MANAGER_URL` is set, all `/v1/*` requests are forwarded to the configured backend. This feature is designed for use with [SwarmCLI](https://swarmcli.io/) (coming soon) and is not intended for standalone use. Both HTTP and WebSocket upgrade (hijack) connections are supported. See [configuration.md](configuration.md#agent-manager-forwarding) for details.

The recognised agent-manager verbs:

| Path           | Method | Purpose                                                              | Guarded by                                                                                                  |
|----------------|--------|----------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| `/v1/exec`     | GET    | WebSocket exec into a Swarm task (`?task_id=&cmd=`).                 | `ExecGuard`: protected-stack containers require `admin` role; non-protected allowed for all authenticated. |
| `/v1/logs`     | GET    | WebSocket service log stream (`?task_id=&follow=&tail=`).            | None (read-only).                                                                                           |
| `/v1/forward`  | GET    | WebSocket raw-TCP relay (`?task_id=&container_port=`).               | `ExecGuard`: forward to protected-stack tasks is **denied for every external role, including admin**. `dest_addr` query parameter is **rejected with HTTP 400** at the proxy edge (SSRF mitigation). |

Audit denials use `AuditGuardBlocked` with a discriminator of `exec:<path>` or `forward:<path>`.

## Docker proxy

All other paths are forwarded to the Docker daemon:

```bash
curl -s http://localhost:2375/v1.47/containers/json | jq .
```

On the external (mTLS) listener these requests are authorized by RBAC: the
proxy maps each request to a `{resource, verb}` (e.g. `GET /services` →
`services:list`, `POST /services/{id}/update` → `services:update`) and rejects
it with `403` unless one of the caller's roles grants it. Stack-labeled
mutations (resources carrying `com.docker.stack.namespace`) are additionally
authorized under the `stacks` resource, so a role with `stacks:create` can
deploy a full stack. Unmapped or raw operations (e.g. `POST /containers/create`)
require the `admin` role. RBAC denials are audited as `rbac.denied`. The
internal listener bypasses RBAC entirely.
