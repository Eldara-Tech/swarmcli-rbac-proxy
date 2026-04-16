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
  -d '{"username": "alice", "role": "user"}'
```

The `role` field is optional and defaults to `"user"`. Set to `"admin"` for admin access.

Response (`201 Created`):

```json
{
  "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  "username": "alice",
  "role": "user",
  "enabled": true,
  "created_at": "2026-03-06T12:00:00Z",
  "updated_at": "2026-03-06T12:00:00Z"
}
```

When `PROXY_TLS_CLIENT_CA_KEY` is set, the response includes an auto-generated client certificate bundle. See [configuration.md](configuration.md#auto-generating-user-certificates) for details.

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
    "role": "user",
    "enabled": true,
    "created_at": "2026-03-06T12:00:00Z",
    "updated_at": "2026-03-06T12:00:00Z"
  }
]
```

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

## Agent proxy forwarding

When `PROXY_AGENT_URL` is set, all `/v1/*` requests are forwarded to the configured backend. This feature is designed for use with [SwarmCLI](https://swarmcli.io/) (coming soon) and is not intended for standalone use. Both HTTP and WebSocket upgrade (hijack) connections are supported. See [configuration.md](configuration.md#agent-proxy-forwarding) for details.

## Docker proxy

All other paths are forwarded to the Docker daemon:

```bash
curl -s http://localhost:2375/v1.47/containers/json | jq .
```
