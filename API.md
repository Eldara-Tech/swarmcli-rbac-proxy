# API Reference

The proxy exposes a management API alongside the Docker proxy. By default the proxy listens on `:2375`.

## Create a user

```bash
curl -s -X POST http://localhost:2375/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"username": "alice"}'
```

Response (`201 Created`):

```json
{
  "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  "username": "alice",
  "enabled": true,
  "created_at": "2026-03-06T12:00:00Z",
  "updated_at": "2026-03-06T12:00:00Z"
}
```

### Error: duplicate username

```bash
curl -s -X POST http://localhost:2375/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"username": "alice"}'
```

Response (`409 Conflict`):

```json
{"error": "username already exists"}
```

### Error: missing username

```bash
curl -s -X POST http://localhost:2375/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{}'
```

Response (`400 Bad Request`):

```json
{"error": "username is required"}
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
    "enabled": true,
    "created_at": "2026-03-06T12:00:00Z",
    "updated_at": "2026-03-06T12:00:00Z"
  }
]
```

## Docker proxy

All other paths are forwarded to the Docker daemon:

```bash
curl -s http://localhost:2375/v1.47/containers/json | jq .
```
