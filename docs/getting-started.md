# Getting started

This walkthrough takes you from nothing to a running proxy with mTLS, one admin, one regular user, a demonstration of the exec guard, and a look at the audit log. Every command is copy-paste-able and the whole thing runs against a local Docker daemon.

- [Prerequisites](#prerequisites)
- [1. Generate the server certificate and client CA](#1-generate-the-server-certificate-and-client-ca)
- [2. Start the proxy with mTLS](#2-start-the-proxy-with-mtls)
- [3. Bootstrap the admin](#3-bootstrap-the-admin)
- [4. Create and onboard a regular user](#4-create-and-onboard-a-regular-user)
- [5. See the exec guard in action](#5-see-the-exec-guard-in-action)
- [6. Review the audit log](#6-review-the-audit-log)
- [Next steps](#next-steps)

## Prerequisites

- Docker Engine reachable at `/var/run/docker.sock`.
- `openssl` for generating certs.
- Either a local build (`go build .`) or the published image (`eldaratech/swarmcli-rbac-proxy:latest`).

## 1. Generate the server certificate and client CA

The proxy is configured with three certificate-related files. Understanding what each one does is the only conceptual step in this guide.

**Proxy TLS certificate** (`PROXY_TLS_CERT` + `PROXY_TLS_KEY`) — the proxy's own TLS certificate and private key, presented to Docker CLI clients during the TLS handshake. Clients use it to verify that they are actually talking to your proxy and not an imposter.

**Client CA certificate** (`PROXY_TLS_CLIENT_CA`) — a certificate-authority certificate used by the proxy to verify incoming client certs and extract each user's identity (the certificate's CN or SAN email). Every user — admin or regular — authenticates by presenting a client cert signed by this CA. This is what makes the proxy multi-user: one CA, one cert per user, one identity per request.

**Client CA private key** (`PROXY_TLS_CLIENT_CA_KEY`) — the CA's private key. When provided, the proxy auto-issues a fresh per-user certificate whenever someone is onboarded, so admins never run `openssl` by hand.

For production, you may want two separate CAs — one that signs the proxy's TLS cert, one that signs user certs — so a compromised user-CA cannot be used to impersonate the proxy. In this walkthrough we use a single CA playing both roles because the onboarding tar bundles the client CA as the Docker context's trust anchor; sharing the CA means a downloaded context works out of the box without a second file to install. Splitting the CAs is a one-file change you can make later (distribute the proxy-TLS CA separately and set `SkipTLSVerify: false` against it).

Create a working directory and generate one CA, the proxy's server cert signed by it, and leave the CA key in place for auto-issuance:

```bash
mkdir -p /tmp/rbac-demo/certs && cd /tmp/rbac-demo

# CA — signs both the proxy's TLS cert (below) and each user's client cert (runtime)
openssl ecparam -genkey -name prime256v1 -out certs/ca-key.pem
openssl req -new -x509 -key certs/ca-key.pem -out certs/ca.pem \
  -days 365 -subj "/CN=RBAC Demo CA"

# Proxy TLS cert — presented to Docker CLI clients
openssl ecparam -genkey -name prime256v1 -out certs/server-key.pem
openssl req -new -key certs/server-key.pem -out certs/server.csr -subj "/CN=localhost"
openssl x509 -req -in certs/server.csr \
  -CA certs/ca.pem -CAkey certs/ca-key.pem -CAcreateserial \
  -out certs/server-cert.pem -days 365 \
  -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth")
```

You now have:
- `certs/server-cert.pem` + `certs/server-key.pem` — presented by the proxy during TLS handshake.
- `certs/ca.pem` + `certs/ca-key.pem` — CA cert and key, used by the proxy to verify and issue client certs.

## 2. Start the proxy with mTLS

Run the proxy with the CA wired in and an admin seeded at startup. `PROXY_TLS_CLIENT_CA_KEY` gives the proxy the CA's private key, which enables automatic per-user certificate issuance during onboarding.

```bash
docker run -d --name rbac-proxy \
  -p 2376:2376 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /tmp/rbac-demo/certs:/certs:ro \
  -e PROXY_LISTEN=:2376 \
  -e PROXY_TLS_CERT=/certs/server-cert.pem \
  -e PROXY_TLS_KEY=/certs/server-key.pem \
  -e PROXY_TLS_CLIENT_CA=/certs/ca.pem \
  -e PROXY_TLS_CLIENT_CA_KEY=/certs/ca-key.pem \
  -e PROXY_ADMIN_TOKEN=demo-admin-token \
  -e PROXY_SEED_USERNAME=admin \
  -e PROXY_SEED_ROLE=admin \
  -e PROXY_EXTERNAL_URL=https://localhost:2376 \
  -e PROXY_INTERNAL_LISTEN=127.0.0.1:2375 \
  -e PROXY_ENV=dev \
  eldaratech/swarmcli-rbac-proxy:latest
```

Check the logs for `seed user created` and `frontend mTLS enabled`:

```bash
docker logs rbac-proxy | head -20
```

**About the admin.** The `admin` role is required to (a) update services in the protected stack through the external listener (image deploys, scaling, secret rotation) and (b) exec or attach into protected-stack containers. If you only ever operate the infra stack from a shell on the manager node (the internal listener bypasses all role checks), you can seed a regular user instead — set `PROXY_SEED_ROLE=user` — and the external listener will only ever be used for read-only access and for day-to-day work on non-protected containers. Most deployments want an admin. See [Permission matrix](configuration.md#permission-matrix) for the full breakdown.

## 3. Bootstrap the admin

The seed user exists in the store but has no client certificate yet. Generate an onboarding token, fetch the cert bundle, and import a Docker context:

```bash
# Issue a fresh onboard token for the admin user
docker exec rbac-proxy swcproxy user regenerate-token admin
```

`swcproxy` prints a ready-to-run `curl` command and `docker context import` command — copy them verbatim. The `-k` is there because the proxy's TLS cert is signed by a CA that your host doesn't trust by default; Docker CLI then uses the CA cert shipped inside the tar and does not need `-k`.

```bash
# Paste the curl and import commands printed by swcproxy, then switch to the new context
docker context use admin-managed
docker ps           # routed through the proxy, authenticated as admin
```

## 4. Create and onboard a regular user

```bash
docker exec rbac-proxy swcproxy user add alice
```

`swcproxy` prints Alice's onboard `curl` and `docker context import` commands. In a real deployment you share these with Alice over a secure channel; here, run them yourself on the same host (same shape as step 3).

## 5. See the exec guard in action

Start a disposable container to exec into:

```bash
docker context use default
docker run -d --name demo-target alpine sleep 3600
```

As admin, exec succeeds:

```bash
docker context use admin-managed
docker exec demo-target echo "hello from admin"
```

Alice — a regular user — is also allowed to exec on `demo-target`, because it isn't in any protected stack:

```bash
docker context use alice-managed
docker exec demo-target echo "hello from alice"    # allowed
```

The guard only denies exec into containers labelled with the proxy's own stack namespace (`com.docker.stack.namespace`), which is populated automatically by `docker stack deploy`. Our `docker run` deployment has no such label, so nothing is "protected" in this demo. To see a `403 Forbidden` for a regular user, deploy the proxy as a Swarm stack (see [README § Docker Swarm](../README.md#docker-swarm-recommended)) and try `docker exec` from Alice's context against the proxy container. See [Stack resource protection](configuration.md#stack-resource-protection) for the full permission matrix and how to set `PROXY_PROTECTED_STACK` explicitly.

## 6. Review the audit log

Every user creation, certificate issuance, guard denial, and onboarding completion is persisted. Inspect the last ten entries:

```bash
docker exec rbac-proxy swcproxy audit ls --limit 10
```

Expect to see at least:
- `token.regenerated` for the admin bootstrap in step 3.
- `cert.issued` + `onboard.completed` for the admin's and Alice's onboard curls.
- `user.created` for Alice (from step 4). The seed user is created at startup outside the audit path, so it has no corresponding entry.

Audit entries are stored in the same database as users (`/data/proxy.db` for SQLite, `audit_log` table for PostgreSQL). Back up the database and you back up the audit trail.

## Next steps

- Production deployment with Docker secrets — see [README § Production deployment](../README.md#production-deployment).
- Full environment variable and JSON config reference — see [configuration.md](configuration.md).
- Threat model, authentication layers, and certificate lifecycle — see [security.md](security.md).
- Management API endpoints — see [api.md](api.md).

### Cleanup

```bash
docker rm -f rbac-proxy demo-target
docker context rm admin-managed alice-managed
rm -rf /tmp/rbac-demo
```
