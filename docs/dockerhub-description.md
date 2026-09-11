# Docker Hub description (source of truth)

This file is the source of truth for the public Docker Hub description of
`eldaratech/swarmcli-rbac-proxy`. After each user-visible change, paste the
sections below into the Docker Hub repo console (*Repository Settings → General
→ Description / Full Description*). This is a manual step today; if it becomes a
recurring chore it can be scripted against the Docker Hub API later.
`swarmcli` and `swarmcli-agent` keep the same file.

The image has two fields:

- **Short description** — one line, maximum ~100 characters.
- **Full description** — Markdown, rendered on the repo page. Relative links do
  **not** resolve there, so every link below is absolute.

---

### Short description

```
mTLS + RBAC for the Docker API: per-user client certificates, roles enforced on every call.
```

### Full description

Paste everything between the two markers below (markers excluded):

<!-- BEGIN swarmcli-rbac-proxy full description -->
## SwarmCLI RBAC Proxy

Multi-user access control for Docker Swarm. It sits between Docker CLI clients
and the daemon, authenticating each user by mTLS client certificate and
enforcing role-based permissions on every API call.

Docker Swarm has no built-in multi-user access control: anyone who can reach the
socket or the TCP endpoint is an admin. This proxy adds per-user authentication,
role-based authorization and infrastructure protection without modifying the
Docker daemon or the Docker CLI.

- Website: https://swarmcli.io
- Source and documentation: https://github.com/Eldara-Tech/swarmcli-rbac-proxy

### Where it sits

```
docker CLI ──mTLS──> swarmcli-rbac-proxy ──> Docker daemon (unix socket or TCP)
                              │
                              ├── authenticates by client certificate (CN/SAN)
                              ├── authorizes by role (default-deny)
                              └── blocks mutations to the infrastructure stack
```

### What it does

- **mTLS client certificates** — one certificate per user, no shared credentials.
- **Role-based access control** — Kubernetes-style roles and per-user bindings,
  default-deny, with built-in `viewer` / `operator` / `admin` plus custom roles.
- **Infrastructure stack protection** — detects the proxy's own Swarm stack and
  refuses external attempts to change its services, secrets, networks or configs.
- **Exec/attach guard** — non-admin users cannot exec into protected containers.
- **Automatic certificate issuance** — client certificates are minted on user
  creation; nobody runs `openssl` by hand.
- **One-command onboarding** — a new user runs one `curl` and one
  `docker context import`.
- **Dual listener** — external mTLS for users, internal plain TCP for admin
  automation on the manager node.
- **Audit log** — user creation, certificate issuance, guard denials and
  completed onboarding are persisted alongside the user store.

### Getting started

The walkthrough — generating a CA, starting the proxy with mTLS, onboarding an
admin and a regular user, and watching the exec guard refuse — is here:

https://github.com/Eldara-Tech/swarmcli-rbac-proxy/blob/main/docs/getting-started.md

Reference: [configuration](https://github.com/Eldara-Tech/swarmcli-rbac-proxy/blob/main/docs/configuration.md)
· [RBAC model](https://github.com/Eldara-Tech/swarmcli-rbac-proxy/blob/main/docs/rbac.md)
· [security and threat model](https://github.com/Eldara-Tech/swarmcli-rbac-proxy/blob/main/docs/security.md)
· [management API](https://github.com/Eldara-Tech/swarmcli-rbac-proxy/blob/main/docs/api.md)

### Security notes

**The internal listener performs no role checks.** It exists for admin
automation on a manager node and must stay bound to loopback or an internal
overlay network — never published to the host.

**The proxy is only as strong as the client CA.** Anything holding the CA key
can mint a user, so treat `PROXY_TLS_CLIENT_CA_KEY` as a Docker secret in
production rather than a bind-mounted file.

### Tags

Tags are **bare semver without a leading `v`** — `2.1.3` — alongside a moving
`<major>.<minor>` tag (`2.1`) and `latest`. Pin an exact version in production.
The image is `linux/amd64`.

### Version compatibility

SwarmCLI Business Edition deploys this proxy and pins a tested tag per release.
If you run it as part of a Business Edition stack, use the tag named in that
release's compatibility table rather than `latest`.

### Support

Issues and discussion: https://github.com/Eldara-Tech/swarmcli-rbac-proxy/issues
<!-- END swarmcli-rbac-proxy full description -->
