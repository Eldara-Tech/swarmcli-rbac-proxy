# Roles and permissions (RBAC)

The proxy authorizes every Docker and agent request on the external (mTLS)
listener against the caller's **roles**. This is the primary authorization
layer; the [protected-stack guard](configuration.md#stack-resource-protection)
is a second, narrower layer that composes with it.

Older releases shipped a fixed two-role model (`admin` / `user`). That has been
replaced by a dynamic, Kubernetes-style RBAC layer: named roles, per-user
bindings, and a default-deny policy. If you are upgrading from the two-role
model, read [Upgrading from admin/user](#upgrading-from-adminuser) first.

## The model

- A **role** is a named set of permission rules. Each rule is a
  `{resources, verbs}` pair; `*` is allowed as a wildcard for either.
- A **binding** maps one user to one role. A user may have several bindings.
- A user's **effective permission** is the union of the rules of all roles bound
  to them. Rules are purely additive — there are no deny rules.
- The policy is **default-deny**: a request is allowed only if some bound role
  grants its `{resource, verb}`. Anything unmapped or ungranted is a `403`.

The resource vocabulary is:

```
stacks, stack logs, services, nodes, networks, volumes,
configs, secrets, exec, port-forward, swarm, system, roles, bindings
```

The verbs are `get`, `list`, `create`, `update`, `delete` (and `*` for all).
The proxy maps each incoming request to exactly one `{resource, verb}` — for
example `GET /services` → `services:list`, `POST /services/{id}/update` →
`services:update`, `GET /v1/exec` → `exec:create`, `GET /swarm` → `swarm:get`.
Reads are authorized too, not just mutations. Raw or unrecognised operations
(e.g. `POST /containers/create`, `GET /events`) map to an internal *unmapped*
sentinel and are therefore **admin-only**.

## Built-in roles

Three roles are seeded on startup and are editable (an admin can adjust their
rules; they are never overwritten if you do). They cannot be deleted.

- **`viewer`** — read-only across the common Swarm resources. Cannot read
  secrets, volumes, or configs; cannot exec, deploy, or mutate anything.
- **`operator`** — everything `viewer` can read, plus volume and config reads,
  plus deploy/update of stacks and services and interactive `exec` /
  `port-forward` into non-infrastructure workloads. Cannot delete stacks,
  enumerate secrets, or touch swarm-level state. This is the default role for a
  newly created non-admin user.
- **`admin`** — unrestricted (`*:*`).

### Permission matrix

Verbs: **G**=get **L**=list **C**=create **U**=update **D**=delete, `*`=all.

| resource | viewer | operator | admin |
|---|---|---|---|
| stacks | GL | GLCU | * |
| stack logs | GL | GL | * |
| services | GL | GLCU | * |
| nodes | GL | GL | * |
| networks | GL | GL | * |
| volumes | — | GL | * |
| configs | — | GL | * |
| secrets | — | — | * |
| exec / attach | — | C | * |
| port-forward | — | C | * |
| swarm | — | — | * |
| system (`_ping` / `version` / `info`) | GL | GL | GL |
| roles / bindings | — | — | * |
| containers (raw run) / unmapped (incl. `/events`) | — | — | * |

`system` covers the Docker handshake endpoints (`_ping`, `version`, `info`) and
is granted to every role so that `docker version` / `docker info` work for all
users. `/events` is **not** part of `system` — it streams cluster-wide resource
lifecycle (including secret and config names) and is therefore admin-only.

### How stacks are authorized

Docker has no `/stacks` endpoint — `docker stack deploy` is a set of labeled
`services` / `networks` / `configs` / `secrets` creates. A **mutating** request
whose target carries the `com.docker.stack.namespace` label is authorized under
the `stacks` resource **OR** the concrete resource. So `operator` (which has
`stacks: create, update`) can deploy a full stack including its overlay
networks, configs, and secrets — but cannot create *standalone* infrastructure
resources, delete stacks (no `stacks: delete`), or enumerate secrets.

**Reads** use the concrete resource only — there is no stacks-OR shortcut — so a
`viewer`'s lack of `secrets` read cannot be bypassed by attaching a stack label.

## How RBAC composes with the protected-stack guard

RBAC decides what a role *may* do; the protected-stack guard then independently
blocks mutations to the proxy's own infrastructure stack — for **every** role,
including admin. The two layers are evaluated in series and **deny wins**:

```
RequireClientCert → RBAC → ExecGuard → ResourceGuard → proxy
```

So an `operator` with `stacks: create` is still blocked from injecting resources
into the protected stack, and even an `admin` cannot delete protected services or
pivot onto the protected overlay through the external listener. See
[configuration.md § Stack resource protection](configuration.md#stack-resource-protection)
for that layer's full matrix and rationale.

RBAC is enforced **only on the external listener and only when mTLS is
configured** (there is no identity to authorize otherwise). The internal
loopback listener (`PROXY_INTERNAL_LISTEN`) bypasses RBAC entirely — it is the
sanctioned path for admin automation inside the container.

## Managing roles and bindings

Two equivalent surfaces: the `swcproxy` CLI (direct store access, run inside the
container) and the admin-token-protected management API.

### CLI

```bash
swcproxy role ls                    # list roles (name, builtin, rule count)
swcproxy role show <name>           # show a role's resources/verbs
swcproxy binding ls                 # list user→role bindings
swcproxy binding add <user> <role>  # bind a user to a role
swcproxy binding rm <id>            # remove a binding (last-admin protected)
```

The CLI inspects roles but does not create them — define custom roles via the
API below. `swcproxy user add <name> [--admin]` automatically creates the
matching binding (`--admin` → `admin`, otherwise `operator`), so the legacy role
flag and the RBAC binding stay in sync.

### API

The `/api/v1/roles` and `/api/v1/bindings` endpoints support full CRUD and are
protected by the admin bearer token. See
[api.md § RBAC: roles and bindings](api.md#rbac-roles-and-bindings) for request
and response shapes. In brief:

```bash
# Define a custom "deployer" role: deploy & manage stacks, nothing else
curl -s -X POST http://localhost:2375/api/v1/roles \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"name":"deployer","rules":[{"resources":["stacks","services"],"verbs":["get","list","create","update"]}]}'

# Bind alice to it
curl -s -X POST http://localhost:2375/api/v1/bindings \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"username":"alice","role_name":"deployer"}'
```

### Guard rails

- Built-in roles cannot be deleted (`409`).
- A role still referenced by a binding cannot be deleted (`409`).
- **Last-admin lockout protection**: the last binding that grants `admin` cannot
  be removed, and a role update that would leave the cluster with no admin is
  refused (`409`). Disabled admin users do not count toward this guard.

## Upgrading from admin/user

> **Breaking change.** Releases before RBAC used a fixed `admin` / `user` model.

On first startup after the upgrade, existing identities are migrated
automatically:

- `User.Role == admin` → bound to the **`admin`** role (unchanged: unrestricted).
- every other user → bound to the **`operator`** role.

`operator` (not `viewer`) is the migration target so that an upgraded non-admin
keeps the non-protected stack/service create/update and exec/port-forward it had
under the old model. What changes is that **reads are now authorized per the
matrix** under default-deny: a migrated non-admin loses the previously
permissive reads of `secrets` and `swarm` and the ability to create or delete
non-protected volumes.

After upgrading, review your bindings (`swcproxy binding ls`) and assign
`viewer` to anyone who should be read-only, or define custom roles for anything
in between.

The legacy `User.Role` flag is retained, but only as the input to the
protected-stack guard's separate `isAdmin` gate — it is no longer the
authorization model.

## Auditing

A request rejected by the RBAC policy engine is recorded as `rbac.denied` —
distinct from `guard.blocked`, which marks protected-stack denials. Query with
`swcproxy audit ls`.

The complete action vocabulary, which is what you need when writing a SIEM rule:

| Group | Actions |
|---|---|
| Users | `user.created`, `user.updated` (enable/disable/role change), `user.deleted` |
| Credentials | `cert.issued`, `onboard.completed`, `token.regenerated` |
| Denials | `rbac.denied` (policy engine), `guard.blocked` (protected-stack guard, volume denials included) |
| RBAC management | `role.created`, `role.updated`, `role.deleted`, `binding.created`, `binding.deleted` |
| Volumes | `volume.created`, `volume.deleted`, `volume.file.deleted`, `volume.file.renamed`, `volume.file.uploaded`, `volume.pruned` |
| Backup | `backup.exported`, `backup.restored` |

Volume actions are recorded on **success**; a volume denial appears as
`guard.blocked` like every other guarded operation.

Each entry records id, timestamp, actor, action, resource (`type:id`), status
(`success` / `denied`), detail and source IP. The actor is a username, or one of
`cli`, `internal` (triggered via the internal listener) or `anonymous`.

Authentication events — mTLS success and failure — are logged to stdout only and
are **not** persisted to the audit table, so do not build an authentication alert
on this table alone.

## See also

- [api.md](api.md#rbac-roles-and-bindings) — roles/bindings management API reference
- [security.md](security.md) — authorization layers and threat model
- [configuration.md § Stack resource protection](configuration.md#stack-resource-protection) — the protected-stack guard matrix
