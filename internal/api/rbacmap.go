// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"net/http"
	"strings"

	"swarm-rbac-proxy/internal/store"
)

// rbacRoute is the classification of a request for authorization: the resource
// and verb it maps to, plus whether the resource participates in the
// stack-label OR (so a stack-labeled mutation is also authorized under the
// "stacks" resource). stackable/id are only consulted for mutating verbs.
type rbacRoute struct {
	resource  string
	verb      string
	stackable bool
	id        string // target resource id for update/delete (label back-query)
}

// stripDockerVersion drops a leading Docker API version segment (e.g. "v1.47")
// from a split path. Shared by mapRequest and the guard's path parsers.
func stripDockerVersion(parts []string) []string {
	if len(parts) > 0 && len(parts[0]) > 1 && parts[0][0] == 'v' && parts[0][1] >= '0' && parts[0][1] <= '9' {
		return parts[1:]
	}
	return parts
}

// resourceUnmapped is the sentinel resource assigned to any request that does
// not map to a known resource+verb (e.g. raw `docker run` via
// POST /containers/create, or a Docker endpoint not yet in the vocabulary). No
// scoped role grants it, so only the admin wildcard ("*") matches — i.e.
// unmapped operations are admin-only (default-deny for every other role).
const resourceUnmapped = "unmapped"

// mapRequest classifies an incoming proxy request into an rbacRoute. Every
// request yields a route: recognised paths map to their concrete resource+verb,
// and anything else falls back to the resourceUnmapped sentinel (admin-only).
func mapRequest(method, path string) rbacRoute {
	if route, ok := classifyRequest(method, path); ok {
		return route
	}
	return rbacRoute{resource: resourceUnmapped, verb: methodVerb(method)}
}

// methodVerb maps an HTTP method to a canonical verb for the unmapped fallback.
// The exact verb is immaterial — only the admin wildcard matches the sentinel
// resource — but a sensible verb keeps audit entries readable.
func methodVerb(method string) string {
	switch method {
	case http.MethodPost:
		return store.VerbCreate
	case http.MethodPut, http.MethodPatch:
		return store.VerbUpdate
	case http.MethodDelete:
		return store.VerbDelete
	default:
		return store.VerbGet
	}
}

// classifyRequest maps recognised paths to a resource+verb. ok is false for any
// path it does not recognise; mapRequest then applies the unmapped fallback.
func classifyRequest(method, path string) (rbacRoute, bool) {
	// Agent-manager paths (/v1/*).
	switch {
	case path == "/v1/exec" || strings.HasPrefix(path, "/v1/exec/"):
		return rbacRoute{resource: store.ResourceExec, verb: store.VerbCreate}, true
	case path == "/v1/forward" || strings.HasPrefix(path, "/v1/forward/"):
		return rbacRoute{resource: store.ResourcePortForward, verb: store.VerbCreate}, true
	case path == "/v1/logs" || strings.HasPrefix(path, "/v1/logs/"):
		return rbacRoute{resource: store.ResourceStackLogs, verb: store.VerbGet}, true
	case method == http.MethodGet && (path == "/v1/containers" || strings.HasPrefix(path, "/v1/containers/")):
		// Read-only per-container health/ports inventory, scoped by the
		// agent-manager to swarm service-task containers. Authorized as a
		// services read (viewer-allowed): its disclosure matches GET /tasks
		// (also services:list) and it exposes no mutation. Non-GET methods fall
		// through to the unmapped (admin-only) sentinel, mirroring how the raw
		// Docker /containers routes send non-reads to unmapped.
		return rbacRoute{resource: store.ResourceServices, verb: store.VerbList}, true
	case path == "/v1/volumes" || strings.HasPrefix(path, "/v1/volumes/"):
		return mapAgentVolume(method, path)
	}
	if strings.HasPrefix(path, "/v1/") {
		return rbacRoute{}, false // unknown agent path
	}

	parts := stripDockerVersion(strings.Split(strings.TrimPrefix(path, "/"), "/"))
	if len(parts) == 0 || parts[0] == "" {
		return rbacRoute{}, false
	}

	// System handshake endpoints — read-only, granted to every role. NB:
	// /events is deliberately NOT here — it streams cluster-wide resource
	// lifecycle (incl. secret/config names) and is not part of the handshake,
	// so it falls through to the admin-only unmapped fallback.
	switch parts[0] {
	case "_ping", "version", "info":
		return rbacRoute{resource: store.ResourceSystem, verb: store.VerbGet}, true
	}

	switch parts[0] {
	case "services", "secrets", "configs", "networks", "volumes":
		return mapStackable(method, parts)
	case "nodes":
		return mapNodes(method, parts)
	case "swarm":
		return mapSwarm(method, parts)
	case "tasks":
		return mapTasks(method, parts)
	case "containers":
		return mapContainers(method, parts)
	case "exec":
		return mapExec(method, parts)
	}
	return rbacRoute{}, false
}

// mapStackable maps the swarm resources that participate in the stack-label OR:
// services, secrets, configs, networks, volumes (Docker-socket path).
func mapStackable(method string, parts []string) (rbacRoute, bool) {
	res := parts[0]
	switch method {
	case http.MethodGet:
		switch {
		case len(parts) == 1:
			return rbacRoute{resource: res, verb: store.VerbList, stackable: true}, true
		case len(parts) >= 3 && parts[2] == "logs":
			return rbacRoute{resource: store.ResourceStackLogs, verb: store.VerbGet}, true
		default:
			return rbacRoute{resource: res, verb: store.VerbGet, stackable: true}, true
		}
	case http.MethodPost:
		switch {
		case len(parts) == 2 && parts[1] == "create":
			return rbacRoute{resource: res, verb: store.VerbCreate, stackable: true}, true
		case len(parts) == 3 && parts[2] == "update":
			// Service rollback (?rollback=previous) folds into update.
			return rbacRoute{resource: res, verb: store.VerbUpdate, stackable: true, id: parts[1]}, true
		case len(parts) == 3 && res == "networks" && (parts[2] == "connect" || parts[2] == "disconnect"):
			// Overlay-membership mutation — an update of the network.
			return rbacRoute{resource: res, verb: store.VerbUpdate, stackable: true, id: parts[1]}, true
		}
	case http.MethodDelete:
		if len(parts) == 2 {
			return rbacRoute{resource: res, verb: store.VerbDelete, stackable: true, id: parts[1]}, true
		}
	}
	return rbacRoute{}, false
}

func mapNodes(method string, parts []string) (rbacRoute, bool) {
	switch method {
	case http.MethodGet:
		if len(parts) == 1 {
			return rbacRoute{resource: store.ResourceNodes, verb: store.VerbList}, true
		}
		return rbacRoute{resource: store.ResourceNodes, verb: store.VerbGet}, true
	case http.MethodPost:
		if len(parts) == 3 && parts[2] == "update" {
			return rbacRoute{resource: store.ResourceNodes, verb: store.VerbUpdate}, true
		}
	case http.MethodDelete:
		if len(parts) == 2 {
			return rbacRoute{resource: store.ResourceNodes, verb: store.VerbDelete}, true
		}
	}
	return rbacRoute{}, false
}

func mapSwarm(method string, parts []string) (rbacRoute, bool) {
	// GET /swarm (inspect) exposes the join tokens, so it is admin-only like
	// every swarm mutation. Map the whole resource to the swarm vocabulary.
	if method == http.MethodGet {
		return rbacRoute{resource: store.ResourceSwarm, verb: store.VerbGet}, true
	}
	if method == http.MethodPost && len(parts) >= 2 {
		switch parts[1] {
		case "init", "join":
			return rbacRoute{resource: store.ResourceSwarm, verb: store.VerbCreate}, true
		case "leave":
			return rbacRoute{resource: store.ResourceSwarm, verb: store.VerbDelete}, true
		case "update", "unlock", "unlockkey":
			return rbacRoute{resource: store.ResourceSwarm, verb: store.VerbUpdate}, true
		}
	}
	return rbacRoute{}, false
}

func mapTasks(method string, parts []string) (rbacRoute, bool) {
	if method != http.MethodGet {
		return rbacRoute{}, false
	}
	if len(parts) >= 3 && parts[2] == "logs" {
		return rbacRoute{resource: store.ResourceStackLogs, verb: store.VerbGet}, true
	}
	// Tasks are service runtime instances — govern reads under services.
	if len(parts) == 1 {
		return rbacRoute{resource: store.ResourceServices, verb: store.VerbList}, true
	}
	return rbacRoute{resource: store.ResourceServices, verb: store.VerbGet}, true
}

func mapContainers(method string, parts []string) (rbacRoute, bool) {
	// Exec / attach — interactive access, governed by the exec resource. The
	// protected-stack ExecGuard further restricts these on top of RBAC.
	if len(parts) >= 3 {
		if parts[2] == "exec" && method == http.MethodPost {
			return rbacRoute{resource: store.ResourceExec, verb: store.VerbCreate}, true
		}
		if parts[2] == "attach" {
			return rbacRoute{resource: store.ResourceExec, verb: store.VerbCreate}, true
		}
		if parts[2] == "logs" && method == http.MethodGet {
			return rbacRoute{resource: store.ResourceStackLogs, verb: store.VerbGet}, true
		}
	}
	// Other container reads (inspect, list, stats, top, …) are service-runtime
	// reads. Container *mutations* (create/start/stop/rm — raw `docker run`)
	// are deliberately unmapped → default-deny → admin-only.
	if method == http.MethodGet {
		if len(parts) == 2 && parts[1] == "json" {
			return rbacRoute{resource: store.ResourceServices, verb: store.VerbList}, true
		}
		return rbacRoute{resource: store.ResourceServices, verb: store.VerbGet}, true
	}
	return rbacRoute{}, false
}

// mapExec maps the Docker exec lifecycle that follows POST /containers/{id}/exec:
// POST /exec/{id}/start (the hijack that actually runs it), POST
// /exec/{id}/resize, and GET /exec/{id}/json. The whole lifecycle is one
// capability, so all of it maps to exec:create — otherwise a role granted exec
// could create an exec instance but not start it.
func mapExec(method string, parts []string) (rbacRoute, bool) {
	if len(parts) >= 3 {
		switch {
		case parts[2] == "start" && method == http.MethodPost:
			return rbacRoute{resource: store.ResourceExec, verb: store.VerbCreate}, true
		case parts[2] == "resize" && method == http.MethodPost:
			return rbacRoute{resource: store.ResourceExec, verb: store.VerbCreate}, true
		case parts[2] == "json" && method == http.MethodGet:
			return rbacRoute{resource: store.ResourceExec, verb: store.VerbCreate}, true
		}
	}
	return rbacRoute{}, false
}

// mapAgentVolume maps the agent-manager volume endpoints (/v1/volumes...).
// These are node-local volume operations; they do not participate in the
// stack-label OR (the volume guard resolves protected-stack ownership on top).
func mapAgentVolume(method, path string) (rbacRoute, bool) {
	rest := strings.TrimPrefix(strings.TrimPrefix(path, "/v1/volumes"), "/")
	var parts []string
	if rest != "" {
		parts = strings.Split(rest, "/")
	}
	switch method {
	case http.MethodGet:
		if len(parts) == 0 {
			return rbacRoute{resource: store.ResourceVolumes, verb: store.VerbList}, true
		}
		return rbacRoute{resource: store.ResourceVolumes, verb: store.VerbGet}, true
	case http.MethodPost:
		// /v1/volumes (create), /v1/volumes/prune (bulk delete),
		// /v1/volumes/{name}/files/rename (mutate).
		if len(parts) == 1 && parts[0] == "prune" {
			return rbacRoute{resource: store.ResourceVolumes, verb: store.VerbDelete}, true
		}
		if len(parts) == 0 {
			return rbacRoute{resource: store.ResourceVolumes, verb: store.VerbCreate}, true
		}
		return rbacRoute{resource: store.ResourceVolumes, verb: store.VerbUpdate}, true
	case http.MethodDelete:
		// /v1/volumes/{name} or /v1/volumes/{name}/files — volume mutation.
		return rbacRoute{resource: store.ResourceVolumes, verb: store.VerbDelete}, true
	}
	return rbacRoute{}, false
}
