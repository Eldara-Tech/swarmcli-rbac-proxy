// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"swarm-rbac-proxy/internal/store"
)

// dockerRoute describes a parsed Docker API request targeting a protected
// resource type.
type dockerRoute struct {
	resource string // "services", "secrets", "networks", "volumes", "configs", "swarm"
	id       string // resource ID or name (empty for create/leave)
	action   string // "delete", "update", "create", "leave"
}

// protectedResources lists Docker resource types whose stack membership
// the guard checks.
var protectedResources = map[string]bool{
	"services": true,
	"secrets":  true,
	"networks": true,
	"volumes":  true,
	"configs":  true,
}

// parseDockerPath extracts the resource type, ID, and action from a Docker
// API request. Returns nil if the request does not target a protected
// operation.
func parseDockerPath(method, path string) *dockerRoute {
	// Split and drop empty leading segment.
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 0 {
		return nil
	}

	// Strip optional version prefix (e.g. "v1.47").
	if len(parts) > 0 && len(parts[0]) > 1 && parts[0][0] == 'v' && parts[0][1] >= '0' && parts[0][1] <= '9' {
		parts = parts[1:]
	}

	if len(parts) == 0 {
		return nil
	}

	// POST /swarm/leave
	if len(parts) >= 2 && parts[0] == "swarm" && parts[1] == "leave" && method == http.MethodPost {
		return &dockerRoute{resource: "swarm", action: "leave"}
	}

	resource := parts[0]
	if !protectedResources[resource] {
		return nil
	}

	switch {
	// POST /{resource}/create
	case len(parts) == 2 && parts[1] == "create" && method == http.MethodPost:
		return &dockerRoute{resource: resource, action: "create"}

	// DELETE /{resource}/{id}
	case len(parts) == 2 && method == http.MethodDelete:
		return &dockerRoute{resource: resource, id: parts[1], action: "delete"}

	// POST /networks/{id}/{connect,disconnect} — overlay-membership
	// mutations; must match before the generic update case because action
	// differs.
	case len(parts) == 3 && resource == "networks" &&
		(parts[2] == "connect" || parts[2] == "disconnect") &&
		method == http.MethodPost:
		return &dockerRoute{resource: "networks", id: parts[1], action: parts[2]}

	// POST /{resource}/{id}/update
	case len(parts) == 3 && parts[2] == "update" && method == http.MethodPost:
		return &dockerRoute{resource: resource, id: parts[1], action: "update"}
	}

	return nil
}

// isInternalListener returns true when the request was explicitly stamped
// by MarkInternalRequest, meaning it arrived on the plain TCP listener.
// Using a positive signal (rather than absence of a user) prevents an auth
// bypass on the external listener from being misread as an internal request.
func isInternalListener(r *http.Request) bool {
	internal, ok := r.Context().Value(ContextKeyInternal).(bool)
	return ok && internal
}

// isAdmin returns true if the request comes from a user with the admin role.
// Returns false for the internal listener (no user context).
func isAdmin(r *http.Request) bool {
	user, ok := r.Context().Value(ContextKeyUser).(*store.User)
	if !ok || user == nil {
		return false
	}
	return user.Role == "admin"
}

// ExecGuard returns middleware that requires admin role only for exec/attach
// requests targeting containers that belong to the protected stack. Exec on
// containers in any other stack is allowed for all authenticated users.
//
// If stackName is empty the guard is a no-op (exec unrestricted).
// The internal listener (no user context) always bypasses this check.
// A back-query error (Docker daemon unreachable) causes fail-closed (503).
func (g *ResourceGuard) ExecGuard(next http.Handler) http.Handler {
	if g == nil || g.stackName == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isExecPath(r.Method, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		// No isInternalListener bypass here: the internal listener is wired
		// with noExecGuard in main.go and never reaches this handler. A missing
		// ContextKeyInternal (or ContextKeyUser) inside ExecGuard means
		// external-without-mTLS — keep fail-closed for protected containers.
		protected, err := g.isProtectedExecTarget(r.Context(), r.URL.Path, r.URL.Query())
		if err != nil {
			l().Warnw("guard: back-query failed, blocking exec", "error", err)
			writeError(w, http.StatusServiceUnavailable, "cannot verify exec target ownership")
			return
		}
		if protected && !isAdmin(r) {
			recordAudit(g.audit, r, store.AuditGuardBlocked, "exec:"+r.URL.Path, "denied", "protected stack exec")
			writeError(w, http.StatusForbidden, "exec on protected stack requires admin role")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isExecPath returns true if the request targets an exec/attach endpoint,
// covering both the Docker API and the agent API.
func isExecPath(method, path string) bool {
	// Agent exec: /v1/exec
	if path == "/v1/exec" || strings.HasPrefix(path, "/v1/exec/") {
		return true
	}

	// Docker exec/attach: /[vN.NN/]containers/{id}/exec or .../attach[/ws]
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 0 && len(parts[0]) > 1 && parts[0][0] == 'v' && parts[0][1] >= '0' && parts[0][1] <= '9' {
		parts = parts[1:]
	}
	if len(parts) >= 3 && parts[0] == "containers" {
		// POST .../exec, POST .../attach, GET .../attach/ws
		if parts[2] == "exec" && method == http.MethodPost {
			return true
		}
		if parts[2] == "attach" {
			return true
		}
	}
	return false
}

// ResourceGuard is middleware that protects Docker Swarm stack resources
// from mutation via the external listener.
type ResourceGuard struct {
	stackName  string
	httpClient *http.Client
	audit      store.AuditStore
}

// NewResourceGuard creates a ResourceGuard that protects the given stack.
// socketPath is the Docker daemon Unix socket used for back-queries.
// If stackName is empty the guard is a no-op.
func NewResourceGuard(stackName, socketPath string, audit store.AuditStore) *ResourceGuard {
	g := &ResourceGuard{stackName: stackName, audit: audit}
	if socketPath != "" {
		g.httpClient = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
				},
			},
		}
	}
	return g
}

// Wrap returns middleware that enforces the guard policy.
func (g *ResourceGuard) Wrap(next http.Handler) http.Handler {
	if g == nil || g.stackName == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := parseDockerPath(r.Method, r.URL.Path)
		if route == nil {
			next.ServeHTTP(w, r)
			return
		}

		if isInternalListener(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Unconditional block for all external users.
		if route.resource == "swarm" && route.action == "leave" {
			l().Warnw("guard: blocked swarm leave", "path", r.URL.Path)
			recordAudit(g.audit, r, store.AuditGuardBlocked, "swarm:leave", "denied", "swarm leave requires direct access")
			writeError(w, http.StatusForbidden, "swarm leave requires direct access")
			return
		}

		switch route.action {
		case "create":
			data, err := g.readCreateBody(r)
			if err != nil {
				l().Warnw("guard: body read error, blocking create", "error", err)
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			protected, err := g.bodyHasProtectedLabel(data)
			if err != nil {
				l().Warnw("guard: body parse error, blocking create", "error", err)
				writeError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			if protected {
				l().Warnw("guard: blocked create in protected stack", "path", r.URL.Path)
				recordAudit(g.audit, r, store.AuditGuardBlocked, route.resource+":create", "denied", "protected stack")
				writeError(w, http.StatusForbidden, "cannot create resources in protected stack")
				return
			}
			// T1: a non-admin `user` role can otherwise create a service in a
			// non-protected namespace that attaches to the protected overlay,
			// pivoting onto `agent-net`. Admins bypass (symmetric with
			// update branch).
			if route.resource == "services" && !isAdmin(r) {
				attached, err := g.bodyHasProtectedNetworkAttachment(r.Context(), data)
				if err != nil {
					l().Warnw("guard: network back-query failed, blocking create", "error", err)
					writeError(w, http.StatusServiceUnavailable, "cannot verify network ownership")
					return
				}
				if attached {
					l().Warnw("guard: blocked create attaching to protected stack network", "path", r.URL.Path)
					recordAudit(g.audit, r, store.AuditGuardBlocked, route.resource+":create", "denied", "protected stack network attachment")
					writeError(w, http.StatusForbidden, "cannot attach to protected stack network")
					return
				}
			}

		case "update":
			if isAdmin(r) {
				break // admins may update protected resources
			}
			protected, err := g.isProtectedResource(r.Context(), route.resource, route.id)
			if err != nil {
				l().Warnw("guard: back-query failed, blocking update", "error", err, "resource", route.resource, "id", route.id)
				writeError(w, http.StatusServiceUnavailable, "cannot verify resource ownership")
				return
			}
			if protected {
				l().Warnw("guard: blocked update of protected resource", "path", r.URL.Path, "resource", route.resource, "id", route.id)
				recordAudit(g.audit, r, store.AuditGuardBlocked, route.resource+":"+route.id, "denied", "protected stack update")
				writeError(w, http.StatusForbidden, "cannot modify protected stack resource")
				return
			}
			// T1: same pivot as create, via service update.
			if route.resource == "services" {
				data, err := g.readCreateBody(r)
				if err != nil {
					l().Warnw("guard: body read error, blocking update", "error", err)
					writeError(w, http.StatusBadRequest, "invalid request body")
					return
				}
				attached, err := g.bodyHasProtectedNetworkAttachment(r.Context(), data)
				if err != nil {
					l().Warnw("guard: network back-query failed, blocking update", "error", err)
					writeError(w, http.StatusServiceUnavailable, "cannot verify network ownership")
					return
				}
				if attached {
					l().Warnw("guard: blocked update attaching to protected stack network", "path", r.URL.Path, "resource", route.resource, "id", route.id)
					recordAudit(g.audit, r, store.AuditGuardBlocked, route.resource+":"+route.id, "denied", "protected stack network attachment (update)")
					writeError(w, http.StatusForbidden, "cannot attach to protected stack network")
					return
				}
			}

		case "connect", "disconnect":
			// T2: overlay-membership mutation. Admins bypass (symmetric with
			// update); non-admins are blocked from (dis)connecting any
			// workload to/from the protected stack overlay.
			if isAdmin(r) {
				break
			}
			protected, err := g.isProtectedResource(r.Context(), "networks", route.id)
			if err != nil {
				l().Warnw("guard: back-query failed, blocking network "+route.action, "error", err, "id", route.id)
				writeError(w, http.StatusServiceUnavailable, "cannot verify network ownership")
				return
			}
			if protected {
				l().Warnw("guard: blocked "+route.action+" of protected stack network", "path", r.URL.Path, "id", route.id)
				recordAudit(g.audit, r, store.AuditGuardBlocked, "networks:"+route.id, "denied", "protected stack network "+route.action)
				writeError(w, http.StatusForbidden, "cannot "+route.action+" protected stack network")
				return
			}

		case "delete":
			protected, err := g.isProtectedResource(r.Context(), route.resource, route.id)
			if err != nil {
				l().Warnw("guard: back-query failed, blocking delete", "error", err, "resource", route.resource, "id", route.id)
				writeError(w, http.StatusServiceUnavailable, "cannot verify resource ownership")
				return
			}
			if protected {
				l().Warnw("guard: blocked delete of protected resource", "path", r.URL.Path, "resource", route.resource, "id", route.id)
				recordAudit(g.audit, r, store.AuditGuardBlocked, route.resource+":"+route.id, "denied", "protected stack delete")
				writeError(w, http.StatusForbidden, "cannot delete protected stack resource")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isProtectedResource checks whether the Docker resource belongs to the
// protected stack by querying the Docker API.
func (g *ResourceGuard) isProtectedResource(ctx context.Context, resource, id string) (bool, error) {
	if g.httpClient == nil {
		return false, nil
	}

	url := "http://docker/" + resource + "/" + id
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 {
			return false, fmt.Errorf("docker API returned %d", resp.StatusCode)
		}
		return false, nil // resource not found — not protected
	}

	// Networks and volumes have Labels at top level; services, secrets,
	// and configs have them under Spec.Labels.
	var result struct {
		Labels map[string]string `json:"Labels"`
		Spec   struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Spec"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	if result.Spec.Labels[stackNamespaceLabel] == g.stackName {
		return true, nil
	}
	if result.Labels[stackNamespaceLabel] == g.stackName {
		return true, nil
	}
	return false, nil
}

// readCreateBody reads the request body with a 2 MB cap and restores it so
// downstream handlers can still read it. Returns nil data for a nil body.
// Multiple inspectors may call this: subsequent calls re-read the restored
// NopCloser and see the same bytes.
func (g *ResourceGuard) readCreateBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	const maxCreateBodySize = 2 << 20 // 2 MB
	data, err := io.ReadAll(io.LimitReader(r.Body, maxCreateBodySize+1))
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	if int64(len(data)) > maxCreateBodySize {
		return nil, fmt.Errorf("request body exceeds %d bytes", maxCreateBodySize)
	}
	return data, nil
}

// bodyHasProtectedLabel checks whether a create-request payload carries the
// protected stack's namespace label at top level or under Spec.
func (g *ResourceGuard) bodyHasProtectedLabel(data []byte) (bool, error) {
	if len(data) == 0 {
		return false, nil
	}
	var body struct {
		Labels map[string]string `json:"Labels"`
		Spec   struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Spec"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return false, err
	}
	if body.Labels[stackNamespaceLabel] == g.stackName {
		return true, nil
	}
	if body.Spec.Labels[stackNamespaceLabel] == g.stackName {
		return true, nil
	}
	return false, nil
}

// bodyHasProtectedNetworkAttachment checks whether a service create/update
// payload's TaskTemplate.Networks[] references any network that belongs to
// the protected stack. Each referenced network id is resolved via the Docker
// back-query; a 5xx from the daemon is surfaced as an error so the caller
// can fail-closed.
func (g *ResourceGuard) bodyHasProtectedNetworkAttachment(ctx context.Context, data []byte) (bool, error) {
	if len(data) == 0 {
		return false, nil
	}
	var body struct {
		TaskTemplate struct {
			Networks []struct {
				Target string `json:"Target"`
			} `json:"Networks"`
		} `json:"TaskTemplate"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return false, err
	}
	for _, n := range body.TaskTemplate.Networks {
		if n.Target == "" {
			continue
		}
		protected, err := g.isProtectedResource(ctx, "networks", n.Target)
		if err != nil {
			return false, err
		}
		if protected {
			return true, nil
		}
	}
	return false, nil
}

// isProtectedExecTarget resolves the exec target from the request path and
// query to determine whether it belongs to the protected stack.
// Returns (false, nil) when the target cannot be identified (allow through).
func (g *ResourceGuard) isProtectedExecTarget(ctx context.Context, path string, query url.Values) (bool, error) {
	// Agent exec: /v1/exec?task_id=<swarm-task-id>
	if path == "/v1/exec" || strings.HasPrefix(path, "/v1/exec/") {
		taskID := query.Get("task_id")
		if taskID == "" {
			return false, nil // no target to check; agent will reject the request anyway
		}
		return g.isProtectedTask(ctx, taskID)
	}

	// Docker exec/attach: /[vN.NN/]containers/{id}/exec|attach[/ws]
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 0 && len(parts[0]) > 1 && parts[0][0] == 'v' && parts[0][1] >= '0' && parts[0][1] <= '9' {
		parts = parts[1:]
	}
	if len(parts) >= 3 && parts[0] == "containers" {
		return g.isProtectedContainer(ctx, parts[1])
	}
	return false, nil
}

// isProtectedTask resolves a Swarm task ID to its parent service and checks
// whether that service belongs to the protected stack.
func (g *ResourceGuard) isProtectedTask(ctx context.Context, taskID string) (bool, error) {
	if g.httpClient == nil {
		return false, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/tasks/"+taskID, nil)
	if err != nil {
		return false, err
	}
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 {
			return false, fmt.Errorf("docker API returned %d for task %s", resp.StatusCode, taskID)
		}
		return false, nil // task not found — not protected
	}
	var task struct {
		ServiceID string `json:"ServiceID"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&task); err != nil {
		return false, err
	}
	if task.ServiceID == "" {
		return false, nil
	}
	return g.isProtectedResource(ctx, "services", task.ServiceID)
}

// isProtectedContainer checks whether a container belongs to the protected
// stack by inspecting its Config.Labels via the Docker API.
func (g *ResourceGuard) isProtectedContainer(ctx context.Context, containerID string) (bool, error) {
	if g.httpClient == nil {
		return false, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+containerID+"/json", nil)
	if err != nil {
		return false, err
	}
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 {
			return false, fmt.Errorf("docker API returned %d for container %s", resp.StatusCode, containerID)
		}
		return false, nil // container not found — not protected
	}
	var result struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Config.Labels[stackNamespaceLabel] == g.stackName, nil
}
