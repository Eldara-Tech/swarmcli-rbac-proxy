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
}

// NewResourceGuard creates a ResourceGuard that protects the given stack.
// socketPath is the Docker daemon Unix socket used for back-queries.
// If stackName is empty the guard is a no-op.
func NewResourceGuard(stackName, socketPath string) *ResourceGuard {
	g := &ResourceGuard{stackName: stackName}
	if socketPath != "" {
		g.httpClient = &http.Client{
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
			writeError(w, http.StatusForbidden, "swarm leave requires direct access")
			return
		}

		switch route.action {
		case "create":
			protected, err := g.hasProtectedLabel(r)
			if err != nil {
				l().Warnw("guard: body parse error, allowing request", "error", err)
			}
			if protected {
				l().Warnw("guard: blocked create in protected stack", "path", r.URL.Path)
				writeError(w, http.StatusForbidden, "cannot create resources in protected stack")
				return
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
				writeError(w, http.StatusForbidden, "cannot modify protected stack resource")
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

// hasProtectedLabel reads the request body for create operations and checks
// whether the payload contains the protected stack's namespace label.
// The body is replaced so downstream handlers can still read it.
func (g *ResourceGuard) hasProtectedLabel(r *http.Request) (bool, error) {
	if r.Body == nil {
		return false, nil
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		return false, err
	}
	r.Body = io.NopCloser(bytes.NewReader(data))

	if len(data) == 0 {
		return false, nil
	}

	// Check Labels at top level and under Spec.
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
