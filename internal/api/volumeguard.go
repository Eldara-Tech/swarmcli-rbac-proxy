// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"swarm-rbac-proxy/internal/store"
)

// isVolumePath reports whether the request targets the agent-manager volume
// endpoints (/v1/volumes...).
func isVolumePath(path string) bool {
	return path == "/v1/volumes" || strings.HasPrefix(path, "/v1/volumes/")
}

// guardVolume enforces the stack-scoped policy for volume management:
//   - reads (GET) are allowed for any authenticated user;
//   - mutations on a volume belonging to the protected stack require admin;
//     mutations on any other volume are allowed for all authenticated users.
//
// The target volume's stack is resolved server-side via an agent-manager
// back-query (volumes are node-local, so a client-supplied label can't be
// trusted and the Docker-socket back-query can't see them). A back-query error
// fails closed (503). Successful mutations are audited.
func (g *ResourceGuard) guardVolume(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if r.Method == http.MethodGet {
		next.ServeHTTP(w, r)
		return
	}

	// Prune is a node-wide bulk delete not tied to a single volume, so the
	// per-volume stack back-query doesn't apply: gate it on admin outright.
	if r.URL.Path == "/v1/volumes/prune" {
		if !isAdmin(r) {
			l().Warnw("guard: blocked volume prune by non-admin", "path", r.URL.Path)
			recordAudit(g.audit, r, store.AuditGuardBlocked, "volumes:prune", "denied", "prune requires admin")
			writeError(w, http.StatusForbidden, "pruning volumes requires admin role")
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if rec.status >= 200 && rec.status < 300 {
			recordAudit(g.audit, r, store.AuditVolumePruned, "volumes:prune", "success", "prune unused volumes")
		}
		return
	}

	nodeID := r.URL.Query().Get("node_id")
	name, err := g.volumeNameForRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid volume request")
		return
	}

	protected, err := g.isProtectedVolume(r.Context(), nodeID, name)
	if err != nil {
		l().Warnw("guard: volume back-query failed, blocking mutation", "error", err, "node", nodeID, "name", name)
		writeError(w, http.StatusServiceUnavailable, "cannot verify volume ownership")
		return
	}
	if protected && !isAdmin(r) {
		l().Warnw("guard: blocked mutation of protected-stack volume", "path", r.URL.Path, "name", name)
		recordAudit(g.audit, r, store.AuditGuardBlocked, "volumes:"+name, "denied", "protected stack volume mutation")
		writeError(w, http.StatusForbidden, "modifying a protected stack volume requires admin role")
		return
	}

	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	next.ServeHTTP(rec, r)
	if rec.status >= 200 && rec.status < 300 {
		if action, detail := volumeAuditAction(r.Method, r.URL.Path); action != "" {
			recordAudit(g.audit, r, action, "volumes:"+name, "success", detail)
		}
	}
}

// volumeNameForRequest extracts the target volume name: from the request body
// for create (POST /v1/volumes), otherwise from the path
// (/v1/volumes/{name}[/files...]).
func (g *ResourceGuard) volumeNameForRequest(r *http.Request) (string, error) {
	if r.URL.Path == "/v1/volumes" && r.Method == http.MethodPost {
		data, err := g.readCreateBody(r)
		if err != nil {
			return "", err
		}
		var body struct {
			Name string `json:"name"`
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, &body); err != nil {
				return "", err
			}
		}
		return body.Name, nil
	}
	// /v1/volumes/{name}[/files...]
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) >= 3 {
		return parts[2], nil
	}
	return "", nil
}

// isProtectedVolume resolves whether the volume (nodeID, name) belongs to the
// protected stack by back-querying the agent-manager for that node's volumes
// and reading the real stack label. Returns false when the back-query is
// unconfigured or the volume is absent (e.g. a fresh create) — a non-existent
// volume cannot be in the protected stack.
func (g *ResourceGuard) isProtectedVolume(ctx context.Context, nodeID, name string) (bool, error) {
	if g.agentMgrClient == nil || g.agentMgrBase == "" || g.stackName == "" {
		return false, nil
	}
	if nodeID == "" || name == "" {
		// Cannot resolve a specific target; the upstream rejects it anyway.
		return false, nil
	}

	u := g.agentMgrBase + "/v1/volumes?node_id=" + url.QueryEscape(nodeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}
	resp, err := g.agentMgrClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("agent-manager returned %d", resp.StatusCode)
	}

	var list struct {
		Volumes []struct {
			Name  string `json:"name"`
			Stack string `json:"stack"`
		} `json:"volumes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return false, err
	}
	for _, v := range list.Volumes {
		if v.Name == name {
			return v.Stack == g.stackName, nil
		}
	}
	return false, nil // not found → not protected
}

// volumeAuditAction maps a volume mutation to its audit action + detail.
func volumeAuditAction(method, path string) (store.AuditAction, string) {
	switch {
	case method == http.MethodPost && path == "/v1/volumes":
		return store.AuditVolumeCreated, "create volume"
	case method == http.MethodDelete && strings.HasSuffix(path, "/files"):
		return store.AuditVolumeFileDeleted, "delete file"
	case method == http.MethodPost && strings.HasSuffix(path, "/files/rename"):
		return store.AuditVolumeFileRenamed, "rename file"
	case method == http.MethodDelete:
		return store.AuditVolumeDeleted, "delete volume"
	}
	return "", ""
}

// statusRecorder captures the upstream response status so a mutation can be
// audited as success only when it actually succeeded.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status = http.StatusOK
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
