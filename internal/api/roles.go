// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"swarm-rbac-proxy/internal/store"
)

// RoleHandler serves the /api/v1/roles management endpoints. Like the user
// management API it is protected by the admin bearer token (RequireToken) at
// the route layer. It needs the UserStore as well, to run the last-admin
// lockout check when a role's rules change.
type RoleHandler struct {
	rbac  store.RBACStore
	users store.UserStore
	audit store.AuditStore
}

// NewRoleHandler creates a RoleHandler.
func NewRoleHandler(rbac store.RBACStore, users store.UserStore, audit store.AuditStore) *RoleHandler {
	return &RoleHandler{rbac: rbac, users: users, audit: audit}
}

type roleRequest struct {
	Name  string                 `json:"name"`
	Rules []store.PermissionRule `json:"rules"`
}

// List handles GET /api/v1/roles.
func (h *RoleHandler) List(w http.ResponseWriter, r *http.Request) {
	roles, err := h.rbac.ListRoles(r.Context())
	if err != nil {
		l().Errorw("list roles failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, roles)
}

// Get handles GET /api/v1/roles/{name}.
func (h *RoleHandler) Get(w http.ResponseWriter, r *http.Request) {
	role, err := h.rbac.GetRole(r.Context(), r.PathValue("name"))
	if err != nil {
		if errors.Is(err, store.ErrRoleNotFound) {
			writeError(w, http.StatusNotFound, "role not found")
			return
		}
		l().Errorw("get role failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, role)
}

// Create handles POST /api/v1/roles.
func (h *RoleHandler) Create(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeRoleRequest(w, r)
	if !ok {
		return
	}
	role := &store.Role{Name: req.Name, Rules: req.Rules}
	if err := h.rbac.CreateRole(r.Context(), role); err != nil {
		switch {
		case errors.Is(err, store.ErrRoleNameRequired):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrRoleExists):
			writeError(w, http.StatusConflict, err.Error())
		default:
			l().Errorw("create role failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	recordAudit(h.audit, r, store.AuditRoleCreated, "role:"+role.Name, "success", "")
	writeJSON(w, http.StatusCreated, role)
}

// Update handles PUT /api/v1/roles/{name} (replaces the rule set).
func (h *RoleHandler) Update(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	req, ok := decodeRoleRequest(w, r)
	if !ok {
		return
	}
	role := &store.Role{Name: name, Rules: req.Rules}
	if err := store.UpdateRoleChecked(r.Context(), h.users, h.rbac, role); err != nil {
		switch {
		case errors.Is(err, store.ErrRoleNotFound):
			writeError(w, http.StatusNotFound, "role not found")
		case errors.Is(err, store.ErrLastAdmin):
			writeError(w, http.StatusConflict, "refusing update: would remove the last admin")
		default:
			l().Errorw("update role failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	recordAudit(h.audit, r, store.AuditRoleUpdated, "role:"+name, "success", "")
	writeJSON(w, http.StatusOK, role)
}

// Delete handles DELETE /api/v1/roles/{name}.
func (h *RoleHandler) Delete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := h.rbac.DeleteRole(r.Context(), name); err != nil {
		switch {
		case errors.Is(err, store.ErrRoleNotFound):
			writeError(w, http.StatusNotFound, "role not found")
		case errors.Is(err, store.ErrRoleBuiltin):
			writeError(w, http.StatusConflict, "builtin role cannot be deleted")
		case errors.Is(err, store.ErrRoleInUse):
			writeError(w, http.StatusConflict, "role is referenced by a binding")
		default:
			l().Errorw("delete role failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	recordAudit(h.audit, r, store.AuditRoleDeleted, "role:"+name, "success", "")
	w.WriteHeader(http.StatusNoContent)
}

func decodeRoleRequest(w http.ResponseWriter, r *http.Request) (roleRequest, bool) {
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, http.StatusBadRequest, "Content-Type must be application/json")
		return roleRequest{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 64 KB
	var req roleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return roleRequest{}, false
	}
	return req, true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		l().Errorw("encode response failed", "error", err)
	}
}
