// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"swarm-rbac-proxy/internal/store"
)

// BindingHandler serves the /api/v1/bindings management endpoints, admin-token
// protected at the route layer. It needs the UserStore both to validate the
// bound user exists and to run the last-admin lockout check on deletion.
type BindingHandler struct {
	rbac  store.RBACStore
	users store.UserStore
	audit store.AuditStore
}

// NewBindingHandler creates a BindingHandler.
func NewBindingHandler(rbac store.RBACStore, users store.UserStore, audit store.AuditStore) *BindingHandler {
	return &BindingHandler{rbac: rbac, users: users, audit: audit}
}

// List handles GET /api/v1/bindings.
func (h *BindingHandler) List(w http.ResponseWriter, r *http.Request) {
	bindings, err := h.rbac.ListBindings(r.Context())
	if err != nil {
		l().Errorw("list bindings failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, bindings)
}

// Create handles POST /api/v1/bindings.
func (h *BindingHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, http.StatusBadRequest, "Content-Type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)
	var req struct {
		Username string `json:"username"`
		RoleName string `json:"role_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Username == "" || req.RoleName == "" {
		writeError(w, http.StatusBadRequest, "username and role_name are required")
		return
	}
	// Validate the user exists for a clearer error than a dangling binding.
	if _, err := h.users.GetUserByUsername(r.Context(), req.Username); err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeError(w, http.StatusBadRequest, "user not found")
			return
		}
		l().Errorw("user lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	b := &store.RoleBinding{Username: req.Username, RoleName: req.RoleName}
	if err := h.rbac.CreateBinding(r.Context(), b); err != nil {
		switch {
		case errors.Is(err, store.ErrRoleNotFound):
			writeError(w, http.StatusBadRequest, "role not found")
		case errors.Is(err, store.ErrBindingExists):
			writeError(w, http.StatusConflict, "binding already exists")
		default:
			l().Errorw("create binding failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	recordAudit(h.audit, r, store.AuditBindingCreated, "binding:"+b.Username+"/"+b.RoleName, "success", "")
	writeJSON(w, http.StatusCreated, b)
}

// Delete handles DELETE /api/v1/bindings/{id}.
func (h *BindingHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := store.DeleteBindingChecked(r.Context(), h.users, h.rbac, id); err != nil {
		switch {
		case errors.Is(err, store.ErrBindingNotFound):
			writeError(w, http.StatusNotFound, "binding not found")
		case errors.Is(err, store.ErrLastAdmin):
			writeError(w, http.StatusConflict, "refusing delete: would remove the last admin")
		default:
			l().Errorw("delete binding failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	recordAudit(h.audit, r, store.AuditBindingDeleted, "binding:"+id, "success", "")
	w.WriteHeader(http.StatusNoContent)
}
