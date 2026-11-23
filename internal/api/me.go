// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"encoding/json"
	"net/http"

	"swarm-rbac-proxy/internal/store"
)

// MeHandler handles GET /api/v1/me: it returns the authenticated caller's own
// identity and role, derived from their mTLS client certificate by the
// RequireClientCert middleware, plus the effective RBAC rules — the flattened
// union of their bound roles' rules, as RBACMiddleware evaluates them. It lets a
// client (e.g. the CLI) learn what it may do without attempting an operation and
// reading a 403.
type MeHandler struct {
	rbac store.RBACStore
}

// NewMeHandler creates a MeHandler that resolves rules from rbac.
func NewMeHandler(rbac store.RBACStore) *MeHandler { return &MeHandler{rbac: rbac} }

type meResponse struct {
	Username string                 `json:"username"`
	Role     string                 `json:"role"`
	Rules    []store.PermissionRule `json:"rules"`
}

func (h *MeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	user, ok := r.Context().Value(ContextKeyUser).(*store.User)
	if !ok || user == nil {
		// No user context: either the internal listener (no mTLS identity) or
		// an unauthenticated external request. Identity is required.
		writeError(w, http.StatusUnauthorized, "client certificate required")
		return
	}
	perms, err := store.GetEffectivePermissions(r.Context(), h.rbac, user.Username)
	if err != nil {
		l().Errorw("me: permission resolution failed", "error", err, "user", user.Username)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	rules := perms.Rules
	if rules == nil {
		rules = []store.PermissionRule{} // encode as [], never null
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(meResponse{Username: user.Username, Role: user.Role, Rules: rules}); err != nil {
		l().Errorw("encode response failed", "error", err)
	}
}
