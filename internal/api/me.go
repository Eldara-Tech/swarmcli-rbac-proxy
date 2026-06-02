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
// RequireClientCert middleware. It lets a client (e.g. the CLI) learn its own
// role without attempting a mutating operation and reading a 403. It carries no
// state and never touches the store — the user is already resolved in context.
type MeHandler struct{}

// NewMeHandler creates a MeHandler.
func NewMeHandler() *MeHandler { return &MeHandler{} }

type meResponse struct {
	Username string `json:"username"`
	Role     string `json:"role"`
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
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(meResponse{Username: user.Username, Role: user.Role}); err != nil {
		l().Errorw("encode response failed", "error", err)
	}
}
