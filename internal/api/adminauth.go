// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"crypto/subtle"
	"net/http"

	"swarm-rbac-proxy/internal/store"
)

// RequireAdminOrToken authorizes the management plane (users / roles /
// bindings). It admits a request that either presents the admin bearer token OR
// is an mTLS-authenticated caller whose effective RBAC permissions confer full
// admin (store.UserIsAdmin). The bearer path preserves CLI/bootstrap/internal-
// listener access; the mTLS path is what lets an admin operate the management
// API from the TUI, which carries a client certificate but no bearer token.
//
// It must be wrapped *after* identity resolution (RequireClientCert on the
// external listener) so the user is present in the request context for the mTLS
// path. The admin predicate is the same one the lockout logic uses, so "who may
// manage" and "who counts as an admin" never diverge — and a later migration to
// a first-class `users` RBAC resource only changes this predicate, not the
// wire contract.
func RequireAdminOrToken(token string, rbac store.RBACStore, audit store.AuditStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bearer token path (constant-time compare, like RequireToken). Only
		// consulted when a token is configured.
		if token != "" {
			expected := []byte("Bearer " + token)
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), expected) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}

		// mTLS admin path: requires a resolved client identity.
		user, ok := r.Context().Value(ContextKeyUser).(*store.User)
		if !ok || user == nil {
			writeError(w, http.StatusUnauthorized, "admin token or client certificate required")
			return
		}
		isAdmin, err := store.UserIsAdmin(r.Context(), rbac, user.Username)
		if err != nil {
			l().Errorw("admin check failed", "error", err, "user", user.Username)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !isAdmin {
			l().Warnw("non-admin management request", "user", user.Username, "method", r.Method, "path", r.URL.Path)
			recordAudit(audit, r, store.AuditRBACDenied, "management:"+r.URL.Path, "denied", "admin role required")
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
