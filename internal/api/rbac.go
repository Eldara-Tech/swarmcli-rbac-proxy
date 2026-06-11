// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"net/http"

	"swarm-rbac-proxy/internal/store"
)

// RBACMiddleware enforces role-based access control on proxied Docker and
// agent-manager requests. It sits after RequireClientCert (which resolves the
// caller's identity) and before the protected-stack ExecGuard/ResourceGuard:
// RBAC decides whether the caller's role may touch the resource/verb at all;
// the stack guards remain the narrow, last line for the infra stack.
//
// Authorization is default-deny: a request that maps to no known resource, or
// for which the caller holds no granting rule, is rejected with 403.
type RBACMiddleware struct {
	rbac  store.RBACStore
	audit store.AuditStore
	// guard resolves the stack-namespace label of a request target so a
	// stack-labeled mutation can be authorized under the "stacks" resource. It
	// is the same *ResourceGuard used for protected-stack checks; it may be nil
	// (no label resolution → mutations judged by the concrete resource only).
	guard *ResourceGuard
}

// NewRBACMiddleware builds the middleware. guard supplies stack-label
// resolution (pass the process ResourceGuard); it may be nil.
func NewRBACMiddleware(rbac store.RBACStore, audit store.AuditStore, guard *ResourceGuard) *RBACMiddleware {
	return &RBACMiddleware{rbac: rbac, audit: audit, guard: guard}
}

// Wrap returns the enforcing middleware. If the store is nil the handler is
// returned unchanged (RBAC disabled).
func (m *RBACMiddleware) Wrap(next http.Handler) http.Handler {
	if m == nil || m.rbac == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The internal listener is trusted loopback and carries no identity.
		if isInternalListener(r) {
			next.ServeHTTP(w, r)
			return
		}

		user, ok := r.Context().Value(ContextKeyUser).(*store.User)
		if !ok || user == nil {
			// mTLS not configured or identity missing — fail closed.
			writeError(w, http.StatusForbidden, "client identity required")
			return
		}

		route := mapRequest(r.Method, r.URL.Path)

		candidates := []string{route.resource}
		if route.stackable && isMutatingVerb(route.verb) {
			labeled, err := m.isStackLabeled(r, route)
			if err != nil {
				l().Warnw("rbac: stack-label back-query failed, blocking", "error", err, "path", r.URL.Path)
				writeError(w, http.StatusServiceUnavailable, "cannot verify resource ownership")
				return
			}
			if labeled {
				candidates = append(candidates, store.ResourceStacks)
			}
		}

		perms, err := store.GetEffectivePermissions(r.Context(), m.rbac, user.Username)
		if err != nil {
			l().Errorw("rbac: permission resolution failed", "error", err, "user", user.Username)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !perms.Allows(candidates, route.verb) {
			l().Warnw("rbac: denied", "user", user.Username, "resource", route.resource, "verb", route.verb, "path", r.URL.Path)
			recordAudit(m.audit, r, store.AuditRBACDenied, route.resource+":"+route.verb, "denied",
				"role lacks "+route.verb+" on "+route.resource)
			writeError(w, http.StatusForbidden, "forbidden: "+route.verb+" on "+route.resource+" not permitted for your role")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isMutatingVerb(verb string) bool {
	return verb == store.VerbCreate || verb == store.VerbUpdate || verb == store.VerbDelete
}

// isStackLabeled reports whether the request's target carries a stack-namespace
// label (i.e. the operation is governed by the "stacks" resource in addition to
// the concrete resource). For create it inspects the request body; for
// update/delete it back-queries the resource's labels.
func (m *RBACMiddleware) isStackLabeled(r *http.Request, route rbacRoute) (bool, error) {
	if m.guard == nil {
		return false, nil
	}
	if route.verb == store.VerbCreate {
		data, err := m.guard.readCreateBody(r)
		if err != nil {
			return false, err
		}
		ns, err := stackLabelFromBody(data)
		return ns != "", err
	}
	if route.id == "" {
		return false, nil
	}
	ns, err := m.guard.resourceStackLabel(r.Context(), route.resource, route.id)
	return ns != "", err
}
