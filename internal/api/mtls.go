// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
	"crypto/x509"
	"net/http"

	"swarm-rbac-proxy/internal/store"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

// ContextKeyUser is the context key for the authenticated *store.User.
const ContextKeyUser contextKey = "authn.user"

// ContextKeyInternal is set to true on requests arriving on the internal
// (plain TCP) listener. Guards check this key instead of the absence of a
// user to avoid treating auth-bypass failures as internal requests.
const ContextKeyInternal contextKey = "internal.request"

// MarkInternalRequest is middleware that stamps requests with the internal
// listener context flag. Apply it exclusively on the internal listener mux.
func MarkInternalRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ContextKeyInternal, true)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireClientCert returns middleware that extracts a username from the
// TLS client certificate, looks it up in the store, and rejects the
// request if the user is not found or not enabled.
//
// If s is nil, the handler is returned unchanged (no auth).
func RequireClientCert(s store.UserStore, next http.Handler) http.Handler {
	if s == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			l().Warnw("no client certificate presented")
			writeError(w, http.StatusUnauthorized, "client certificate required")
			return
		}

		cert := r.TLS.PeerCertificates[0]
		username := extractIdentity(cert)
		if username == "" {
			l().Warnw("certificate has no usable identity")
			writeError(w, http.StatusUnauthorized, "certificate has no usable identity")
			return
		}

		user, err := s.GetUserByUsername(r.Context(), username)
		if err != nil {
			l().Warnw("user lookup failed", "username", username, "error", err)
			writeError(w, http.StatusForbidden, "unknown user")
			return
		}
		if !user.Enabled {
			l().Warnw("disabled user", "username", username)
			writeError(w, http.StatusForbidden, "user disabled")
			return
		}

		l().Debugw("authenticated", "username", username, "user_id", user.ID)
		ctx := context.WithValue(r.Context(), ContextKeyUser, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractIdentity returns a username from the certificate.
// Preference: SAN email (if present), then Subject CN.
func extractIdentity(cert *x509.Certificate) string {
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}
	return cert.Subject.CommonName
}
