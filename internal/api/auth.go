package api

import (
	"crypto/subtle"
	"net/http"
)

// RequireToken returns middleware that validates a Bearer token.
// If token is empty, the handler is returned unchanged (no auth).
func RequireToken(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	expected := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), expected) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}
