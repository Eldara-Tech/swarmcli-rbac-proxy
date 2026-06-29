// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"

	proxylog "swarm-rbac-proxy/internal/log"
	"swarm-rbac-proxy/internal/store"
)

func l() *proxylog.ProxyLogger { return proxylog.L().With("component", "api") }

// UserHandler handles /api/v1/users requests. It owns both the user store and
// the RBAC store because user lifecycle and role bindings are managed together
// (create binds a role; delete cascades bindings; role change re-binds) — see
// the store-level *Checked helpers that keep the two in sync and enforce the
// last-admin lockout.
type UserHandler struct {
	store       store.UserStore
	rbac        store.RBACStore
	audit       store.AuditStore
	externalURL string
}

// NewUserHandler creates a handler backed by the given stores. externalURL is
// the public proxy origin used to build onboarding URLs (PROXY_EXTERNAL_URL).
func NewUserHandler(s store.UserStore, rbac store.RBACStore, audit store.AuditStore, externalURL string) *UserHandler {
	return &UserHandler{store: s, rbac: rbac, audit: audit, externalURL: externalURL}
}

func (h *UserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.list(w, r)
	case http.MethodPost:
		h.create(w, r)
	default:
		l().Warnw("method not allowed", "method", r.Method)
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *UserHandler) create(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, http.StatusBadRequest, "Content-Type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10) // 10 KB

	var req struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !validUsername(req.Username) {
		writeError(w, http.StatusBadRequest, "username must be 1-64 characters: letters, digits, '.', '_' or '-'")
		return
	}
	role, ok := normalizeCreateRole(req.Role)
	if !ok {
		writeError(w, http.StatusBadRequest, "role must be one of: admin, operator, viewer")
		return
	}

	u, err := store.CreateUserWithBinding(r.Context(), h.store, h.rbac, req.Username, role)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrUsernameRequired):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrUsernameExists):
			writeError(w, http.StatusConflict, err.Error())
		default:
			l().Errorw("store create failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	// Audit creation before issuing the token: the user already exists, so the
	// record must not be lost if token issuance then fails.
	l().Infow("user created", "id", u.ID, "username", u.Username, "role", u.Role)
	recordAudit(h.audit, r, store.AuditUserCreated, "user:"+u.Username, "success", "role:"+u.Role)

	token, err := h.issueToken(r, u.Username)
	if err != nil {
		// The user exists (and is audited above) but has no usable token; surface
		// the failure so the caller can retry (regenerate-token) rather than
		// silently stranding it.
		l().Errorw("set onboard token failed", "error", err, "username", u.Username)
		writeError(w, http.StatusInternalServerError, "user created but onboard token failed; regenerate it")
		return
	}

	writeJSON(w, http.StatusCreated, onboardResponse{User: u, OnboardToken: token, OnboardURL: h.onboardURL(token)})
}

func (h *UserHandler) list(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		l().Errorw("store list failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

// Delete handles DELETE /api/v1/users/{username}. It refuses to delete the
// caller themselves (the issue's restriction) and the last admin, and cascades
// the user's role bindings (via store.DeleteUserChecked).
func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	if actorFromRequest(r) == username {
		recordAudit(h.audit, r, store.AuditUserDeleted, "user:"+username, "denied", "self-delete")
		writeError(w, http.StatusConflict, "you cannot delete yourself")
		return
	}
	if err := store.DeleteUserChecked(r.Context(), h.store, h.rbac, username); err != nil {
		switch {
		case errors.Is(err, store.ErrUserNotFound):
			writeError(w, http.StatusNotFound, "user not found")
		case errors.Is(err, store.ErrLastAdmin):
			recordAudit(h.audit, r, store.AuditUserDeleted, "user:"+username, "denied", "last admin")
			writeError(w, http.StatusConflict, "refusing delete: would remove the last admin")
		default:
			l().Errorw("store delete failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	l().Infow("user deleted", "username", username)
	recordAudit(h.audit, r, store.AuditUserDeleted, "user:"+username, "success", "")
	w.WriteHeader(http.StatusNoContent)
}

// RegenerateToken handles POST /api/v1/users/{username}/regenerate-token: it
// issues a fresh one-time onboard token (invalidating the previous one) and
// returns it plus the onboard URL.
func (h *UserHandler) RegenerateToken(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	if _, err := h.store.GetUserByUsername(r.Context(), username); err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		l().Errorw("user lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	token, err := h.issueToken(r, username)
	if err != nil {
		l().Errorw("set onboard token failed", "error", err, "username", username)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	l().Infow("onboard token regenerated", "username", username)
	recordAudit(h.audit, r, store.AuditTokenRegenerated, "user:"+username, "success", "")
	writeJSON(w, http.StatusOK, onboardResponse{OnboardToken: token, OnboardURL: h.onboardURL(token)})
}

// Update handles PATCH /api/v1/users/{username}: enable/disable and/or role
// change. Both guard against locking the caller out (no self-disable, no
// self-role-change) and against removing the last admin.
func (h *UserHandler) Update(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, http.StatusBadRequest, "Content-Type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)
	var req struct {
		Enabled *bool   `json:"enabled,omitempty"`
		Role    *string `json:"role,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Enabled == nil && req.Role == nil {
		writeError(w, http.StatusBadRequest, "nothing to update: provide 'enabled' and/or 'role'")
		return
	}
	// Validate the role against the built-ins here, like create does, so the
	// management API cannot set User.Role to an arbitrary string that the
	// protected-stack admin gate (User.Role == "admin") would then misread.
	if req.Role != nil && !isBuiltinRole(*req.Role) {
		writeError(w, http.StatusBadRequest, "role must be one of: admin, operator, viewer")
		return
	}
	self := actorFromRequest(r) == username

	// Role change first so a combined enable+role request lands the role even if
	// the (independent) enable toggle is a no-op.
	if req.Role != nil {
		if self {
			writeError(w, http.StatusConflict, "you cannot change your own role")
			return
		}
		if err := store.SetUserRoleChecked(r.Context(), h.store, h.rbac, username, *req.Role); err != nil {
			h.writeUpdateErr(w, r, username, err)
			return
		}
		recordAudit(h.audit, r, store.AuditUserUpdated, "user:"+username, "success", "role:"+*req.Role)
	}
	if req.Enabled != nil {
		if self && !*req.Enabled {
			writeError(w, http.StatusConflict, "you cannot disable yourself")
			return
		}
		if err := store.SetUserEnabledChecked(r.Context(), h.store, h.rbac, username, *req.Enabled); err != nil {
			h.writeUpdateErr(w, r, username, err)
			return
		}
		state := "disabled"
		if *req.Enabled {
			state = "enabled"
		}
		recordAudit(h.audit, r, store.AuditUserUpdated, "user:"+username, "success", state)
	}

	u, err := h.store.GetUserByUsername(r.Context(), username)
	if err != nil {
		l().Errorw("post-update lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// writeUpdateErr maps a store error from an update to an HTTP response.
func (h *UserHandler) writeUpdateErr(w http.ResponseWriter, r *http.Request, username string, err error) {
	switch {
	case errors.Is(err, store.ErrUserNotFound):
		writeError(w, http.StatusNotFound, "user not found")
	case errors.Is(err, store.ErrRoleNotFound):
		writeError(w, http.StatusBadRequest, "role not found")
	case errors.Is(err, store.ErrLastAdmin):
		recordAudit(h.audit, r, store.AuditUserUpdated, "user:"+username, "denied", "last admin")
		writeError(w, http.StatusConflict, "refusing change: would remove the last admin")
	default:
		l().Errorw("user update failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// issueToken generates a fresh one-time onboard token and persists it.
func (h *UserHandler) issueToken(r *http.Request, username string) (string, error) {
	token, err := generateOnboardToken()
	if err != nil {
		return "", err
	}
	if err := h.store.SetOnboardToken(r.Context(), username, token); err != nil {
		return "", err
	}
	return token, nil
}

// onboardURL builds the public onboarding URL for a token, or "" when no
// external URL is configured (the caller then shows the bare token).
func (h *UserHandler) onboardURL(token string) string {
	if h.externalURL == "" {
		return ""
	}
	base := h.externalURL
	if after, ok := strings.CutPrefix(base, "tcp://"); ok {
		base = "https://" + after
	}
	return strings.TrimSuffix(base, "/") + "/api/v1/onboard/" + token
}

// onboardResponse is the body for create and regenerate-token: the user (omitted
// for regenerate) plus the one-time token and its ready-to-use onboard URL. The
// private key is never here — it is generated on the user's machine when they
// redeem the token at GET /api/v1/onboard/{token}.
type onboardResponse struct {
	User         *store.User `json:"user,omitempty"`
	OnboardToken string      `json:"onboard_token"`
	OnboardURL   string      `json:"onboard_url,omitempty"`
}

// isBuiltinRole reports whether role is exactly one of the three assignable
// built-in roles (no empty-string defaulting, unlike normalizeCreateRole).
func isBuiltinRole(role string) bool {
	switch role {
	case store.RoleAdmin, store.RoleOperator, store.RoleViewer:
		return true
	default:
		return false
	}
}

// normalizeCreateRole validates the requested role for user creation. An empty
// role defaults to operator (a sensible non-privileged default); otherwise it
// must be one of the built-in role names.
func normalizeCreateRole(role string) (string, bool) {
	if role == "" {
		return store.RoleOperator, true
	}
	if isBuiltinRole(role) {
		return role, true
	}
	return "", false
}

// usernameRe constrains create usernames: 1-64 chars, starting alphanumeric,
// then letters/digits/'.'/'_'/'-'. The username becomes the client cert CN and
// appears in onboard URLs and audit records, so it is held to a conservative
// shell/URL/log-safe charset.
var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func validUsername(s string) bool { return usernameRe.MatchString(s) }

func generateOnboardToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// actorFromRequest extracts the actor name from the request context.
func actorFromRequest(r *http.Request) string {
	if u, ok := r.Context().Value(ContextKeyUser).(*store.User); ok && u != nil {
		return u.Username
	}
	return "anonymous"
}

// sourceIP extracts the client IP from the request.
func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// recordAudit writes an audit entry if the store is non-nil. Errors are
// logged but never propagated — audit failures must not block requests.
func recordAudit(audit store.AuditStore, r *http.Request, action store.AuditAction, resource, status, detail string) {
	if audit == nil {
		return
	}
	if err := audit.RecordAudit(r.Context(), &store.AuditEntry{
		Actor:    actorFromRequest(r),
		Action:   action,
		Resource: resource,
		Status:   status,
		Detail:   detail,
		SourceIP: sourceIP(r),
	}); err != nil {
		l().Errorw("audit record failed", "error", err, "action", action)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]string{"message": msg}); err != nil {
		l().Errorw("encode error response failed", "error", err)
	}
}
