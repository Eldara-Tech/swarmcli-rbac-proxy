package api

import (
	"encoding/json"
	"errors"
	"net/http"

	proxylog "swarm-rbac-proxy/internal/log"
	"swarm-rbac-proxy/internal/store"
)

func l() *proxylog.ProxyLogger { return proxylog.L().With("component", "api") }

// UserHandler handles /api/v1/users requests.
type UserHandler struct {
	store store.UserStore
}

// NewUserHandler creates a handler backed by the given store.
func NewUserHandler(s store.UserStore) *UserHandler {
	return &UserHandler{store: s}
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
	ct := r.Header.Get("Content-Type")
	if ct != "application/json" {
		l().Warnw("bad content-type", "content_type", ct)
		writeError(w, http.StatusBadRequest, "Content-Type must be application/json")
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		l().Warnw("invalid JSON body", "error", err)
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	u := &store.User{Username: req.Username}
	if err := h.store.CreateUser(r.Context(), u); err != nil {
		switch {
		case errors.Is(err, store.ErrUsernameRequired):
			l().Warnw("missing username")
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrUsernameExists):
			l().Warnw("duplicate username", "username", req.Username)
			writeError(w, http.StatusConflict, err.Error())
		default:
			l().Errorw("store create failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	l().Infow("user created", "id", u.ID, "username", u.Username)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(u); err != nil {
		l().Errorw("encode response failed", "error", err)
	}
}

func (h *UserHandler) list(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		l().Errorw("store list failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(users); err != nil {
		l().Errorw("encode response failed", "error", err)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		l().Errorw("encode error response failed", "error", err)
	}
}
