package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"swarm-rbac-proxy/internal/store"
)

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
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *UserHandler) create(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	if ct != "application/json" {
		writeError(w, http.StatusBadRequest, "Content-Type must be application/json")
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	u := &store.User{Username: req.Username}
	if err := h.store.CreateUser(r.Context(), u); err != nil {
		switch {
		case errors.Is(err, store.ErrUsernameRequired):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrUsernameExists):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(u)
}

func (h *UserHandler) list(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
