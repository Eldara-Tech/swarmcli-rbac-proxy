package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	proxylog "swarm-rbac-proxy/internal/log"
	"swarm-rbac-proxy/internal/store"
)

func TestMain(m *testing.M) {
	proxylog.InitTestIfTestLogEnv()
	defer proxylog.Sync()
	os.Exit(m.Run())
}

func newTestHandler() *UserHandler {
	return NewUserHandler(store.NewMemoryStore())
}

func TestCreateUser(t *testing.T) {
	h := newTestHandler()

	body := `{"username":"alice"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	var u store.User
	if err := json.NewDecoder(w.Body).Decode(&u); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if u.Username != "alice" {
		t.Errorf("username = %q, want %q", u.Username, "alice")
	}
	if u.ID == "" {
		t.Error("expected ID to be set")
	}
	if !u.Enabled {
		t.Error("expected enabled to be true")
	}
}

func TestCreateUser_DuplicateUsername(t *testing.T) {
	h := newTestHandler()

	for i, wantCode := range []int{http.StatusCreated, http.StatusConflict} {
		body := `{"username":"bob"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != wantCode {
			t.Fatalf("request %d: status = %d, want %d", i, w.Code, wantCode)
		}
	}
}

func TestCreateUser_MissingUsername(t *testing.T) {
	h := newTestHandler()

	body := `{"username":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateUser_BadJSON(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateUser_WrongContentType(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"x"}`))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestListUsers_Empty(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	body := strings.TrimSpace(w.Body.String())
	if body != "[]" {
		t.Errorf("body = %q, want %q", body, "[]")
	}
}

func TestListUsers_AfterCreate(t *testing.T) {
	h := newTestHandler()

	// Create a user first.
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"carol"}`))
	createReq.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), createReq)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var users []store.User
	if err := json.NewDecoder(w.Body).Decode(&users); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("got %d users, want 1", len(users))
	}
	if users[0].Username != "carol" {
		t.Errorf("username = %q, want %q", users[0].Username, "carol")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := newTestHandler()

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/v1/users", nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want %d", method, w.Code, http.StatusMethodNotAllowed)
		}
	}
}
