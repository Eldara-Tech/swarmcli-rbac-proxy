// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
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

const testExternalURL = "tcp://proxy.example:2376"

// newSeededStore returns a MemoryStore with the built-in roles seeded — the
// same precondition main.go establishes at startup (CreateUserWithBinding needs
// the target role to exist).
func newSeededStore(t *testing.T) *store.MemoryStore {
	t.Helper()
	s := store.NewMemoryStore()
	if err := store.SeedDefaultRoles(context.Background(), s); err != nil {
		t.Fatalf("seed roles: %v", err)
	}
	return s
}

// newTestHandler returns a UserHandler over a freshly seeded store (used for
// both user and RBAC persistence), plus that store for assertions.
func newTestHandler(t *testing.T) (*UserHandler, *store.MemoryStore) {
	t.Helper()
	s := newSeededStore(t)
	return NewUserHandler(s, s, nil, testExternalURL), s
}

// testMux wires the handler to a mux so {username} path values resolve.
func testMux(h *UserHandler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/api/v1/users", h)
	mux.HandleFunc("POST /api/v1/users/{username}/regenerate-token", h.RegenerateToken)
	mux.HandleFunc("PATCH /api/v1/users/{username}", h.Update)
	mux.HandleFunc("DELETE /api/v1/users/{username}", h.Delete)
	return mux
}

// asUser injects an authenticated mTLS identity into the request context, so
// the handler's self-action guards (actorFromRequest) see a caller.
func asUser(req *http.Request, username string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), ContextKeyUser, &store.User{Username: username}))
}

func seedAdmin(t *testing.T, s *store.MemoryStore, name string) {
	t.Helper()
	if _, err := store.CreateUserWithBinding(context.Background(), s, s, name, store.RoleAdmin); err != nil {
		t.Fatalf("seed admin %s: %v", name, err)
	}
}

func postJSON(mux http.Handler, path, body string, actor string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if actor != "" {
		req = asUser(req, actor)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

type createResp struct {
	User         *store.User `json:"user"`
	OnboardToken string      `json:"onboard_token"`
	OnboardURL   string      `json:"onboard_url"`
}

func userBindings(t *testing.T, s *store.MemoryStore, username string) []string {
	t.Helper()
	bs, err := s.ListBindingsForUser(context.Background(), username)
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	roles := make([]string, 0, len(bs))
	for _, b := range bs {
		roles = append(roles, b.RoleName)
	}
	return roles
}

// --- create ---

func TestCreateUser_DefaultRoleOperator(t *testing.T) {
	h, s := newTestHandler(t)

	w := postJSON(testMux(h), "/api/v1/users", `{"username":"alice"}`, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %s)", w.Code, w.Body)
	}
	var resp createResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.User == nil || resp.User.Username != "alice" {
		t.Fatalf("user = %+v, want alice", resp.User)
	}
	if !resp.User.Enabled {
		t.Error("expected enabled true")
	}
	if resp.User.Role != store.RoleOperator {
		t.Errorf("role = %q, want operator (default)", resp.User.Role)
	}
	if len(resp.OnboardToken) != 64 {
		t.Errorf("onboard_token len = %d, want 64 hex chars", len(resp.OnboardToken))
	}
	if !strings.HasPrefix(resp.OnboardURL, "https://proxy.example:2376/api/v1/onboard/") {
		t.Errorf("onboard_url = %q, want https onboard URL", resp.OnboardURL)
	}
	if got := userBindings(t, s, "alice"); len(got) != 1 || got[0] != store.RoleOperator {
		t.Errorf("bindings = %v, want [operator]", got)
	}
}

func TestCreateUser_AdminRoleBinds(t *testing.T) {
	h, s := newTestHandler(t)
	w := postJSON(testMux(h), "/api/v1/users", `{"username":"root","role":"admin"}`, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	if got := userBindings(t, s, "root"); len(got) != 1 || got[0] != store.RoleAdmin {
		t.Errorf("bindings = %v, want [admin]", got)
	}
	isAdmin, err := store.UserIsAdmin(context.Background(), s, "root")
	if err != nil || !isAdmin {
		t.Errorf("UserIsAdmin = %v, %v; want true", isAdmin, err)
	}
}

func TestCreateUser_InvalidRole(t *testing.T) {
	h, _ := newTestHandler(t)
	w := postJSON(testMux(h), "/api/v1/users", `{"username":"x","role":"superuser"}`, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestCreateUser_Duplicate(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := testMux(h)
	for i, want := range []int{http.StatusCreated, http.StatusConflict} {
		w := postJSON(mux, "/api/v1/users", `{"username":"bob"}`, "")
		if w.Code != want {
			t.Fatalf("request %d: status = %d, want %d", i, w.Code, want)
		}
	}
}

func TestCreateUser_MissingUsername(t *testing.T) {
	h, _ := newTestHandler(t)
	w := postJSON(testMux(h), "/api/v1/users", `{"username":""}`, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestCreateUser_BadJSONAndContentType(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := testMux(h)

	w := postJSON(mux, "/api/v1/users", "{invalid", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad json: status = %d, want 400", w.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"x"}`))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("wrong content-type: status = %d, want 400", rec.Code)
	}
}

// --- list ---

func TestListUsers(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := testMux(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("empty list: status %d body %q", w.Code, w.Body.String())
	}

	postJSON(mux, "/api/v1/users", `{"username":"carol"}`, "")
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var users []store.User
	if err := json.NewDecoder(w.Body).Decode(&users); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(users) != 1 || users[0].Username != "carol" {
		t.Fatalf("users = %+v, want [carol]", users)
	}
}

// --- regenerate token ---

func TestRegenerateToken(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := testMux(h)

	first := postJSON(mux, "/api/v1/users", `{"username":"dave"}`, "")
	var created createResp
	_ = json.NewDecoder(first.Body).Decode(&created)

	w := postJSON(mux, "/api/v1/users/dave/regenerate-token", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp createResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.OnboardToken) != 64 || resp.OnboardToken == created.OnboardToken {
		t.Errorf("expected a fresh 64-char token, got %q (was %q)", resp.OnboardToken, created.OnboardToken)
	}
	if !strings.Contains(resp.OnboardURL, "/api/v1/onboard/") {
		t.Errorf("onboard_url = %q", resp.OnboardURL)
	}
}

func TestRegenerateToken_NotFound(t *testing.T) {
	h, _ := newTestHandler(t)
	w := postJSON(testMux(h), "/api/v1/users/ghost/regenerate-token", "", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// --- delete ---

func deleteAs(mux http.Handler, username, actor string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+username, nil)
	if actor != "" {
		req = asUser(req, actor)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestDeleteUser_CascadesBindings(t *testing.T) {
	h, s := newTestHandler(t)
	mux := testMux(h)
	seedAdmin(t, s, "admin") // keeps an admin so lockout never trips
	postJSON(mux, "/api/v1/users", `{"username":"erin"}`, "")

	w := deleteAs(mux, "erin", "admin")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body %s)", w.Code, w.Body)
	}
	if got := userBindings(t, s, "erin"); len(got) != 0 {
		t.Errorf("bindings after delete = %v, want none (cascaded)", got)
	}
}

func TestDeleteUser_Self(t *testing.T) {
	h, s := newTestHandler(t)
	mux := testMux(h)
	seedAdmin(t, s, "admin")

	w := deleteAs(mux, "admin", "admin")
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (self-delete)", w.Code)
	}
}

func TestDeleteUser_LastAdmin(t *testing.T) {
	h, s := newTestHandler(t)
	mux := testMux(h)
	seedAdmin(t, s, "onlyadmin")

	// A different admin actor deletes the only admin → last-admin lockout.
	w := deleteAs(mux, "onlyadmin", "someoneelse")
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (last admin)", w.Code)
	}
}

func TestDeleteUser_NotFound(t *testing.T) {
	h, s := newTestHandler(t)
	seedAdmin(t, s, "admin")
	w := deleteAs(testMux(h), "nobody", "admin")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// --- update: enable/disable ---

func patchAs(mux http.Handler, username, body, actor string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/users/"+username, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if actor != "" {
		req = asUser(req, actor)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestUpdate_DisableThenEnable(t *testing.T) {
	h, s := newTestHandler(t)
	mux := testMux(h)
	seedAdmin(t, s, "admin")
	postJSON(mux, "/api/v1/users", `{"username":"frank"}`, "")

	w := patchAs(mux, "frank", `{"enabled":false}`, "admin")
	if w.Code != http.StatusOK {
		t.Fatalf("disable: status = %d, want 200 (body %s)", w.Code, w.Body)
	}
	u, _ := s.GetUserByUsername(context.Background(), "frank")
	if u.Enabled {
		t.Error("expected frank disabled")
	}

	w = patchAs(mux, "frank", `{"enabled":true}`, "admin")
	if w.Code != http.StatusOK {
		t.Fatalf("enable: status = %d, want 200", w.Code)
	}
	u, _ = s.GetUserByUsername(context.Background(), "frank")
	if !u.Enabled {
		t.Error("expected frank enabled")
	}
}

func TestUpdate_SelfDisable(t *testing.T) {
	h, s := newTestHandler(t)
	mux := testMux(h)
	seedAdmin(t, s, "admin")
	w := patchAs(mux, "admin", `{"enabled":false}`, "admin")
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (self-disable)", w.Code)
	}
}

func TestUpdate_LastAdminDisable(t *testing.T) {
	h, s := newTestHandler(t)
	mux := testMux(h)
	seedAdmin(t, s, "onlyadmin")
	w := patchAs(mux, "onlyadmin", `{"enabled":false}`, "someoneelse")
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (last admin disable)", w.Code)
	}
}

// --- update: role change ---

func TestUpdate_RoleChange(t *testing.T) {
	h, s := newTestHandler(t)
	mux := testMux(h)
	seedAdmin(t, s, "admin")
	postJSON(mux, "/api/v1/users", `{"username":"grace","role":"operator"}`, "")

	w := patchAs(mux, "grace", `{"role":"viewer"}`, "admin")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body)
	}
	u, _ := s.GetUserByUsername(context.Background(), "grace")
	if u.Role != store.RoleViewer {
		t.Errorf("User.Role = %q, want viewer", u.Role)
	}
	if got := userBindings(t, s, "grace"); len(got) != 1 || got[0] != store.RoleViewer {
		t.Errorf("bindings = %v, want [viewer] (replaced)", got)
	}
}

func TestUpdate_RoleChange_InvalidRole(t *testing.T) {
	h, s := newTestHandler(t)
	mux := testMux(h)
	seedAdmin(t, s, "admin")
	postJSON(mux, "/api/v1/users", `{"username":"heidi"}`, "")
	w := patchAs(mux, "heidi", `{"role":"wizard"}`, "admin")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (unknown role)", w.Code)
	}
}

func TestUpdate_SelfRoleChange(t *testing.T) {
	h, s := newTestHandler(t)
	mux := testMux(h)
	seedAdmin(t, s, "admin")
	w := patchAs(mux, "admin", `{"role":"operator"}`, "admin")
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (self role change)", w.Code)
	}
}

func TestUpdate_LastAdminDemote(t *testing.T) {
	h, s := newTestHandler(t)
	mux := testMux(h)
	seedAdmin(t, s, "onlyadmin")
	w := patchAs(mux, "onlyadmin", `{"role":"operator"}`, "someoneelse")
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (last admin demote)", w.Code)
	}
}

func TestUpdate_NothingToUpdate(t *testing.T) {
	h, s := newTestHandler(t)
	mux := testMux(h)
	seedAdmin(t, s, "admin")
	postJSON(mux, "/api/v1/users", `{"username":"ivan"}`, "")
	w := patchAs(mux, "ivan", `{}`, "admin")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (empty patch)", w.Code)
	}
}

// --- audit ---

func TestAudit_CreateAndDelete(t *testing.T) {
	s := newSeededStore(t)
	h := NewUserHandler(s, s, s, testExternalURL)
	mux := testMux(h)
	seedAdmin(t, s, "admin")

	postJSON(mux, "/api/v1/users", `{"username":"judy"}`, "admin")
	deleteAs(mux, "judy", "admin")

	entries, err := s.ListAuditEntries(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	var created, deleted bool
	for _, e := range entries {
		if e.Action == store.AuditUserCreated && e.Resource == "user:judy" {
			created = true
			if e.Detail != "role:operator" {
				t.Errorf("create detail = %q, want role:operator", e.Detail)
			}
		}
		if e.Action == store.AuditUserDeleted && e.Resource == "user:judy" && e.Status == "success" {
			deleted = true
		}
	}
	if !created || !deleted {
		t.Errorf("expected create+delete audit entries; created=%v deleted=%v", created, deleted)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h, _ := newTestHandler(t)
	for _, method := range []string{http.MethodPut, http.MethodHead} {
		req := httptest.NewRequest(method, "/api/v1/users", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", method, w.Code)
		}
	}
}
