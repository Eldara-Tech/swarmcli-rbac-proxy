// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"swarm-rbac-proxy/internal/store"
)

// newRBACEnv returns a middleware backed by a memory store seeded with the
// built-in roles and a bound user per role (v=viewer, o=operator, a=admin).
// The guard has no Docker socket, so stack-label detection for create works via
// the request body, while update/delete targets resolve as unlabeled.
func newRBACEnv(t *testing.T) *RBACMiddleware {
	t.Helper()
	ctx := context.Background()
	s := store.NewMemoryStore()
	if err := store.SeedDefaultRoles(ctx, s); err != nil {
		t.Fatal(err)
	}
	for name, role := range map[string]string{"v": store.RoleViewer, "o": store.RoleOperator, "a": store.RoleAdmin} {
		if err := s.CreateUser(ctx, &store.User{Username: name}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateBinding(ctx, &store.RoleBinding{Username: name, RoleName: role}); err != nil {
			t.Fatal(err)
		}
	}
	guard := NewResourceGuard("", "", nil) // no protected stack, no socket
	return NewRBACMiddleware(s, nil, guard)
}

// call runs a request as the given user through the middleware and returns the
// resulting status code (200 = allowed through to next, 403 = denied).
func call(mw *RBACMiddleware, user, method, path, body string) int {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := mw.Wrap(next)
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r = r.WithContext(context.WithValue(r.Context(), ContextKeyUser, &store.User{Username: user}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr.Code
}

const (
	deny  = http.StatusForbidden
	allow = http.StatusOK
)

func TestRBACMatrix(t *testing.T) {
	mw := newRBACEnv(t)
	labeled := `{"Labels":{"com.docker.stack.namespace":"app"}}`

	cases := []struct {
		name               string
		method, path, body string
		v, o, a            int // expected status for viewer, operator, admin
	}{
		// Reads.
		{"services list", "GET", "/services", "", allow, allow, allow},
		{"nodes list", "GET", "/nodes", "", allow, allow, allow},
		{"networks get", "GET", "/networks/n1", "", allow, allow, allow},
		{"stack logs", "GET", "/services/s1/logs", "", allow, allow, allow},
		{"secrets list", "GET", "/secrets", "", deny, deny, allow},
		{"configs list", "GET", "/configs", "", deny, allow, allow},
		{"volumes list (agent)", "GET", "/v1/volumes", "", deny, allow, allow},
		{"swarm inspect", "GET", "/swarm", "", deny, deny, allow},
		{"system info", "GET", "/info", "", allow, allow, allow},
		{"ping", "GET", "/_ping", "", allow, allow, allow},

		// Standalone (unlabeled) mutations.
		{"standalone service create", "POST", "/services/create", "{}", deny, allow, allow},
		{"standalone secret create", "POST", "/secrets/create", "{}", deny, deny, allow},
		{"standalone network create", "POST", "/networks/create", "{}", deny, deny, allow},
		{"standalone config create", "POST", "/configs/create", "{}", deny, deny, allow},
		{"service update", "POST", "/services/s1/update", "{}", deny, allow, allow},
		{"service delete (no teardown for operator)", "DELETE", "/services/s1", "", deny, deny, allow},

		// Stack-labeled mutations → governed by stacks (operator may deploy).
		{"stack service create", "POST", "/services/create", labeled, deny, allow, allow},
		{"stack secret create", "POST", "/secrets/create", labeled, deny, allow, allow},
		{"stack network create", "POST", "/networks/create", labeled, deny, allow, allow},
		{"stack config create", "POST", "/configs/create", labeled, deny, allow, allow},

		// Interactive access — incl. the exec lifecycle that follows the
		// create call, so an operator can actually start the exec it created.
		{"docker exec create", "POST", "/containers/c1/exec", "", deny, allow, allow},
		{"docker exec start", "POST", "/exec/e1/start", "", deny, allow, allow},
		{"agent exec", "POST", "/v1/exec", "", deny, allow, allow},
		{"agent forward", "GET", "/v1/forward", "", deny, allow, allow},

		// /events streams resource lifecycle metadata → admin-only.
		{"events", "GET", "/events", "", deny, deny, allow},

		// Agent volume mutations (operator is read-only on volumes).
		{"agent volume create", "POST", "/v1/volumes", "{}", deny, deny, allow},
		{"agent volume delete", "DELETE", "/v1/volumes/vol", "", deny, deny, allow},

		// Unmapped → admin-only.
		{"raw container run", "POST", "/containers/create", "{}", deny, deny, allow},
		{"container start", "POST", "/containers/c1/start", "", deny, deny, allow},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for user, want := range map[string]int{"v": tc.v, "o": tc.o, "a": tc.a} {
				if got := call(mw, user, tc.method, tc.path, tc.body); got != want {
					t.Errorf("user=%s %s %s: got %d, want %d", user, tc.method, tc.path, got, want)
				}
			}
		})
	}
}

func TestRBACInternalListenerBypass(t *testing.T) {
	mw := newRBACEnv(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := mw.Wrap(next)
	// No user, but stamped as internal → must bypass RBAC.
	r := httptest.NewRequest("POST", "/secrets/create", nil)
	r = r.WithContext(context.WithValue(r.Context(), ContextKeyInternal, true))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("internal listener should bypass RBAC, got %d", rr.Code)
	}
}

func TestRBACNoUserDenied(t *testing.T) {
	mw := newRBACEnv(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := mw.Wrap(next)
	// External request with no identity → fail closed.
	r := httptest.NewRequest("GET", "/services", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-identity request should be denied, got %d", rr.Code)
	}
}

func TestRBACDisabledWhenStoreNil(t *testing.T) {
	mw := NewRBACMiddleware(nil, nil, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := mw.Wrap(next)
	r := httptest.NewRequest("POST", "/secrets/create", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusTeapot {
		t.Fatalf("nil store should disable RBAC (passthrough), got %d", rr.Code)
	}
}
