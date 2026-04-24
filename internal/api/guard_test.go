// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"swarm-rbac-proxy/internal/store"
)

// --- parseDockerPath tests ---

func TestParseDockerPath(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   *dockerRoute
	}{
		// Services
		{"DELETE", "/v1.44/services/abc", &dockerRoute{"services", "abc", "delete"}},
		{"DELETE", "/services/abc", &dockerRoute{"services", "abc", "delete"}},
		{"POST", "/v1.47/services/abc/update", &dockerRoute{"services", "abc", "update"}},
		{"POST", "/services/create", &dockerRoute{"services", "", "create"}},
		{"POST", "/v1.44/services/create", &dockerRoute{"services", "", "create"}},

		// Secrets
		{"DELETE", "/v1.44/secrets/mysecret", &dockerRoute{"secrets", "mysecret", "delete"}},
		{"POST", "/v1.44/secrets/mysecret/update", &dockerRoute{"secrets", "mysecret", "update"}},
		{"POST", "/v1.44/secrets/create", &dockerRoute{"secrets", "", "create"}},

		// Networks
		{"DELETE", "/v1.44/networks/mynet", &dockerRoute{"networks", "mynet", "delete"}},
		{"POST", "/v1.47/networks/mynet/connect", &dockerRoute{"networks", "mynet", "connect"}},
		{"POST", "/networks/mynet/connect", &dockerRoute{"networks", "mynet", "connect"}},
		{"POST", "/v1.47/networks/mynet/disconnect", &dockerRoute{"networks", "mynet", "disconnect"}},
		{"POST", "/networks/mynet/disconnect", &dockerRoute{"networks", "mynet", "disconnect"}},

		// Volumes
		{"DELETE", "/v1.44/volumes/myvol", &dockerRoute{"volumes", "myvol", "delete"}},

		// Configs
		{"DELETE", "/v1.44/configs/mycfg", &dockerRoute{"configs", "mycfg", "delete"}},
		{"POST", "/configs/create", &dockerRoute{"configs", "", "create"}},

		// Swarm leave
		{"POST", "/swarm/leave", &dockerRoute{"swarm", "", "leave"}},
		{"POST", "/v1.44/swarm/leave", &dockerRoute{"swarm", "", "leave"}},

		// Non-protected operations — should return nil
		{"GET", "/v1.44/services", nil},
		{"GET", "/v1.44/services/abc", nil},
		{"GET", "/v1.44/containers/json", nil},
		{"POST", "/v1.44/containers/create", nil},
		{"DELETE", "/v1.44/containers/abc", nil},
		{"DELETE", "/v1.44/images/abc", nil},
		{"GET", "/swarm/leave", nil}, // wrong method
		{"GET", "/", nil},
		{"GET", "", nil},

		// connect/disconnect only apply to networks; other resources fall
		// through to nil (not a protected action).
		{"POST", "/v1.47/services/mysvc/connect", nil},
		{"POST", "/v1.47/networks/mynet/connect", &dockerRoute{"networks", "mynet", "connect"}},
		// wrong method
		{"GET", "/v1.47/networks/mynet/connect", nil},
		{"DELETE", "/v1.47/networks/mynet/connect", nil},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := parseDockerPath(tt.method, tt.path)
			if tt.want == nil {
				if got != nil {
					t.Errorf("got %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("got nil, want %+v", tt.want)
			}
			if got.resource != tt.want.resource || got.id != tt.want.id || got.action != tt.want.action {
				t.Errorf("got {%s, %s, %s}, want {%s, %s, %s}",
					got.resource, got.id, got.action,
					tt.want.resource, tt.want.id, tt.want.action)
			}
		})
	}
}

// --- isInternalListener tests ---

func TestIsInternalListener(t *testing.T) {
	tests := []struct {
		name     string
		internal bool // whether to set ContextKeyInternal
		want     bool
	}{
		{"internal flag set", true, true},
		{"no internal flag (external with user)", false, false},
		{"no internal flag (external no user)", false, false}, // regression: auth bypass ≠ internal
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tt.internal {
				ctx := context.WithValue(r.Context(), ContextKeyInternal, true)
				r = r.WithContext(ctx)
			}
			if got := isInternalListener(r); got != tt.want {
				t.Errorf("isInternalListener() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- isAdmin tests ---

func TestIsAdmin(t *testing.T) {
	tests := []struct {
		name string
		user *store.User
		want bool
	}{
		{"no user in context (internal)", nil, false},
		{"admin role", &store.User{Role: "admin"}, true},
		{"user role", &store.User{Role: "user"}, false},
		{"empty role", &store.User{Role: ""}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tt.user != nil {
				ctx := context.WithValue(r.Context(), ContextKeyUser, tt.user)
				r = r.WithContext(ctx)
			}
			if got := isAdmin(r); got != tt.want {
				t.Errorf("isAdmin() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- ResourceGuard.Wrap integration tests ---

// passHandler records that it was called and echoes back 200.
func passHandler() (http.Handler, *bool) {
	called := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	return h, &called
}

func withUser(r *http.Request, user *store.User) *http.Request {
	ctx := context.WithValue(r.Context(), ContextKeyUser, user)
	return r.WithContext(ctx)
}

func TestGuard_NonAdminDeleteProtectedService(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startTestSocket(t, mock)

	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("DELETE", "/v1.44/services/proxy-svc", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestGuard_AdminDeleteProtectedService(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startTestSocket(t, mock)

	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("DELETE", "/v1.44/services/proxy-svc", nil)
	r = withUser(r, &store.User{Role: "admin"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestGuard_AdminUpdateProtectedService(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startTestSocket(t, mock)

	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.44/services/proxy-svc/update", nil)
	r = withUser(r, &store.User{Role: "admin"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestGuard_InternalListenerDeleteProtected(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startTestSocket(t, mock)

	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	// Positive internal flag — simulates internal listener.
	r := httptest.NewRequest("DELETE", "/v1.44/services/proxy-svc", nil)
	ctx := context.WithValue(r.Context(), ContextKeyInternal, true)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestGuard_NoInternalFlagNoUserIsBlocked(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startTestSocket(t, mock)

	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	// No user, no internal flag — simulates auth bypass on external listener.
	r := httptest.NewRequest("DELETE", "/v1.44/services/proxy-svc", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (auth bypass must not grant internal access)", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler must not be called for unauthenticated external request")
	}
}

func TestGuard_NonAdminDeleteNonProtected(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"user-app"}}}`)
	})
	sock := startTestSocket(t, mock)

	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("DELETE", "/v1.44/services/user-svc", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestGuard_NonAdminCreateWithProtectedLabel(t *testing.T) {
	guard := NewResourceGuard("swarmcli-infra", "", nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	body := `{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}`
	r := httptest.NewRequest("POST", "/v1.44/services/create", strings.NewReader(body))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestGuard_NonAdminCreateWithoutProtectedLabel(t *testing.T) {
	guard := NewResourceGuard("swarmcli-infra", "", nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	body := `{"Labels":{"com.docker.stack.namespace":"user-app"}}`
	r := httptest.NewRequest("POST", "/v1.44/services/create", strings.NewReader(body))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestGuard_NonAdminSwarmLeave(t *testing.T) {
	guard := NewResourceGuard("swarmcli-infra", "", nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/swarm/leave", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestGuard_AdminSwarmLeave(t *testing.T) {
	guard := NewResourceGuard("swarmcli-infra", "", nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/swarm/leave", nil)
	r = withUser(r, &store.User{Role: "admin"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestGuard_ReadOnlyPassesThrough(t *testing.T) {
	guard := NewResourceGuard("swarmcli-infra", "", nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("GET", "/v1.44/services", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestGuard_BackQueryFailure_UpdateFailClosed(t *testing.T) {
	// Mock returns 500 — guard should fail closed for updates.
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	sock := startTestSocket(t, mock)

	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.44/services/some-svc/update", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (fail closed)", w.Code, http.StatusServiceUnavailable)
	}
	if *called {
		t.Error("inner handler should not have been called (fail closed)")
	}
}

func TestGuard_BackQueryFailure_DeleteFailClosed(t *testing.T) {
	// Mock returns 500 — guard should fail closed for deletes.
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	sock := startTestSocket(t, mock)

	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("DELETE", "/v1.44/services/some-svc", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (fail closed)", w.Code, http.StatusServiceUnavailable)
	}
	if *called {
		t.Error("inner handler should not have been called (fail closed)")
	}
}

func TestGuard_BodyStillReadableAfterCreate(t *testing.T) {
	guard := NewResourceGuard("swarmcli-infra", "", nil)
	body := `{"Labels":{"app":"myapp"},"Image":"nginx"}`
	var innerBody string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		innerBody = string(data)
		w.WriteHeader(http.StatusOK)
	})
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.44/services/create", strings.NewReader(body))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if innerBody != body {
		t.Errorf("inner body = %q, want %q", innerBody, body)
	}
}

func TestGuard_EmptyStackName_NoOp(t *testing.T) {
	guard := NewResourceGuard("", "", nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("DELETE", "/v1.44/services/anything", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestGuard_NilGuard_NoOp(t *testing.T) {
	var guard *ResourceGuard
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("DELETE", "/v1.44/services/anything", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestGuard_NetworkLabelAtTopLevel(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Networks have Labels at top level, not under Spec.
		fmt.Fprint(w, `{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}`)
	})
	sock := startTestSocket(t, mock)

	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("DELETE", "/v1.44/networks/infra-net", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestGuard_NonAdminUpdateProtectedSecret(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startTestSocket(t, mock)

	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.44/secrets/ca-key/update", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestGuard_CreateSpecLabels(t *testing.T) {
	// Some resources have labels under Spec in the create body.
	guard := NewResourceGuard("swarmcli-infra", "", nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	body := `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`
	r := httptest.NewRequest("POST", "/v1.44/secrets/create", strings.NewReader(body))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

// networkMock returns a handler that responds to /networks/{id} and
// /services/{id} back-queries. Networks carry their label at top level;
// the service branch keeps non-protected so update-path tests can isolate
// the body-inspect check from the service-id check.
func networkMock(networkStackLabel, serviceStackLabel string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/networks/"):
			fmt.Fprintf(w, `{"Labels":{"com.docker.stack.namespace":%q}}`, networkStackLabel)
		case strings.HasPrefix(r.URL.Path, "/services/"):
			fmt.Fprintf(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":%q}}}`, serviceStackLabel)
		default:
			http.NotFound(w, r)
		}
	})
}

// --- T1: service create/update Networks[].Target body inspection ---

const serviceCreateWithProtectedNet = `{
  "Name": "pivot",
  "TaskTemplate": {
    "ContainerSpec": {"Image": "alpine"},
    "Networks": [{"Target": "proto-net-id"}]
  }
}`

func TestGuard_NonAdminServiceCreateWithProtectedNetAttachment(t *testing.T) {
	sock := startTestSocket(t, networkMock("swarmcli-infra", "user-app"))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/services/create", strings.NewReader(serviceCreateWithProtectedNet))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestGuard_AdminServiceCreateWithProtectedNetAttachment_Blocked(t *testing.T) {
	// Admins are also blocked from attaching a service to the protected
	// overlay via the proxy — overlay mutation requires host Docker.
	sock := startTestSocket(t, networkMock("swarmcli-infra", "user-app"))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/services/create", strings.NewReader(serviceCreateWithProtectedNet))
	r = withUser(r, &store.User{Role: "admin"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestGuard_NonAdminServiceCreateNonProtectedNetAttachment_Allowed(t *testing.T) {
	sock := startTestSocket(t, networkMock("user-app", "user-app"))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/services/create", strings.NewReader(serviceCreateWithProtectedNet))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestGuard_NonAdminServiceUpdateWithProtectedNetAttachment(t *testing.T) {
	// Service itself is non-protected (so the isProtectedResource check
	// passes), but the body attaches to the protected overlay.
	sock := startTestSocket(t, networkMock("swarmcli-infra", "user-app"))
	audit := store.NewMemoryStore()
	guard := NewResourceGuard("swarmcli-infra", sock, audit)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/services/user-svc/update", strings.NewReader(serviceCreateWithProtectedNet))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
	entries, _ := audit.ListAuditEntries(context.Background(), 10)
	if len(entries) != 1 || entries[0].Detail != "protected stack network attachment (update)" {
		t.Errorf("expected audit entry with 'protected stack network attachment (update)' detail, got %+v", entries)
	}
}

func TestGuard_AdminServiceUpdateInPlaceOnProtectedService_Allowed(t *testing.T) {
	// Admin updating a protected-stack service whose body re-affirms
	// agent-net attachment: pivot-only semantics leave this allowed —
	// the service is already on the overlay, this is an in-place update
	// (image rotate / scale / secret rotate), not a pivot.
	sock := startTestSocket(t, networkMock("swarmcli-infra", "swarmcli-infra"))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/services/proto-svc/update", strings.NewReader(serviceCreateWithProtectedNet))
	r = withUser(r, &store.User{Role: "admin"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestGuard_AdminServiceUpdatePivotOntoProtectedNet_Blocked(t *testing.T) {
	// Admin updating a non-protected service whose body attaches to
	// agent-net: this IS a pivot and is blocked for admins too.
	sock := startTestSocket(t, networkMock("swarmcli-infra", "user-app"))
	audit := store.NewMemoryStore()
	guard := NewResourceGuard("swarmcli-infra", sock, audit)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/services/user-svc/update", strings.NewReader(serviceCreateWithProtectedNet))
	r = withUser(r, &store.User{Role: "admin"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
	entries, _ := audit.ListAuditEntries(context.Background(), 10)
	if len(entries) != 1 || entries[0].Detail != "protected stack network attachment (update)" {
		t.Errorf("expected audit entry with 'protected stack network attachment (update)' detail, got %+v", entries)
	}
}

func TestGuard_ServiceCreateBodyStillReadableAfterNetCheck(t *testing.T) {
	sock := startTestSocket(t, networkMock("user-app", "user-app"))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	var innerBody string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		innerBody = string(data)
		w.WriteHeader(http.StatusOK)
	})
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/services/create", strings.NewReader(serviceCreateWithProtectedNet))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if innerBody != serviceCreateWithProtectedNet {
		t.Errorf("inner body = %q, want %q", innerBody, serviceCreateWithProtectedNet)
	}
}

func TestGuard_ServiceCreateNetAttachmentBackQueryFailure_FailClosed(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	sock := startTestSocket(t, mock)
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/services/create", strings.NewReader(serviceCreateWithProtectedNet))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (fail closed)", w.Code, http.StatusServiceUnavailable)
	}
	if *called {
		t.Error("inner handler should not have been called (fail closed)")
	}
}

// --- T2: /networks/{id}/connect and /disconnect ---

func TestGuard_NonAdminNetworkConnect_Protected(t *testing.T) {
	sock := startTestSocket(t, networkMock("swarmcli-infra", ""))
	audit := store.NewMemoryStore()
	guard := NewResourceGuard("swarmcli-infra", sock, audit)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/networks/infra-net/connect", strings.NewReader(`{"Container":"ctr-abc"}`))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
	entries, _ := audit.ListAuditEntries(context.Background(), 10)
	if len(entries) != 1 || entries[0].Detail != "protected stack network connect" {
		t.Errorf("expected audit entry with 'protected stack network connect' detail, got %+v", entries)
	}
}

func TestGuard_NonAdminNetworkDisconnect_Protected(t *testing.T) {
	sock := startTestSocket(t, networkMock("swarmcli-infra", ""))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/networks/infra-net/disconnect", strings.NewReader(`{"Container":"ctr-abc"}`))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestGuard_AdminNetworkConnect_Blocked(t *testing.T) {
	// Admins are also blocked from (dis)connecting workloads to the
	// protected overlay via the proxy.
	sock := startTestSocket(t, networkMock("swarmcli-infra", ""))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/networks/infra-net/connect", strings.NewReader(`{"Container":"ctr-abc"}`))
	r = withUser(r, &store.User{Role: "admin"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestGuard_AdminNetworkDisconnect_Blocked(t *testing.T) {
	sock := startTestSocket(t, networkMock("swarmcli-infra", ""))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/networks/infra-net/disconnect", strings.NewReader(`{"Container":"ctr-abc"}`))
	r = withUser(r, &store.User{Role: "admin"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestGuard_NonAdminNetworkConnect_NonProtected_Allowed(t *testing.T) {
	sock := startTestSocket(t, networkMock("user-app", ""))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/networks/user-net/connect", strings.NewReader(`{"Container":"ctr-abc"}`))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestGuard_NetworkConnect_BackQueryFailure_FailClosed(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	sock := startTestSocket(t, mock)
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.47/networks/some-net/connect", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (fail closed)", w.Code, http.StatusServiceUnavailable)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

// --- isExecPath tests ---

func TestIsExecPath(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		// Agent exec
		{"GET", "/v1/exec", true},
		{"POST", "/v1/exec", true},
		{"GET", "/v1/exec/", true},
		{"GET", "/v1/exec/something", true},
		// Docker exec
		{"POST", "/v1.44/containers/abc/exec", true},
		{"POST", "/containers/abc/exec", true},
		// Docker attach (POST and WebSocket)
		{"POST", "/v1.44/containers/abc/attach", true},
		{"POST", "/containers/abc/attach", true},
		{"GET", "/containers/abc/attach/ws", true},       // WebSocket attach
		{"GET", "/v1.44/containers/abc/attach/ws", true}, // versioned WebSocket attach
		{"GET", "/containers/abc/attach", true},          // GET attach (non-WebSocket)
		// Non-exec
		{"GET", "/v1.44/containers/abc/exec", false},   // wrong method for Docker exec
		{"POST", "/v1.44/containers/abc/start", false}, // not exec/attach
		{"GET", "/v1/logs", false},
		{"POST", "/v1/execute", false},
		{"GET", "/v1/", false},
		{"GET", "/", false},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			if got := isExecPath(tt.method, tt.path); got != tt.want {
				t.Errorf("isExecPath(%q, %q) = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}

// --- ExecGuard tests ---

// containerMock returns a handler that responds to /containers/{id}/json and
// /tasks/{id} back-queries, plus /services/{id} for the task→service path.
// stackLabel is the com.docker.stack.namespace to embed.
func containerMock(stackLabel string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/containers/"):
			fmt.Fprintf(w, `{"Config":{"Labels":{"com.docker.stack.namespace":%q}}}`, stackLabel)
		case strings.HasPrefix(r.URL.Path, "/tasks/"):
			fmt.Fprint(w, `{"ServiceID":"svc-abc"}`)
		case strings.HasPrefix(r.URL.Path, "/services/"):
			fmt.Fprintf(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":%q}}}`, stackLabel)
		default:
			http.NotFound(w, r)
		}
	})
}

func TestExecGuard_EmptyStackName_NoOp(t *testing.T) {
	guard := NewResourceGuard("", "", nil)
	inner, called := passHandler()
	handler := guard.ExecGuard(inner)

	r := httptest.NewRequest("GET", "/v1/exec", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestExecGuard_NonExecPath_PassesThrough(t *testing.T) {
	guard := NewResourceGuard("swarmcli-infra", "", nil)
	inner, called := passHandler()
	handler := guard.ExecGuard(inner)

	r := httptest.NewRequest("GET", "/v1/logs", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

// TestExecGuard_NoSocket_ExecUnrestricted verifies that when no Docker socket
// is configured the guard cannot do back-queries and therefore allows all exec
// (can't distinguish stacks). The internal listener uses noExecGuard in
// main.go and never reaches ExecGuard — no bypass is needed here.
func TestExecGuard_NoSocket_ExecUnrestricted(t *testing.T) {
	guard := NewResourceGuard("swarmcli-infra", "", nil) // stackName set, but no socket
	inner, called := passHandler()
	handler := guard.ExecGuard(inner)

	r := httptest.NewRequest("GET", "/v1/exec", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestExecGuard_AgentExec_ProtectedStack_NonAdmin_Blocked(t *testing.T) {
	sock := startTestSocket(t, containerMock("swarmcli-infra"))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.ExecGuard(inner)

	r := httptest.NewRequest("GET", "/v1/exec?task_id=task-xyz", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestExecGuard_AgentExec_ProtectedStack_Admin_Allowed(t *testing.T) {
	sock := startTestSocket(t, containerMock("swarmcli-infra"))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.ExecGuard(inner)

	r := httptest.NewRequest("GET", "/v1/exec?task_id=task-xyz", nil)
	r = withUser(r, &store.User{Role: "admin"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestExecGuard_AgentExec_NonProtectedStack_UserAllowed(t *testing.T) {
	sock := startTestSocket(t, containerMock("user-app"))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.ExecGuard(inner)

	r := httptest.NewRequest("GET", "/v1/exec?task_id=task-xyz", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestExecGuard_AgentExec_NoTaskID_PassesThrough(t *testing.T) {
	guard := NewResourceGuard("swarmcli-infra", "", nil)
	inner, called := passHandler()
	handler := guard.ExecGuard(inner)

	r := httptest.NewRequest("GET", "/v1/exec", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestExecGuard_DockerExec_ProtectedStack_NonAdmin_Blocked(t *testing.T) {
	sock := startTestSocket(t, containerMock("swarmcli-infra"))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.ExecGuard(inner)

	r := httptest.NewRequest("POST", "/v1.44/containers/ctr-abc/exec", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestExecGuard_DockerExec_NonProtectedStack_UserAllowed(t *testing.T) {
	sock := startTestSocket(t, containerMock("user-app"))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.ExecGuard(inner)

	r := httptest.NewRequest("POST", "/v1.44/containers/ctr-abc/exec", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestExecGuard_DockerAttach_ProtectedStack_NonAdmin_Blocked(t *testing.T) {
	sock := startTestSocket(t, containerMock("swarmcli-infra"))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.ExecGuard(inner)

	r := httptest.NewRequest("POST", "/containers/ctr-abc/attach", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestExecGuard_DockerExec_NoStackLabel_UserAllowed(t *testing.T) {
	// Container has no stack label — not part of any stack, not protected.
	sock := startTestSocket(t, containerMock(""))
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.ExecGuard(inner)

	r := httptest.NewRequest("POST", "/containers/ctr-abc/exec", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestExecGuard_BackQueryError_FailClosed(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	sock := startTestSocket(t, mock)
	guard := NewResourceGuard("swarmcli-infra", sock, nil)
	inner, called := passHandler()
	handler := guard.ExecGuard(inner)

	r := httptest.NewRequest("POST", "/v1.44/containers/ctr-abc/exec", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (fail closed)", w.Code, http.StatusServiceUnavailable)
	}
	if *called {
		t.Error("inner handler should not have been called")
	}
}

func TestGuard_CreateMalformedBodyBlocked(t *testing.T) {
	guard := NewResourceGuard("swarmcli-infra", "", nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	// Invalid JSON body should be blocked (fail-closed on parse error).
	r := httptest.NewRequest("POST", "/services/create", strings.NewReader("{invalid-json"))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed body: status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if *called {
		t.Error("inner handler should not be called on malformed body")
	}
}

func TestGuard_CreateOversizedBodyBlocked(t *testing.T) {
	guard := NewResourceGuard("swarmcli-infra", "", nil)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	// Body larger than maxCreateBodySize (2 MB) should be blocked.
	bigBody := strings.NewReader(strings.Repeat("x", 3<<20)) // 3 MB
	r := httptest.NewRequest("POST", "/services/create", bigBody)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("oversized body: status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if *called {
		t.Error("inner handler should not be called on oversized body")
	}
}

// --- Audit entry tests ---

func TestGuard_SwarmLeave_AuditEntry(t *testing.T) {
	audit := store.NewMemoryStore()
	guard := NewResourceGuard("swarmcli-infra", "", audit)
	inner, _ := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/swarm/leave", nil)
	r = withUser(r, &store.User{Username: "alice", Role: "user"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	entries, err := audit.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(entries))
	}
	if entries[0].Action != store.AuditGuardBlocked {
		t.Errorf("Action = %q, want %q", entries[0].Action, store.AuditGuardBlocked)
	}
	if entries[0].Resource != "swarm:leave" {
		t.Errorf("Resource = %q, want %q", entries[0].Resource, "swarm:leave")
	}
	if entries[0].Status != "denied" {
		t.Errorf("Status = %q, want %q", entries[0].Status, "denied")
	}
	if entries[0].Actor != "alice" {
		t.Errorf("Actor = %q, want %q", entries[0].Actor, "alice")
	}
}

func TestGuard_CreateProtected_AuditEntry(t *testing.T) {
	audit := store.NewMemoryStore()
	guard := NewResourceGuard("swarmcli-infra", "", audit)
	inner, _ := passHandler()
	handler := guard.Wrap(inner)

	body := `{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}`
	r := httptest.NewRequest("POST", "/services/create", strings.NewReader(body))
	r = withUser(r, &store.User{Username: "bob", Role: "user"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	entries, err := audit.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(entries))
	}
	if entries[0].Resource != "services:create" {
		t.Errorf("Resource = %q, want %q", entries[0].Resource, "services:create")
	}
}

func TestGuard_UpdateProtected_NonAdmin_AuditEntry(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startTestSocket(t, mock)

	audit := store.NewMemoryStore()
	guard := NewResourceGuard("swarmcli-infra", sock, audit)
	inner, _ := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.44/secrets/ca-key/update", nil)
	r = withUser(r, &store.User{Username: "eve", Role: "user"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	entries, err := audit.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(entries))
	}
	if entries[0].Resource != "secrets:ca-key" {
		t.Errorf("Resource = %q, want %q", entries[0].Resource, "secrets:ca-key")
	}
	if entries[0].Detail != "protected stack update" {
		t.Errorf("Detail = %q, want %q", entries[0].Detail, "protected stack update")
	}
}

func TestGuard_DeleteProtected_AuditEntry(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startTestSocket(t, mock)

	audit := store.NewMemoryStore()
	guard := NewResourceGuard("swarmcli-infra", sock, audit)
	inner, _ := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("DELETE", "/v1.44/services/proxy-svc", nil)
	r = withUser(r, &store.User{Username: "eve", Role: "user"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	entries, err := audit.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(entries))
	}
	if entries[0].Resource != "services:proxy-svc" {
		t.Errorf("Resource = %q, want %q", entries[0].Resource, "services:proxy-svc")
	}
	if entries[0].Detail != "protected stack delete" {
		t.Errorf("Detail = %q, want %q", entries[0].Detail, "protected stack delete")
	}
}

func TestExecGuard_ProtectedExec_NonAdmin_AuditEntry(t *testing.T) {
	sock := startTestSocket(t, containerMock("swarmcli-infra"))

	audit := store.NewMemoryStore()
	guard := NewResourceGuard("swarmcli-infra", sock, audit)
	inner, _ := passHandler()
	handler := guard.ExecGuard(inner)

	r := httptest.NewRequest("POST", "/v1.44/containers/ctr-abc/exec", nil)
	r = withUser(r, &store.User{Username: "eve", Role: "user"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	entries, err := audit.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(entries))
	}
	if entries[0].Action != store.AuditGuardBlocked {
		t.Errorf("Action = %q, want %q", entries[0].Action, store.AuditGuardBlocked)
	}
	if entries[0].Resource != "exec:/v1.44/containers/ctr-abc/exec" {
		t.Errorf("Resource = %q, want %q", entries[0].Resource, "exec:/v1.44/containers/ctr-abc/exec")
	}
	if entries[0].Detail != "protected stack exec" {
		t.Errorf("Detail = %q, want %q", entries[0].Detail, "protected stack exec")
	}
}

func TestGuard_InternalListener_NoAudit(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startTestSocket(t, mock)

	audit := store.NewMemoryStore()
	guard := NewResourceGuard("swarmcli-infra", sock, audit)
	inner, _ := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("DELETE", "/v1.44/services/proxy-svc", nil)
	ctx := context.WithValue(r.Context(), ContextKeyInternal, true)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	entries, err := audit.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 audit entries for internal listener, got %d", len(entries))
	}
}

func TestGuard_AdminUpdate_NoAudit(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startTestSocket(t, mock)

	audit := store.NewMemoryStore()
	guard := NewResourceGuard("swarmcli-infra", sock, audit)
	inner, _ := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("POST", "/v1.44/services/proxy-svc/update", nil)
	r = withUser(r, &store.User{Username: "admin1", Role: "admin"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	entries, err := audit.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 audit entries for admin update, got %d", len(entries))
	}
}

func TestGuard_NonProtectedDelete_NoAudit(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"user-app"}}}`)
	})
	sock := startTestSocket(t, mock)

	audit := store.NewMemoryStore()
	guard := NewResourceGuard("swarmcli-infra", sock, audit)
	inner, _ := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("DELETE", "/v1.44/services/user-svc", nil)
	r = withUser(r, &store.User{Username: "alice", Role: "user"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	entries, err := audit.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 audit entries for non-protected delete, got %d", len(entries))
	}
}
