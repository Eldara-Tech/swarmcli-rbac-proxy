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
		name string
		user *store.User
		want bool
	}{
		{"no user in context (internal)", nil, true},
		{"admin role", &store.User{Role: "admin"}, false},
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

	guard := NewResourceGuard("swarmcli-infra", sock)
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

	guard := NewResourceGuard("swarmcli-infra", sock)
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

	guard := NewResourceGuard("swarmcli-infra", sock)
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

	guard := NewResourceGuard("swarmcli-infra", sock)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	// No user in context — simulates internal listener.
	r := httptest.NewRequest("DELETE", "/v1.44/services/proxy-svc", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called")
	}
}

func TestGuard_NonAdminDeleteNonProtected(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"user-app"}}}`)
	})
	sock := startTestSocket(t, mock)

	guard := NewResourceGuard("swarmcli-infra", sock)
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
	guard := NewResourceGuard("swarmcli-infra", "")
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
	guard := NewResourceGuard("swarmcli-infra", "")
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
	guard := NewResourceGuard("swarmcli-infra", "")
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
	guard := NewResourceGuard("swarmcli-infra", "")
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
	guard := NewResourceGuard("swarmcli-infra", "")
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

func TestGuard_BackQueryFailure_FailOpen(t *testing.T) {
	// Mock returns 500 — guard should fail open.
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	sock := startTestSocket(t, mock)

	guard := NewResourceGuard("swarmcli-infra", sock)
	inner, called := passHandler()
	handler := guard.Wrap(inner)

	r := httptest.NewRequest("DELETE", "/v1.44/services/some-svc", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (fail open)", w.Code, http.StatusOK)
	}
	if !*called {
		t.Error("inner handler should have been called (fail open)")
	}
}

func TestGuard_BodyStillReadableAfterCreate(t *testing.T) {
	guard := NewResourceGuard("swarmcli-infra", "")
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
	guard := NewResourceGuard("", "")
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

	guard := NewResourceGuard("swarmcli-infra", sock)
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

	guard := NewResourceGuard("swarmcli-infra", sock)
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
	guard := NewResourceGuard("swarmcli-infra", "")
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
