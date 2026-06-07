// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"swarm-rbac-proxy/internal/store"
)

// volBackQuery returns an httptest server standing in for the agent-manager's
// GET /v1/volumes?node_id=. It reports `volumes` with the given name->stack map.
func volBackQuery(t *testing.T, stacks map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/volumes" {
			t.Errorf("back-query path = %q", r.URL.Path)
		}
		type vol struct {
			Name  string `json:"name"`
			Stack string `json:"stack"`
		}
		out := struct {
			Volumes []vol `json:"volumes"`
		}{}
		for name, stack := range stacks {
			out.Volumes = append(out.Volumes, vol{Name: name, Stack: stack})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// okNext is a terminal handler that records it was reached and writes 204.
func okNext(reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusNoContent)
	})
}

func newVolGuard(t *testing.T, stacks map[string]string) *ResourceGuard {
	g := NewResourceGuard("swarmcli-infra", "", nil)
	bq := volBackQuery(t, stacks)
	g.SetAgentManager(bq.Client(), bq.URL)
	return g
}

func TestVolumeGuard_GetAllowed(t *testing.T) {
	g := newVolGuard(t, nil)
	var reached bool
	h := g.ExecGuard(okNext(&reached))

	r := httptest.NewRequest(http.MethodGet, "/v1/volumes", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !reached {
		t.Fatal("GET should pass through")
	}
}

func TestVolumeGuard_NonAdminMutatesProtected_Denied(t *testing.T) {
	g := newVolGuard(t, map[string]string{"infra-db": "swarmcli-infra"})
	var reached bool
	h := g.ExecGuard(okNext(&reached))

	r := httptest.NewRequest(http.MethodDelete, "/v1/volumes/infra-db?node_id=n1", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if reached {
		t.Fatal("protected-stack mutation by non-admin must be blocked")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("code = %d want 403", w.Code)
	}
}

func TestVolumeGuard_AdminMutatesProtected_Allowed(t *testing.T) {
	g := newVolGuard(t, map[string]string{"infra-db": "swarmcli-infra"})
	var reached bool
	h := g.ExecGuard(okNext(&reached))

	r := httptest.NewRequest(http.MethodDelete, "/v1/volumes/infra-db?node_id=n1", nil)
	r = withUser(r, &store.User{Role: "admin"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !reached {
		t.Fatal("admin mutation of protected volume should pass")
	}
}

func TestVolumeGuard_NonAdminMutatesUnprotected_Allowed(t *testing.T) {
	g := newVolGuard(t, map[string]string{"app-data": "user-app"})
	var reached bool
	h := g.ExecGuard(okNext(&reached))

	r := httptest.NewRequest(http.MethodDelete, "/v1/volumes/app-data?node_id=n1", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !reached {
		t.Fatal("non-protected mutation should pass for any authenticated user")
	}
}

func TestVolumeGuard_CreateUnknownName_Allowed(t *testing.T) {
	g := newVolGuard(t, nil) // node has no volumes → fresh name not protected
	var reached bool
	h := g.ExecGuard(okNext(&reached))

	r := httptest.NewRequest(http.MethodPost, "/v1/volumes?node_id=n1", strings.NewReader(`{"name":"newvol"}`))
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !reached {
		t.Fatal("creating a fresh, non-colliding volume should be allowed")
	}
}

func TestVolumeGuard_BackQueryError_FailsClosed(t *testing.T) {
	g := NewResourceGuard("swarmcli-infra", "", nil)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(bad.Close)
	g.SetAgentManager(bad.Client(), bad.URL)

	var reached bool
	h := g.ExecGuard(okNext(&reached))
	r := httptest.NewRequest(http.MethodDelete, "/v1/volumes/x?node_id=n1", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if reached {
		t.Fatal("must not pass through on back-query failure")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d want 503", w.Code)
	}
}

func TestVolumeGuard_FileDeleteProtected_Denied(t *testing.T) {
	g := newVolGuard(t, map[string]string{"infra-db": "swarmcli-infra"})
	var reached bool
	h := g.ExecGuard(okNext(&reached))

	r := httptest.NewRequest(http.MethodDelete, "/v1/volumes/infra-db/files?node_id=n1&path=/x", nil)
	r = withUser(r, &store.User{Role: "user"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if reached || w.Code != http.StatusForbidden {
		t.Fatalf("file mutation on protected volume must be 403, got reached=%v code=%d", reached, w.Code)
	}
}

func TestVolumeGuard_SuccessIsAudited(t *testing.T) {
	mem := store.NewMemoryStore()
	g := NewResourceGuard("swarmcli-infra", "", mem)
	bq := volBackQuery(t, map[string]string{"app-data": "user-app"})
	g.SetAgentManager(bq.Client(), bq.URL)

	var reached bool
	h := g.ExecGuard(okNext(&reached))
	r := httptest.NewRequest(http.MethodDelete, "/v1/volumes/app-data?node_id=n1", nil)
	r = withUser(r, &store.User{Role: "user"})
	h.ServeHTTP(httptest.NewRecorder(), r)

	if !reached {
		t.Fatal("expected pass-through")
	}
	entries, err := mem.ListAuditEntries(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != store.AuditVolumeDeleted || entries[0].Status != "success" {
		t.Fatalf("expected one volume.deleted success audit, got %+v", entries)
	}
}
