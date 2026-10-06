// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"swarm-rbac-proxy/internal/store"
)

// liveSpec is the stored spec of every service the mock socket serves; the
// "stacked" service additionally carries a stack label.
const liveSpec = `{"Name":"web","Labels":{},` +
	`"TaskTemplate":{"ContainerSpec":{"Image":"nginx:1.27","Init":false,` +
	`"Mounts":[{"Type":"volume","Source":"z","Target":"/z"},{"Type":"volume","Source":"a","Target":"/a"}],` +
	`"Ulimits":[{"Name":"nproc","Soft":64,"Hard":64},{"Name":"nofile","Soft":1024,"Hard":1024}]},` +
	`"Resources":{"Limits":{"MemoryBytes":9007199254740993}},"ForceUpdate":1},` +
	`"Mode":{"Replicated":{"Replicas":2}}}`

// specWith returns liveSpec with edit applied to its decoded form.
func specWith(t *testing.T, edit func(spec map[string]any)) string {
	t.Helper()
	var spec map[string]any
	dec := json.NewDecoder(strings.NewReader(liveSpec))
	dec.UseNumber()
	if err := dec.Decode(&spec); err != nil {
		t.Fatal(err)
	}
	edit(spec)
	out, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func task(spec map[string]any) map[string]any { return spec["TaskTemplate"].(map[string]any) }

func container(spec map[string]any) map[string]any {
	return task(spec)["ContainerSpec"].(map[string]any)
}

// serviceSocket serves GET /services/{id}: "stacked" is stack-labeled, any
// other id is the unlabeled liveSpec.
func serviceSocket(t *testing.T) string {
	t.Helper()
	return startTestSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spec := liveSpec
		if r.URL.Path == "/services/stacked" {
			spec = strings.Replace(liveSpec, `"Labels":{}`, `"Labels":{"com.docker.stack.namespace":"app"}`, 1)
		}
		fmt.Fprint(w, `{"ID":"x","Version":{"Index":42},"Spec":`+spec+`}`)
	}))
}

// newUpdateEnv binds u to an update-only role (reads plus update), s to stacks
// create+update, o to operator and v to viewer.
func newUpdateEnv(t *testing.T, sock string) (*RBACMiddleware, *store.MemoryStore) {
	t.Helper()
	ctx := context.Background()
	s := store.NewMemoryStore()
	if err := store.SeedDefaultRoles(ctx, s); err != nil {
		t.Fatal(err)
	}
	read := store.PermissionRule{Resources: []string{store.ResourceStacks, store.ResourceServices}, Verbs: []string{store.VerbGet, store.VerbList}}
	roles := []store.Role{
		{Name: "updater", Rules: []store.PermissionRule{read, {Resources: []string{store.ResourceServices, store.ResourceStacks}, Verbs: []string{store.VerbUpdate}}}},
		{Name: "stacker", Rules: []store.PermissionRule{read, {Resources: []string{store.ResourceStacks}, Verbs: []string{store.VerbCreate, store.VerbUpdate}}}},
	}
	for i := range roles {
		if err := s.CreateRole(ctx, &roles[i]); err != nil {
			t.Fatal(err)
		}
	}
	for user, role := range map[string]string{"u": "updater", "s": "stacker", "o": store.RoleOperator, "v": store.RoleViewer} {
		if err := s.CreateUser(ctx, &store.User{Username: user}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateBinding(ctx, &store.RoleBinding{Username: user, RoleName: role}); err != nil {
			t.Fatal(err)
		}
	}
	return NewRBACMiddleware(s, s, NewResourceGuard("", sock, s)), s
}

// sendUpdate runs a request through mw as user and returns the status and the
// path the next handler saw ("" when it was not reached). The caller's own
// request must come back unchanged, since the access log reads it afterwards.
func sendUpdate(t *testing.T, mw *RBACMiddleware, user, target, body string, header http.Header) (int, string) {
	t.Helper()
	seen := ""
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		r.Header[k] = v
	}
	r = r.WithContext(context.WithValue(r.Context(), ContextKeyUser, &store.User{Username: user}))
	path := r.URL.Path
	rr := httptest.NewRecorder()
	mw.Wrap(next).ServeHTTP(rr, r)
	if r.URL.Path != path {
		t.Errorf("caller's request path changed to %q", r.URL.Path)
	}
	return rr.Code, seen
}

func TestServiceUpdate_WithoutCreate(t *testing.T) {
	mw, _ := newUpdateEnv(t, serviceSocket(t))
	evilMount := specWith(t, func(s map[string]any) {
		container(s)["Mounts"] = []any{map[string]any{"Type": "bind", "Source": "/", "Target": "/host"}}
	})
	auth := http.Header{"X-Registry-Auth": {"e30="}}

	cases := []struct {
		name, user, target, body string
		header                   http.Header
		want                     int
		wantPath                 string
	}{
		{"scale", "u", "/v1.45/services/web/update?version=42",
			specWith(t, func(s map[string]any) { s["Mode"] = map[string]any{"Replicated": map[string]any{"Replicas": 5}} }),
			nil, allow, "/services/web/update"},
		{"restart", "u", "/v1.53/services/web/update?version=42",
			specWith(t, func(s map[string]any) { task(s)["ForceUpdate"] = 2 }), nil, allow, "/services/web/update"},
		{"unchanged", "u", "/services/web/update?version=42", liveSpec, nil, allow, "/services/web/update"},
		{"mounts and ulimits in another order", "u", "/services/web/update?version=42",
			specWith(t, func(s map[string]any) {
				for _, key := range []string{"Mounts", "Ulimits"} {
					l := container(s)[key].([]any)
					l[0], l[1] = l[1], l[0]
				}
			}), nil, allow, "/services/web/update"},
		{"rollback ignores the body", "u", "/v1.45/services/web/update?version=42&rollback=previous",
			evilMount, nil, allow, "/services/web/update"},
		{"stack-labeled scale", "u", "/services/stacked/update?version=42",
			strings.Replace(liveSpec, `"Labels":{}`, `"Labels":{"com.docker.stack.namespace":"app"}`, 1),
			nil, allow, "/services/stacked/update"},

		{"bind mount", "u", "/services/web/update?version=42", evilMount, nil, deny, ""},
		{"a mount swapped for another", "u", "/services/web/update?version=42",
			specWith(t, func(s map[string]any) {
				container(s)["Mounts"].([]any)[0] = map[string]any{"Type": "bind", "Source": "/", "Target": "/z"}
			}), nil, deny, ""},
		{"image", "u", "/services/web/update?version=42",
			specWith(t, func(s map[string]any) { container(s)["Image"] = "evil:1" }), nil, deny, ""},
		{"a dropped field", "u", "/services/web/update?version=42",
			specWith(t, func(s map[string]any) { delete(container(s), "Init") }), nil, deny, ""},
		{"numbers compare exactly", "u", "/services/web/update?version=42",
			strings.Replace(liveSpec, "9007199254740993", "9007199254740992", 1), nil, deny, ""},
		{"global mode", "u", "/services/web/update?version=42",
			specWith(t, func(s map[string]any) { s["Mode"] = map[string]any{"Global": map[string]any{}} }), nil, deny, ""},
		{"case-variant key the daemon would also read", "u", "/services/web/update?version=42",
			specWith(t, func(s map[string]any) { s["taskTemplate"] = map[string]any{} }), nil, deny, ""},
		{"deprecated top-level Networks", "u", "/services/web/update?version=42",
			specWith(t, func(s map[string]any) { s["Networks"] = []any{map[string]any{"Target": "infra"}} }), nil, deny, ""},
		{"rollback=none still compares", "u", "/services/web/update?version=42&rollback=none", evilMount, nil, deny, ""},
		{"registry auth", "u", "/services/web/update?version=42", liveSpec, auth, deny, ""},
		{"registry auth on rollback", "u", "/services/web/update?version=42&rollback=previous", liveSpec, auth, deny, ""},
		{"invalid JSON", "u", "/services/web/update?version=42", "{", nil, deny, ""},
		{"empty body", "u", "/services/web/update?version=42", "", nil, deny, ""},
		{"oversized body", "u", "/services/web/update?version=42", strings.Repeat(" ", 2<<20+1), nil, deny, ""},

		// Callers who may create the service keep the full update, unrewritten.
		{"operator", "o", "/v1.45/services/web/update?version=42", evilMount, nil, allow, "/v1.45/services/web/update"},
		{"stacks:create on a stack service", "s", "/v1.45/services/stacked/update?version=42", evilMount, nil, allow, "/v1.45/services/stacked/update"},
		{"stacks role on an unlabeled service", "s", "/services/web/update?version=42", evilMount, nil, deny, ""},
		{"viewer", "v", "/services/web/update?version=42", liveSpec, nil, deny, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, path := sendUpdate(t, mw, tc.user, tc.target, tc.body, tc.header)
			if got != tc.want || path != tc.wantPath {
				t.Errorf("got %d %q, want %d %q", got, path, tc.want, tc.wantPath)
			}
		})
	}
}

func TestServiceUpdate_DenialIsAudited(t *testing.T) {
	mw, s := newUpdateEnv(t, serviceSocket(t))
	body := specWith(t, func(s map[string]any) { container(s)["Image"] = "evil:1" })
	if got, _ := sendUpdate(t, mw, "u", "/services/web/update?version=42", body, nil); got != deny {
		t.Fatalf("got %d, want %d", got, deny)
	}
	entries, _ := s.ListAuditEntries(context.Background(), 10)
	want := "role lacks create, so may only scale, restart or roll back: the update changes more than replicas or ForceUpdate"
	if len(entries) != 1 || entries[0].Action != store.AuditRBACDenied || entries[0].Resource != "services:update" || entries[0].Detail != want {
		t.Errorf("audit = %+v", entries)
	}
}

func TestServiceUpdate_FailsClosedWithoutLiveSpec(t *testing.T) {
	cases := map[string]string{
		"daemon error":  respondingSocket(t, http.StatusInternalServerError, `{}`),
		"not found":     respondingSocket(t, http.StatusNotFound, `{}`),
		"no spec":       respondingSocket(t, http.StatusOK, `{}`),
		"not json":      respondingSocket(t, http.StatusOK, `not json`),
		"no socket":     "",
		"socket closed": filepath.Join(t.TempDir(), "absent.sock"),
	}
	for name, sock := range cases {
		t.Run(name, func(t *testing.T) {
			mw, _ := newUpdateEnv(t, sock)
			// No socket also skips the stack-label back-query, so this is the
			// TCP-backend shape: the update must still not go through.
			got, _ := sendUpdate(t, mw, "u", "/services/web/update?version=42", liveSpec, nil)
			if got != http.StatusServiceUnavailable {
				t.Errorf("got %d, want %d", got, http.StatusServiceUnavailable)
			}
		})
	}
}

func TestLiveServiceSpec_Errors(t *testing.T) {
	var nilGuard *ResourceGuard
	if _, err := nilGuard.liveServiceSpec(context.Background(), "web"); err == nil {
		t.Error("nil guard: want error")
	}
	g := NewResourceGuard("", serviceSocket(t), nil)
	if _, err := g.liveServiceSpec(context.Background(), "a%zz"); err == nil {
		t.Error("unparseable id: want error")
	}
	g = NewResourceGuard("", filepath.Join(t.TempDir(), "absent.sock"), nil)
	if _, err := g.liveServiceSpec(context.Background(), "web"); err == nil {
		t.Error("unreachable daemon: want error")
	}
	g = NewResourceGuard("", respondingSocket(t, http.StatusOK, `not json`), nil)
	if _, err := g.liveServiceSpec(context.Background(), "web"); err == nil {
		t.Error("undecodable service: want error")
	}
}

// respondingSocket answers every request with status and body.
func respondingSocket(t *testing.T, status int, body string) string {
	t.Helper()
	return startTestSocket(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
}
