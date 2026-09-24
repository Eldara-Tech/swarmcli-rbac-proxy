// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"swarm-rbac-proxy/internal/api"
	"swarm-rbac-proxy/internal/store"
)

// externalMuxEnv is a real external listener built by buildExternalMux (the
// function main uses) over mTLS, with Docker and agent-manager mocks behind it.
type externalMuxEnv struct {
	t      *testing.T
	addr   string
	ca     *testCA
	caPool *x509.CertPool
	store  *store.MemoryStore
}

const externalMuxAdminToken = "test-admin-token"

// startExternalMux seeds the built-in roles, binds each user to the given role,
// and serves buildExternalMux on a TLS listener configured as main configures
// it (VerifyClientCertIfGiven). The guard's back-query socket labels service
// "stacked" with a stack namespace and leaves "plain" unlabeled. Every mock
// response carries an X-Backend header naming which upstream answered.
func startExternalMux(t *testing.T, bindings map[string]string, extraRoles ...store.Role) *externalMuxEnv {
	t.Helper()
	ctx := context.Background()
	s := store.NewMemoryStore()
	if err := store.SeedDefaultRoles(ctx, s); err != nil {
		t.Fatal(err)
	}
	for i := range extraRoles {
		if err := s.CreateRole(ctx, &extraRoles[i]); err != nil {
			t.Fatal(err)
		}
	}
	for user, role := range bindings {
		if err := s.CreateUser(ctx, &store.User{Username: user, Role: "user"}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateBinding(ctx, &store.RoleBinding{Username: user, RoleName: role}); err != nil {
			t.Fatal(err)
		}
	}

	sock := startMockDockerSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/stacked") {
			fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"app"}}}`)
			return
		}
		fmt.Fprint(w, `{"Spec":{"Labels":{}}}`)
	}))
	backendMock := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Backend", name)
			dockerMock().ServeHTTP(w, r)
		})
	}
	dockerAddr := startTCPServer(t, backendMock("docker"))
	agentAddr := startTCPServer(t, backendMock("agent"))

	guard := api.NewResourceGuard("swarmcli-infra", sock, s)
	mux := buildExternalMux(routeDeps{
		userStore:         s,
		auditStore:        s,
		rbacStore:         s,
		guard:             guard,
		adminToken:        externalMuxAdminToken,
		backupDir:         t.TempDir(),
		agentManagerProxy: newProxy(backend{network: "tcp", address: agentAddr}),
		dockerProxy:       guard.Wrap(newProxy(backend{network: "tcp", address: dockerAddr})),
	}, true)

	ca := newTestCA(t)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{ca.issueCert(t, serverTemplate())},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return &externalMuxEnv{t: t, addr: ln.Addr().String(), ca: ca, caPool: caPool, store: s}
}

// client returns an HTTPS client presenting a cert for cn, or none if cn is "".
func (e *externalMuxEnv) client(cn string) *http.Client {
	cfg := &tls.Config{RootCAs: e.caPool}
	if cn != "" {
		cfg.Certificates = []tls.Certificate{e.ca.issueCert(e.t, clientTemplateWithCN(cn))}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func (e *externalMuxEnv) do(c *http.Client, method, path string, header http.Header) (*http.Response, []byte) {
	e.t.Helper()
	req, err := http.NewRequest(method, "https://"+e.addr+path, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

type meBody struct {
	Username string                 `json:"username"`
	Role     string                 `json:"role"`
	Rules    []store.PermissionRule `json:"rules"`
}

// me fetches GET /api/v1/me as cn and fails the test unless it is a 200.
func (e *externalMuxEnv) me(cn string) meBody {
	e.t.Helper()
	resp, body := e.do(e.client(cn), http.MethodGet, "/api/v1/me", nil)
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("GET /api/v1/me as %q: status %d, body %s", cn, resp.StatusCode, body)
	}
	var m meBody
	if err := json.Unmarshal(body, &m); err != nil {
		e.t.Fatalf("decode /me: %v; body %s", err, body)
	}
	return m
}

func defaultRoleRules(t *testing.T, name string) []store.PermissionRule {
	t.Helper()
	for _, r := range store.DefaultRoles() {
		if r.Name == name {
			return r.Rules
		}
	}
	t.Fatalf("no default role %q", name)
	return nil
}

// TestIntegration_ExternalMux_MeReturnsEffectiveRules drives GET /api/v1/me
// through main's real external-listener wiring: each user gets exactly their
// bound role's rules; an unknown cert and a missing cert are refused.
func TestIntegration_ExternalMux_MeReturnsEffectiveRules(t *testing.T) {
	env := startExternalMux(t, map[string]string{"v": store.RoleViewer, "o": store.RoleOperator})

	for _, tc := range []struct{ user, role string }{
		{"v", store.RoleViewer},
		{"o", store.RoleOperator},
	} {
		got := env.me(tc.user)
		if got.Username != tc.user || got.Role != "user" {
			t.Errorf("%s: identity = %q/%q, want %q/user", tc.user, got.Username, got.Role, tc.user)
		}
		if want := defaultRoleRules(t, tc.role); !reflect.DeepEqual(got.Rules, want) {
			t.Errorf("%s: rules = %+v, want %+v", tc.user, got.Rules, want)
		}
	}

	if resp, body := env.do(env.client("stranger"), http.MethodGet, "/api/v1/me", nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("unknown CN: status %d, want 403; body %s", resp.StatusCode, body)
	}
	if resp, body := env.do(env.client(""), http.MethodGet, "/api/v1/me", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no cert: status %d, want 401; body %s", resp.StatusCode, body)
	}
}

// TestIntegration_ExternalMux_MeRulesPredictEnforcement pins the contract a
// client relies on: evaluating the rules from /me with the request's RBAC
// mapping (candidates + verb, as in internal/api/rbacmap.go) predicts exactly
// what the real middleware chain does — reaching Docker, or 403.
func TestIntegration_ExternalMux_MeRulesPredictEnforcement(t *testing.T) {
	stackUpdater := store.Role{
		Name:  "stack-updater",
		Rules: []store.PermissionRule{{Resources: []string{store.ResourceStacks}, Verbs: []string{store.VerbUpdate}}},
	}
	env := startExternalMux(t, map[string]string{
		"v": store.RoleViewer,
		"o": store.RoleOperator,
		"s": stackUpdater.Name,
	}, stackUpdater)

	stackable := func(res ...string) []string { return append([]string{store.ResourceServices}, res...) }
	requests := []struct {
		name, method, path string
		candidates         []string
		verb               string
	}{
		{"restart unlabeled", http.MethodPost, "/v1.47/services/plain/update", stackable(), store.VerbUpdate},
		{"restart stack-labeled", http.MethodPost, "/v1.47/services/stacked/update", stackable(store.ResourceStacks), store.VerbUpdate},
		{"service logs", http.MethodGet, "/v1.47/services/plain/logs", []string{store.ResourceStackLogs}, store.VerbGet},
		{"delete unlabeled", http.MethodDelete, "/v1.47/services/plain", stackable(), store.VerbDelete},
		{"delete stack-labeled", http.MethodDelete, "/v1.47/services/stacked", stackable(store.ResourceStacks), store.VerbDelete},
		{"events", http.MethodGet, "/v1.47/events", []string{"unmapped"}, store.VerbGet},
	}

	actual := map[string]bool{}
	for _, user := range []string{"v", "o", "s"} {
		perms := store.EffectivePermissions{Rules: env.me(user).Rules}
		c := env.client(user)
		for _, rq := range requests {
			predicted := perms.Allows(rq.candidates, rq.verb)
			resp, body := env.do(c, rq.method, rq.path, nil)
			allowed := resp.StatusCode/100 == 2 && resp.Header.Get("X-Backend") == "docker"
			if !allowed && resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s / %s: status %d is neither a proxied 2xx nor 403; body %s", user, rq.name, resp.StatusCode, body)
			}
			if predicted != allowed {
				t.Errorf("%s / %s: /me rules predict allowed=%v, proxy enforced allowed=%v (status %d, body %s)",
					user, rq.name, predicted, allowed, resp.StatusCode, body)
			}
			actual[user+"/"+rq.name] = allowed
		}
	}

	// Anchor the agreement to known outcomes, so it cannot hold vacuously.
	for key, want := range map[string]bool{
		"s/restart stack-labeled": true, // stacks:update grants a stack-labeled service
		"s/restart unlabeled":     false,
		"o/restart unlabeled":     true,
		"v/restart unlabeled":     false,
		"v/service logs":          true,
		"o/delete unlabeled":      false,
		"o/events":                false,
	} {
		if actual[key] != want {
			t.Errorf("%s: allowed=%v, want %v", key, actual[key], want)
		}
	}
}

// TestIntegration_ExternalMux_RoutesWired checks every route main registers on
// the external listener reaches its own handler: the catch-all "/" would
// otherwise swallow a dropped route and forward it to Docker.
func TestIntegration_ExternalMux_RoutesWired(t *testing.T) {
	env := startExternalMux(t, map[string]string{"a": store.RoleAdmin, "v": store.RoleViewer})
	bindings, err := env.store.ListBindingsForUser(context.Background(), "v")
	if err != nil || len(bindings) != 1 {
		t.Fatalf("bindings for v: %v, %v", bindings, err)
	}

	admin := env.client("a")
	bearer := http.Header{"Authorization": {"Bearer " + externalMuxAdminToken}}
	for _, tc := range []struct {
		method, path, backend string
	}{
		{http.MethodGet, "/api/v1/users", ""},
		{http.MethodPost, "/api/v1/users/v/regenerate-token", ""},
		{http.MethodPatch, "/api/v1/users/v", ""},
		{http.MethodDelete, "/api/v1/users/nobody", ""},
		{http.MethodGet, "/api/v1/onboard/no-such-token", ""},
		{http.MethodGet, "/api/v1/roles", ""},
		{http.MethodPost, "/api/v1/roles", ""},
		{http.MethodGet, "/api/v1/roles/viewer", ""},
		{http.MethodPut, "/api/v1/roles/nosuchrole", ""},
		{http.MethodDelete, "/api/v1/roles/nosuchrole", ""},
		{http.MethodGet, "/api/v1/bindings", ""},
		{http.MethodPost, "/api/v1/bindings", ""},
		{http.MethodDelete, "/api/v1/bindings/" + bindings[0].ID, ""},
		{http.MethodGet, "/api/v1/me", ""},
		{http.MethodGet, "/v1/containers", "agent"},
		{http.MethodGet, "/v1.47/_ping", "docker"},
	} {
		resp, body := env.do(admin, tc.method, tc.path, bearer)
		if got := resp.Header.Get("X-Backend"); got != tc.backend {
			t.Errorf("%s %s: answered by backend %q, want %q (status %d, body %s)",
				tc.method, tc.path, got, tc.backend, resp.StatusCode, body)
		}
		if resp.StatusCode == http.StatusNotFound && string(body) == "404 page not found\n" {
			t.Errorf("%s %s: not registered on the mux", tc.method, tc.path)
		}
	}
}
