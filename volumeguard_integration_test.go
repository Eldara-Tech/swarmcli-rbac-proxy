// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"swarm-rbac-proxy/internal/api"
	"swarm-rbac-proxy/internal/store"
)

// volumeAgentMgrStub stands in for the agent-manager: it answers the guard's
// ownership back-query (GET /v1/volumes?node_id=) from stacks, and 204s any
// forwarded mutation.
func volumeAgentMgrStub(stacks map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/volumes" {
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
			return
		}
		w.WriteHeader(http.StatusNoContent) // forwarded mutation
	})
}

// startVolumeGuardFrontend wires RequireClientCert → ExecGuard → reverse-proxy
// to the agent-manager stub (the volume guard lives in ExecGuard), with the
// guard's ownership back-query pointed at the same stub.
func startVolumeGuardFrontend(t *testing.T, serverCert tls.Certificate, clientCA *x509.CertPool, userStore store.UserStore, protectedStack string, stacks map[string]string) string {
	t.Helper()

	agent := httptest.NewServer(volumeAgentMgrStub(stacks))
	t.Cleanup(agent.Close)
	agentURL, _ := url.Parse(agent.URL)

	guard := api.NewResourceGuard(protectedStack, "", nil)
	guard.SetAgentManager(agent.Client(), agent.URL)

	mux := http.NewServeMux()
	mux.Handle("/", api.RequireClientCert(userStore, guard.ExecGuard(httputil.NewSingleHostReverseProxy(agentURL))))

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCA,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func volGuardClient(t *testing.T, ca *testCA, caPool *x509.CertPool, cn, role string) (*http.Client, string) {
	t.Helper()
	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: cn, Role: role}); err != nil {
		t.Fatal(err)
	}
	addr := startVolumeGuardFrontend(t, ca.issueCert(t, serverTemplate()), caPool, s, "swarmcli-infra",
		map[string]string{"infra-db": "swarmcli-infra", "app-data": "user-app"})
	clientCert := ca.issueCert(t, clientTemplateWithCN(cn))
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
	}}}
	return c, addr
}

func TestIntegration_VolumeGuard_NonAdminMutateProtected_Denied(t *testing.T) {
	ca := newTestCA(t)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)
	c, addr := volGuardClient(t, ca, caPool, "alice", "user")

	req, _ := http.NewRequest(http.MethodDelete, "https://"+addr+"/v1/volumes/infra-db?node_id=n1", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestIntegration_VolumeGuard_AdminMutateProtected_Allowed(t *testing.T) {
	ca := newTestCA(t)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)
	c, addr := volGuardClient(t, ca, caPool, "admin", "admin")

	req, _ := http.NewRequest(http.MethodDelete, "https://"+addr+"/v1/volumes/infra-db?node_id=n1", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (forwarded)", resp.StatusCode)
	}
}

func TestIntegration_VolumeGuard_NonAdminMutateNonProtected_Allowed(t *testing.T) {
	ca := newTestCA(t)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)
	c, addr := volGuardClient(t, ca, caPool, "alice", "user")

	req, _ := http.NewRequest(http.MethodDelete, "https://"+addr+"/v1/volumes/app-data?node_id=n1", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (non-protected forwarded)", resp.StatusCode)
	}
}

func TestIntegration_VolumeGuard_NonAdminList_Allowed(t *testing.T) {
	ca := newTestCA(t)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)
	c, addr := volGuardClient(t, ca, caPool, "alice", "user")

	req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/v1/volumes", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (read allowed for any role)", resp.StatusCode)
	}
}
