// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"testing"

	"swarm-rbac-proxy/internal/store"
)

func TestMapRequest(t *testing.T) {
	cases := []struct {
		name      string
		method    string
		path      string
		wantRes   string
		wantVerb  string
		stackable bool
	}{
		// Services (Docker socket), version prefix stripped.
		{"services list", "GET", "/services", store.ResourceServices, store.VerbList, true},
		{"services list versioned", "GET", "/v1.47/services", store.ResourceServices, store.VerbList, true},
		{"service inspect", "GET", "/services/abc", store.ResourceServices, store.VerbGet, true},
		{"service create", "POST", "/services/create", store.ResourceServices, store.VerbCreate, true},
		{"service update", "POST", "/services/abc/update", store.ResourceServices, store.VerbUpdate, true},
		{"service rollback folds into update", "POST", "/v1.47/services/abc/update", store.ResourceServices, store.VerbUpdate, true},
		{"service delete", "DELETE", "/services/abc", store.ResourceServices, store.VerbDelete, true},
		{"service logs", "GET", "/services/abc/logs", store.ResourceStackLogs, store.VerbGet, false},

		// Secrets / configs / networks / volumes (stackable).
		{"secrets list", "GET", "/secrets", store.ResourceSecrets, store.VerbList, true},
		{"secret create", "POST", "/secrets/create", store.ResourceSecrets, store.VerbCreate, true},
		{"config create", "POST", "/configs/create", store.ResourceConfigs, store.VerbCreate, true},
		{"network create", "POST", "/networks/create", store.ResourceNetworks, store.VerbCreate, true},
		{"network connect", "POST", "/networks/n1/connect", store.ResourceNetworks, store.VerbUpdate, true},
		{"volume delete (docker)", "DELETE", "/volumes/v1", store.ResourceVolumes, store.VerbDelete, true},

		// Nodes / swarm.
		{"nodes list", "GET", "/nodes", store.ResourceNodes, store.VerbList, false},
		{"node inspect", "GET", "/nodes/n1", store.ResourceNodes, store.VerbGet, false},
		{"swarm inspect (join tokens)", "GET", "/swarm", store.ResourceSwarm, store.VerbGet, false},
		{"swarm leave", "POST", "/swarm/leave", store.ResourceSwarm, store.VerbDelete, false},

		// Tasks / containers / logs.
		{"tasks list", "GET", "/tasks", store.ResourceServices, store.VerbList, false},
		{"task logs", "GET", "/tasks/t1/logs", store.ResourceStackLogs, store.VerbGet, false},
		{"container inspect", "GET", "/containers/c1/json", store.ResourceServices, store.VerbGet, false},
		{"container list", "GET", "/containers/json", store.ResourceServices, store.VerbList, false},
		{"container logs", "GET", "/containers/c1/logs", store.ResourceStackLogs, store.VerbGet, false},
		{"container exec", "POST", "/containers/c1/exec", store.ResourceExec, store.VerbCreate, false},
		{"container attach", "POST", "/containers/c1/attach", store.ResourceExec, store.VerbCreate, false},

		// System handshake.
		{"ping", "GET", "/_ping", store.ResourceSystem, store.VerbGet, false},
		{"version", "GET", "/version", store.ResourceSystem, store.VerbGet, false},
		{"info versioned", "GET", "/v1.47/info", store.ResourceSystem, store.VerbGet, false},

		// Agent-manager control + volumes.
		{"agent exec", "POST", "/v1/exec", store.ResourceExec, store.VerbCreate, false},
		{"agent forward", "GET", "/v1/forward", store.ResourcePortForward, store.VerbCreate, false},
		{"agent logs", "GET", "/v1/logs", store.ResourceStackLogs, store.VerbGet, false},
		{"agent volumes list", "GET", "/v1/volumes", store.ResourceVolumes, store.VerbList, false},
		{"agent volume create", "POST", "/v1/volumes", store.ResourceVolumes, store.VerbCreate, false},
		{"agent volume prune", "POST", "/v1/volumes/prune", store.ResourceVolumes, store.VerbDelete, false},
		{"agent volume delete", "DELETE", "/v1/volumes/vol", store.ResourceVolumes, store.VerbDelete, false},
		{"agent volume file rename", "POST", "/v1/volumes/vol/files/rename", store.ResourceVolumes, store.VerbUpdate, false},

		// Unmapped → admin-only sentinel.
		{"raw container create", "POST", "/containers/create", resourceUnmapped, store.VerbCreate, false},
		{"container start", "POST", "/containers/c1/start", resourceUnmapped, store.VerbCreate, false},
		{"unknown agent path", "GET", "/v1/whatever", resourceUnmapped, store.VerbGet, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapRequest(tc.method, tc.path)
			if got.resource != tc.wantRes || got.verb != tc.wantVerb {
				t.Errorf("mapRequest(%s %s) = {%s,%s}, want {%s,%s}",
					tc.method, tc.path, got.resource, got.verb, tc.wantRes, tc.wantVerb)
			}
			if got.stackable != tc.stackable {
				t.Errorf("mapRequest(%s %s) stackable = %v, want %v",
					tc.method, tc.path, got.stackable, tc.stackable)
			}
		})
	}
}

func TestStripDockerVersion(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"v1.47", "services"}, []string{"services"}},
		{[]string{"services"}, []string{"services"}},
		{[]string{"v2", "nodes"}, []string{"nodes"}},
		{[]string{"version"}, []string{"version"}}, // not a version segment
		{[]string{}, []string{}},
	}
	for _, tc := range cases {
		got := stripDockerVersion(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("stripDockerVersion(%v) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("stripDockerVersion(%v) = %v, want %v", tc.in, got, tc.want)
			}
		}
	}
}
