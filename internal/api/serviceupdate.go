// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
)

// operationalUpdateDenial decides a service update for a caller who may update
// the service but not create it. A full-spec update is root-equivalent on the
// nodes (bind mounts, capabilities, image), which is no more than create
// already grants, so only callers who can create get it; everyone else may
// scale, restart or roll back. It returns why the request is refused, or ""
// when it only does one of those. An error means the live spec could not be
// read; the caller must fail closed.
func (g *ResourceGuard) operationalUpdateDenial(r *http.Request, id string) (string, error) {
	if r.Header.Get("X-Registry-Auth") != "" {
		return "registry credentials are not permitted", nil
	}
	// The daemon ignores the body of a rollback and reinstates PreviousSpec,
	// a spec someone already applied; the TUI sends PreviousSpec as the body.
	if r.URL.Query().Get("rollback") != "previous" {
		live, err := g.liveServiceSpec(r.Context(), id)
		if err != nil {
			return "", err
		}
		data, err := g.readCreateBody(r)
		if err != nil {
			return "invalid request body", nil
		}
		// The daemon applies the first JSON value of the body, like this.
		body, err := decodeJSONValue(data)
		if err != nil {
			return "invalid request body", nil
		}
		if !reflect.DeepEqual(normalizeSpec(live), normalizeSpec(body)) {
			return "the update changes more than replicas or ForceUpdate", nil
		}
	}
	return "", nil
}

// withoutAPIVersion returns r addressed to the daemon's own API version. The
// daemon strips fields an older version lacks (seccomp, capabilities, …) from
// an update body before applying it, so a body that matched the live spec could
// still loosen it. The URL is copied: the access log reads r's after the call.
func withoutAPIVersion(r *http.Request) *http.Request {
	u := *r.URL
	u.Path = "/" + strings.Join(stripDockerVersion(strings.Split(strings.TrimPrefix(u.Path, "/"), "/")), "/")
	u.RawPath = ""
	r = r.WithContext(r.Context())
	r.URL = &u
	return r
}

// liveServiceSpec returns the service's current Spec as generic JSON, so that
// a field this proxy has never heard of still counts in the comparison.
func (g *ResourceGuard) liveServiceSpec(ctx context.Context, id string) (any, error) {
	if g == nil || g.httpClient == nil {
		return nil, fmt.Errorf("no docker back-query")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/services/"+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker API returned %d for service %s", resp.StatusCode, id)
	}
	var svc struct {
		Spec json.RawMessage `json:"Spec"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&svc); err != nil {
		return nil, err
	}
	return decodeJSONValue(svc.Spec)
}

// decodeJSONValue decodes the first JSON value in data, keeping numbers exact.
func decodeJSONValue(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	err := dec.Decode(&v)
	return v, err
}

// normalizeSpec deletes the two fields scaling and restarting change,
// Mode.Replicated.Replicas and TaskTemplate.ForceUpdate, and sorts the two
// lists `docker service update` re-sorts on every call, ContainerSpec.Mounts
// and Ulimits, whose order the daemon does not use.
func normalizeSpec(spec any) any {
	m, _ := spec.(map[string]any)
	if mode, ok := m["Mode"].(map[string]any); ok {
		if replicated, ok := mode["Replicated"].(map[string]any); ok {
			delete(replicated, "Replicas")
		}
	}
	if task, ok := m["TaskTemplate"].(map[string]any); ok {
		delete(task, "ForceUpdate")
		if ctr, ok := task["ContainerSpec"].(map[string]any); ok {
			for _, key := range []string{"Mounts", "Ulimits"} {
				if list, ok := ctr[key].([]any); ok {
					sort.Slice(list, func(i, j int) bool {
						a, _ := json.Marshal(list[i])
						b, _ := json.Marshal(list[j])
						return string(a) < string(b)
					})
				}
			}
		}
	}
	return spec
}
