// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
)

const stackNamespaceLabel = "com.docker.stack.namespace"

// DetectStackName queries the Docker daemon to discover the stack namespace
// label on the proxy's own container. It connects to the Docker API at
// socketPath (e.g. "/var/run/docker.sock") using plain HTTP over Unix.
//
// Docker sets the container hostname to the container ID, so os.Hostname()
// is used to identify the container.
func DetectStackName(ctx context.Context, socketPath string) (string, error) {
	if socketPath == "" {
		return "", fmt.Errorf("no socket path provided")
	}

	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("get hostname: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}

	url := "http://docker/containers/" + hostname + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("container inspect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("container inspect returned %d", resp.StatusCode)
	}

	var result struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	name := result.Config.Labels[stackNamespaceLabel]
	if name == "" {
		return "", fmt.Errorf("container has no %s label", stackNamespaceLabel)
	}
	return name, nil
}
