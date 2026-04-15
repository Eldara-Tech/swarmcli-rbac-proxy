// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// startTestSocket creates a Unix socket HTTP server at a temp path.
func startTestSocket(t *testing.T, handler http.Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "test.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func TestDetectStackName_HappyPath(t *testing.T) {
	hostname, _ := os.Hostname()
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/containers/" + hostname + "/json"
		if r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"Config":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})

	sock := startTestSocket(t, mock)
	name, err := DetectStackName(context.Background(), sock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "swarmcli-infra" {
		t.Errorf("stack name = %q, want %q", name, "swarmcli-infra")
	}
}

func TestDetectStackName_NoLabel(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Config":{"Labels":{}}}`)
	})

	sock := startTestSocket(t, mock)
	_, err := DetectStackName(context.Background(), sock)
	if err == nil {
		t.Fatal("expected error for missing label")
	}
}

func TestDetectStackName_NotFound(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	sock := startTestSocket(t, mock)
	_, err := DetectStackName(context.Background(), sock)
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestDetectStackName_ConnectionError(t *testing.T) {
	_, err := DetectStackName(context.Background(), "/nonexistent/socket.sock")
	if err == nil {
		t.Fatal("expected error for unreachable socket")
	}
}

func TestDetectStackName_MalformedJSON(t *testing.T) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{invalid`)
	})

	sock := startTestSocket(t, mock)
	_, err := DetectStackName(context.Background(), sock)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestDetectStackName_EmptySocketPath(t *testing.T) {
	_, err := DetectStackName(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty socket path")
	}
}
