package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// startMockSocket creates a Unix socket HTTP server at a temp path.
// Returns the socket path and a cleanup function.
func startMockSocket(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "mock.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)

	return sock, func() {
		srv.Close()
		ln.Close()
		os.Remove(sock)
	}
}

func TestProxy_GetContainers(t *testing.T) {
	body := `[{"Id":"abc123","Names":["/test"]}]`
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.45/containers/json" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	})

	sock, cleanup := startMockSocket(t, mock)
	defer cleanup()

	proxy := newProxy(backend{network: "unix", address: sock})
	ts := httptest.NewServer(proxy)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1.45/containers/json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != body {
		t.Errorf("body = %q, want %q", got, body)
	}
}

func TestProxy_PostRequest(t *testing.T) {
	reqBody := `{"Image":"alpine"}`
	respBody := `{"Id":"new123"}`

	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1.45/containers/create" {
			t.Errorf("path = %s", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) != reqBody {
			t.Errorf("request body = %q, want %q", b, reqBody)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, respBody)
	})

	sock, cleanup := startMockSocket(t, mock)
	defer cleanup()

	proxy := newProxy(backend{network: "unix", address: sock})
	ts := httptest.NewServer(proxy)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1.45/containers/create", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != respBody {
		t.Errorf("body = %q, want %q", got, respBody)
	}
}

func TestProxy_StreamingResponse(t *testing.T) {
	lines := []string{"line1\n", "line2\n", "line3\n"}

	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected Flusher")
		}
		w.Header().Set("Transfer-Encoding", "chunked")
		for _, line := range lines {
			fmt.Fprint(w, line)
			flusher.Flush()
		}
	})

	sock, cleanup := startMockSocket(t, mock)
	defer cleanup()

	proxy := newProxy(backend{network: "unix", address: sock})
	ts := httptest.NewServer(proxy)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1.45/containers/abc/logs?follow=true")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	got, _ := io.ReadAll(resp.Body)
	want := strings.Join(lines, "")
	if string(got) != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestProxy_UpgradeConnection(t *testing.T) {
	// Mock server: on receiving an Upgrade request, hijack and echo bytes.
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "" {
			http.Error(w, "expected upgrade", 400)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", 500)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		// Send a 101 response.
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: tcp\r\nConnection: Upgrade\r\n\r\n")
		buf.Flush()

		// Echo: read one line, write it back.
		line, err := buf.ReadString('\n')
		if err != nil {
			return
		}
		buf.WriteString("echo:" + line)
		buf.Flush()
	})

	sock, cleanup := startMockSocket(t, mock)
	defer cleanup()

	proxy := newProxy(backend{network: "unix", address: sock})
	ts := httptest.NewServer(proxy)
	defer ts.Close()

	// Connect to the proxy with a raw TCP connection.
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send an upgrade request.
	req := "POST /v1.45/exec/abc123/start HTTP/1.1\r\n" +
		"Host: docker\r\n" +
		"Upgrade: tcp\r\n" +
		"Connection: Upgrade\r\n" +
		"\r\n"
	fmt.Fprint(conn, req)

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101, got: %s", statusLine)
	}

	// Consume remaining headers.
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}

	// Send data through the upgraded connection.
	fmt.Fprint(conn, "hello\n")
	reply, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if reply != "echo:hello\n" {
		t.Errorf("reply = %q, want %q", reply, "echo:hello\n")
	}
}

func TestParseBackend(t *testing.T) {
	tests := []struct {
		input       string
		wantNetwork string
		wantAddress string
		wantErr     bool
	}{
		{"unix:///var/run/docker.sock", "unix", "/var/run/docker.sock", false},
		{"tcp://remote:2375", "tcp", "remote:2375", false},
		{"/tmp/my.sock", "unix", "/tmp/my.sock", false},
		{"", "", "", true},
		{"ftp://host:21", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			b, err := parseBackend(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseBackend(%q) err = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if b.network != tt.wantNetwork || b.address != tt.wantAddress {
				t.Errorf("parseBackend(%q) = {%q, %q}, want {%q, %q}",
					tt.input, b.network, b.address, tt.wantNetwork, tt.wantAddress)
			}
		})
	}
}
