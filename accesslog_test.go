// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	proxylog "swarm-rbac-proxy/internal/log"
)

func TestRedactPath(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		{"onboarding token never reaches the log", "/api/v1/onboard/s3cr3t-token", "/api/v1/onboard/<redacted>"},
		{"the route itself is not a secret", "/api/v1/onboard/", "/api/v1/onboard/"},
		{"docker resource ids are what makes a line useful", "/v1.45/containers/abc123/json", "/v1.45/containers/abc123/json"},
		{"a prefix that only looks similar is untouched", "/api/v1/onboarding", "/api/v1/onboarding"},
		{"management routes pass through", "/api/v1/users", "/api/v1/users"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactPath(tc.path); got != tc.want {
				t.Errorf("redactPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// syncBuffer is a bytes.Buffer safe for the server goroutine to write while the
// test goroutine reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogs points the process logger at a buffer and returns a function
// yielding the decoded JSON entries written since.
func captureLogs(t *testing.T) func() []map[string]any {
	t.Helper()
	buf := &syncBuffer{}
	proxylog.InitTo(buf, "prod", "debug")
	t.Cleanup(func() { proxylog.InitTestIfTestLogEnv() })

	return func() []map[string]any {
		proxylog.Sync()
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var entry map[string]any
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatalf("log line is not JSON: %q (%v)", line, err)
			}
			out = append(out, entry)
		}
		return out
	}
}

func TestAccessLog_ServedRequestIsDebugAndFailureIsInfo(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		wantLevel string
		wantMsg   string
	}{
		{"a served request stays quiet", http.StatusOK, "DEBUG", "request served"},
		{"a denial is visible at the default level", http.StatusForbidden, "INFO", "request failed"},
		{"a fail-closed guard is visible too", http.StatusServiceUnavailable, "INFO", "request failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := captureLogs(t)

			h := accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("body"))
			}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil))

			got := entries()
			if len(got) != 1 {
				t.Fatalf("want exactly one log line, got %d: %v", len(got), got)
			}
			if got[0]["level"] != tc.wantLevel || got[0]["msg"] != tc.wantMsg {
				t.Errorf("level/msg = %v/%v, want %v/%v", got[0]["level"], got[0]["msg"], tc.wantLevel, tc.wantMsg)
			}
			if got[0]["status"] != float64(tc.status) {
				t.Errorf("status = %v, want %d", got[0]["status"], tc.status)
			}
			if got[0]["bytes"] != float64(4) {
				t.Errorf("bytes = %v, want 4", got[0]["bytes"])
			}
			if got[0]["path"] != "/v1.45/containers/json" {
				t.Errorf("path = %v", got[0]["path"])
			}
		})
	}
}

func TestAccessLog_RedactsTheOnboardingToken(t *testing.T) {
	entries := captureLogs(t)

	h := accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound) // logged at info, so it is the default-level case too
	}))
	h.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/api/v1/onboard/super-secret", nil))

	got := entries()
	if len(got) != 1 {
		t.Fatalf("want one log line, got %d", len(got))
	}
	if got[0]["path"] != "/api/v1/onboard/<redacted>" {
		t.Errorf("path = %v, want the token redacted", got[0]["path"])
	}
	for _, e := range got {
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "super-secret") {
			t.Fatalf("the onboarding token reached the log: %s", raw)
		}
	}
}

// waitForLog polls until at least n entries have been written, because the
// access-log line lands after the handler returns and the test observes it from
// another goroutine.
func waitForLog(t *testing.T, entries func() []map[string]any, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := entries()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("want %d log lines, got %d: %v", n, len(got), got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestAccessLog_ForwardsHijack is the guard for exec and attach: the recorder
// sits between the mux and handleUpgrade, and a recorder that does not forward
// Hijack turns every upgrade into a 500.
func TestAccessLog_ForwardsHijack(t *testing.T) {
	entries := captureLogs(t)

	handled := make(chan bool, 1)
	h := accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			handled <- false
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			handled <- false
			return
		}
		_ = conn.Close()
		handled <- true
	}))

	ts := httptest.NewServer(h)
	defer ts.Close()
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /v1/exec HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if !<-handled {
		t.Fatal("accessLog did not forward Hijack; exec and attach would be broken")
	}

	// A hijacked request reports the upgrade rather than the 200 the recorder
	// was initialised with — nothing ever wrote a status.
	got := waitForLog(t, entries, 1)
	if got[0]["msg"] != "request upgraded" {
		t.Fatalf("want a 'request upgraded' line, got %v", got)
	}
	if _, ok := got[0]["status"]; ok {
		t.Error("a hijacked connection has no status to report")
	}
}

// TestAccessLog_ForwardsResponseController covers the capabilities brokered
// through http.ResponseController rather than through an interface assertion:
// without Unwrap the recorder masks them, and a wrapper is meant to be
// transparent.
func TestAccessLog_ForwardsResponseController(t *testing.T) {
	result := make(chan error, 1)
	h := accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		result <- http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Minute))
	}))

	ts := httptest.NewServer(h)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/v1.45/containers/json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := <-result; err != nil {
		t.Errorf("SetWriteDeadline through the recorder: %v", err)
	}
}

// TestAccessLog_ForwardsFlush is the guard for streaming: ReverseProxy asks the
// ResponseWriter for a Flusher, and a recorder that hides it makes `docker
// events` and log follows buffer until the stream ends.
func TestAccessLog_ForwardsFlush(t *testing.T) {
	flushed := make(chan bool, 1)
	h := accessLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			flushed <- false
			return
		}
		_, _ = w.Write([]byte("chunk"))
		f.Flush()
		flushed <- true
	}))

	ts := httptest.NewServer(h)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if !<-flushed {
		t.Fatal("accessLog hid the Flusher; streaming responses would buffer")
	}
	body := bufio.NewReader(resp.Body)
	buf := make([]byte, 5)
	if _, err := body.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "chunk" {
		t.Errorf("body = %q, want %q", buf, "chunk")
	}
}
