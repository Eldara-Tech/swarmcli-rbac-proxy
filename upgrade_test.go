// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// dialUpgraded opens an upgraded session through the proxy and returns the raw
// connection positioned just past the 101 response headers.
func dialUpgraded(t *testing.T, addr string) (*net.TCPConn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("want *net.TCPConn, got %T", conn)
	}
	fmt.Fprint(tcp, "POST /v1.45/exec/abc/start HTTP/1.1\r\nHost: docker\r\n"+
		"Upgrade: tcp\r\nConnection: Upgrade\r\n\r\n")

	r := bufio.NewReader(tcp)
	status, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("want 101, got %q", status)
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	return tcp, r
}

// upgradeMock is a backend that speaks the hijack handshake and then runs fn
// over the raw connection.
func upgradeMock(fn func(net.Conn, *bufio.ReadWriter)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: tcp\r\nConnection: Upgrade\r\n\r\n")
		_ = buf.Flush()
		fn(conn, buf)
	})
}

// TestUpgrade_StdinEOFDoesNotTruncateOutput covers the half-close: a caller that
// finishes sending (`echo x | docker exec -i …`) closes its write side, and the
// session must carry on until the command is done. Ending the session on the
// first half to finish would cut the output off here.
func TestUpgrade_StdinEOFDoesNotTruncateOutput(t *testing.T) {
	setDrain(t, 2*time.Second)

	sock, cleanup := startMockSocket(t, upgradeMock(func(conn net.Conn, buf *bufio.ReadWriter) {
		if _, err := buf.ReadString('\n'); err != nil {
			return
		}
		// Output arrives after stdin has already ended, in pieces.
		for i := 0; i < 3; i++ {
			fmt.Fprintf(buf, "line%d\n", i)
			_ = buf.Flush()
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer cleanup()

	ts := httptest.NewServer(newProxy(backend{network: "unix", address: sock}))
	defer ts.Close()

	conn, r := dialUpgraded(t, ts.Listener.Addr().String())
	defer func() { _ = conn.Close() }()

	fmt.Fprint(conn, "stdin\n")
	if err := conn.CloseWrite(); err != nil { // caller is done sending, not gone
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("output truncated after %d of 3 lines: %v", i, err)
		}
		if want := fmt.Sprintf("line%d\n", i); line != want {
			t.Fatalf("line %d = %q, want %q", i, line, want)
		}
	}
}

// TestUpgrade_AbandonedSessionIsReleased is the leak guard. The session used to
// wait for both directions, so a caller that vanished left the backend socket
// and its goroutine pinned until the hour-long idle timeout expired — with this
// test hanging until the go test deadline rather than failing.
func TestUpgrade_AbandonedSessionIsReleased(t *testing.T) {
	setDrain(t, 250*time.Millisecond)

	released := make(chan time.Time, 1)
	sock, cleanup := startMockSocket(t, upgradeMock(func(conn net.Conn, _ *bufio.ReadWriter) {
		// An idle shell: it never writes, and only notices the session ended
		// when the proxy closes the connection under it.
		_, _ = conn.Read(make([]byte, 1))
		released <- time.Now()
	}))
	defer cleanup()

	ts := httptest.NewServer(newProxy(backend{network: "unix", address: sock}))
	defer ts.Close()

	conn, _ := dialUpgraded(t, ts.Listener.Addr().String())
	start := time.Now()
	if err := conn.Close(); err != nil { // the caller goes away mid-session
		t.Fatal(err)
	}

	select {
	case at := <-released:
		if elapsed := at.Sub(start); elapsed > 5*time.Second {
			t.Errorf("backend held for %v after the caller left", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the backend connection was never released; the session is still waiting on the idle timeout")
	}
}

// setDrain shrinks the post-stdin-EOF window for the duration of a test.
func setDrain(t *testing.T, d time.Duration) {
	t.Helper()
	prev := upgradeDrainTimeout
	upgradeDrainTimeout = d
	t.Cleanup(func() { upgradeDrainTimeout = prev })
}
