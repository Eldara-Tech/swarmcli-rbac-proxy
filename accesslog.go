// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"swarm-rbac-proxy/internal/api"
)

// onboardPathPrefix is the one route whose *path* carries a secret: the
// single-use onboarding token is a path segment, not a header or a query
// parameter, so a log line that records the path records the token.
const onboardPathPrefix = "/api/v1/onboard/"

// redactPath returns a request path safe to write to a log. Docker API paths
// carry resource IDs and filters, which are exactly what makes a log line
// useful; the onboarding token is the sole exception and is replaced.
func redactPath(p string) string {
	if strings.HasPrefix(p, onboardPathPrefix) && len(p) > len(onboardPathPrefix) {
		return onboardPathPrefix + "<redacted>"
	}
	return p
}

// accessLog returns middleware that records one line per request.
//
// The proxy had no request log at all, so an incident was visible only as its
// consequences — a burst of upstream failures with nothing saying what had been
// asked for. The level split keeps that fixable without making the fix a new
// source of volume: a served request logs at debug, so turning PROXY_LOG_LEVEL
// up gives a full trace on demand, while anything the proxy refused or could
// not complete logs at info and is therefore visible by default. Guard and RBAC
// denials keep their own warn-level lines; this one adds the status and how
// long it took.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		fields := []interface{}{
			"method", r.Method,
			"path", redactPath(r.URL.Path),
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_ip", requestIP(r),
		}
		if user := certIdentity(r); user != "" {
			fields = append(fields, "user", user)
		}

		// A hijacked connection has no status: handleUpgrade took the socket and
		// wrote raw bytes to it. Saying so is more honest than reporting the 200
		// this recorder was initialised with.
		if rec.hijacked {
			l().Debugw("request upgraded", fields...)
			return
		}
		fields = append(fields, "status", rec.status, "bytes", rec.bytes)
		if rec.status >= http.StatusBadRequest {
			l().Infow("request failed", fields...)
			return
		}
		l().Debugw("request served", fields...)
	})
}

// certIdentity names the mTLS caller, or "" on the internal listener and on any
// request that presented no certificate.
func certIdentity(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return api.IdentityFromCert(r.TLS.PeerCertificates[0])
}

// statusRecorder captures the status and byte count of a response.
//
// It must forward Hijack and Flush: without Hijack, exec and attach stop
// working, because handleUpgrade takes the raw socket through that interface;
// without Flush, ReverseProxy cannot stream, and `docker events` and log
// follows would buffer until they ended.
type statusRecorder struct {
	http.ResponseWriter
	status   int
	bytes    int
	written  bool
	hijacked bool
}

func (s *statusRecorder) WriteHeader(status int) {
	if s.written {
		return
	}
	s.status = status
	s.written = true
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.written = true
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the real ResponseWriter, so every
// capability it brokers — deadlines, flushing, whatever a later Go adds —
// passes through instead of being masked by this wrapper.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijack not supported by %T", s.ResponseWriter)
	}
	s.hijacked = true
	return hj.Hijack()
}
