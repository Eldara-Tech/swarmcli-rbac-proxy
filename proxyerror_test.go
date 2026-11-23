// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestProxyErrorHandler_ClientHangUpIsNotAProxyError is the regression guard for
// the log flood: a caller that goes away mid-request produced one error-level
// "http: proxy error: context canceled" per in-flight request, on a stream
// PROXY_LOG_LEVEL could not reach.
func TestProxyErrorHandler_ClientHangUpIsNotAProxyError(t *testing.T) {
	entries := captureLogs(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/abc/stats", nil)
	proxyErrorHandler(rec, req, context.Canceled)

	got := entries()
	if len(got) != 1 {
		t.Fatalf("want one log line, got %d: %v", len(got), got)
	}
	if got[0]["level"] != "DEBUG" {
		t.Errorf("level = %v, want DEBUG: a caller hanging up is routine", got[0]["level"])
	}
	// Nothing is written to a response whose reader is already gone.
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("wrote %d/%q to a departed client", rec.Code, rec.Body.String())
	}
}

// TestProxyErrorHandler_WrappedCancellationIsRecognised covers the shape the
// error actually arrives in: the transport wraps it rather than returning the
// sentinel, so a == comparison would miss every real occurrence.
func TestProxyErrorHandler_WrappedCancellationIsRecognised(t *testing.T) {
	entries := captureLogs(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil)
	proxyErrorHandler(rec, req, &url_Error{Op: "Get", Err: context.Canceled})

	got := entries()
	if len(got) != 1 || got[0]["level"] != "DEBUG" {
		t.Fatalf("wrapped cancellation was not recognised: %v", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want nothing written", rec.Code)
	}
}

// TestProxyErrorHandler_RealFailureStillReports checks the other half: a dead
// backend must keep its error level and its 502, or quieting the noise would
// have quieted the signal with it.
func TestProxyErrorHandler_RealFailureStillReports(t *testing.T) {
	entries := captureLogs(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1.45/containers/json", nil)
	proxyErrorHandler(rec, req, errors.New("dial unix /var/run/docker.sock: connect: connection refused"))

	got := entries()
	if len(got) != 1 {
		t.Fatalf("want one log line, got %d: %v", len(got), got)
	}
	if got[0]["level"] != "ERROR" || got[0]["msg"] != "proxy error" {
		t.Errorf("level/msg = %v/%v, want ERROR/proxy error", got[0]["level"], got[0]["msg"])
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

// TestProxyErrorHandler_RedactsTheOnboardingToken keeps the error path to the
// same rule as the access log: the token is a path segment.
func TestProxyErrorHandler_RedactsTheOnboardingToken(t *testing.T) {
	entries := captureLogs(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/onboard/super-secret", nil)
	proxyErrorHandler(httptest.NewRecorder(), req, errors.New("boom"))

	got := entries()
	if len(got) != 1 || got[0]["path"] != "/api/v1/onboard/<redacted>" {
		t.Fatalf("path = %v, want the token redacted", got)
	}
}

// url_Error is a minimal stand-in for *url.Error: the point is only that the
// handler unwraps rather than compares.
type url_Error struct {
	Op  string
	Err error
}

func (e *url_Error) Error() string { return e.Op + ": " + e.Err.Error() }
func (e *url_Error) Unwrap() error { return e.Err }
