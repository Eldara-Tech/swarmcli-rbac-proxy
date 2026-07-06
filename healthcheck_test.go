// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthProbe(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	if err := healthProbe(ok.URL + "/_swc/version"); err != nil {
		t.Fatalf("healthy probe: got %v, want nil", err)
	}

	unavail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unavail.Close()
	if err := healthProbe(unavail.URL + "/_swc/version"); err == nil {
		t.Fatal("unhealthy probe: got nil, want error")
	}

	// Nothing listening on port 1.
	if err := healthProbe("http://127.0.0.1:1/_swc/version"); err == nil {
		t.Fatal("refused probe: got nil, want error")
	}
}
