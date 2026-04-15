// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package api

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"swarm-rbac-proxy/internal/certauth"
	"swarm-rbac-proxy/internal/store"
)

// OnboardHandler handles GET /api/v1/onboard/{token}.
// It consumes the one-time token, issues a client certificate, and returns
// a Docker-context-compatible tar archive.
type OnboardHandler struct {
	store       store.UserStore
	ca          *certauth.CA
	externalURL string
}

// NewOnboardHandler creates an onboard handler.
func NewOnboardHandler(s store.UserStore, ca *certauth.CA, externalURL string) *OnboardHandler {
	return &OnboardHandler{store: s, ca: ca, externalURL: externalURL}
}

func (h *OnboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	token := r.PathValue("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}

	u, err := h.store.ConsumeOnboardToken(r.Context(), token)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrTokenNotFound):
			writeError(w, http.StatusNotFound, "invalid token")
		case errors.Is(err, store.ErrTokenConsumed):
			writeError(w, http.StatusGone, "token already consumed")
		default:
			l().Errorw("consume token failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	if h.ca == nil {
		l().Errorw("onboard called but CA not configured")
		writeError(w, http.StatusServiceUnavailable, "certificate authority not configured")
		return
	}

	certPEM, keyPEM, err := h.ca.IssueCert(u.Username)
	if err != nil {
		l().Errorw("cert issuance failed", "error", err, "username", u.Username)
		writeError(w, http.StatusInternalServerError, "certificate generation failed")
		return
	}

	tarData, err := buildContextTar(u.Username, h.externalURL, h.ca.CACertPEM(), certPEM, keyPEM)
	if err != nil {
		l().Errorw("tar build failed", "error", err, "username", u.Username)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	l().Infow("onboard completed", "username", u.Username)
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", "attachment; filename="+u.Username+".tar")
	_, _ = w.Write(tarData)
}

// contextMeta matches the Docker context export format.
type contextMeta struct {
	Name      string                     `json:"Name"`
	Metadata  contextMetadata            `json:"Metadata"`
	Endpoints map[string]contextEndpoint `json:"Endpoints"`
}

type contextMetadata struct {
	Description string `json:"Description"`
}

type contextEndpoint struct {
	Host          string `json:"Host"`
	SkipTLSVerify bool   `json:"SkipTLSVerify"`
}

// buildContextTar creates a Docker-context-compatible tar archive.
func buildContextTar(username, externalURL string, caPEM, certPEM, keyPEM []byte) ([]byte, error) {
	meta := contextMeta{
		Name: username + "-managed",
		Metadata: contextMetadata{
			Description: "SwarmCLI managed context for " + username,
		},
		Endpoints: map[string]contextEndpoint{
			"docker": {
				Host:          externalURL,
				SkipTLSVerify: false,
			},
		},
	}

	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	files := []struct {
		name string
		data []byte
	}{
		{"meta.json", metaJSON},
		{"tls/docker/ca.pem", caPEM},
		{"tls/docker/cert.pem", certPEM},
		{"tls/docker/key.pem", keyPEM},
	}

	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: f.name,
			Size: int64(len(f.data)),
			Mode: 0600,
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
