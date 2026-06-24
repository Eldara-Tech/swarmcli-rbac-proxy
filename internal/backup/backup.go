// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

// Package backup assembles and serialises the logical backup artifact shared
// by the swcproxy CLI (`backup`/`restore`) and the proxy server's
// /startbackup endpoint. It is a portable JSON export of users + audit log
// (and, CLI-only, an optional CA bundle), independent of the storage backend.
package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"swarm-rbac-proxy/internal/config"
	"swarm-rbac-proxy/internal/store"
)

// Schema and Version identify the artifact format. restore refuses any
// document whose schema or version it does not recognise.
const (
	Schema  = "swarmcli-rbac-proxy/backup"
	Version = 1
)

// User mirrors store.User but with explicit JSON tags for the
// onboarding-token fields, which store.User marks json:"-".
type User struct {
	ID              string     `json:"id"`
	Username        string     `json:"username"`
	Role            string     `json:"role"`
	Enabled         bool       `json:"enabled"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	OnboardToken    string     `json:"onboard_token,omitempty"`
	TokenIssuedAt   *time.Time `json:"token_issued_at,omitempty"`
	TokenConsumedAt *time.Time `json:"token_consumed_at,omitempty"`
}

// CA carries the client CA cert+key for one-file disaster recovery. It is only
// ever populated by the CLI's opt-in --include-ca; the server endpoint never
// embeds it.
type CA struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// Doc is the top-level backup artifact.
type Doc struct {
	Schema       string             `json:"schema"`
	Version      int                `json:"version"`
	CreatedAt    time.Time          `json:"created_at"`
	ProxyVersion string             `json:"proxy_version"`
	Users        []User             `json:"users"`
	Audit        []store.AuditEntry `json:"audit"`
	CA           *CA                `json:"ca,omitempty"`
}

// Create exports users + audit entries from the store and assembles a
// CA-less backup document stamped with createdAt and proxyVersion. Callers
// that want a DR bundle set Doc.CA afterwards.
func Create(ctx context.Context, bs store.BackupStore, proxyVersion string, createdAt time.Time) (*Doc, error) {
	users, err := bs.ExportUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("export users: %w", err)
	}
	entries, err := bs.ExportAuditEntries(ctx)
	if err != nil {
		return nil, fmt.Errorf("export audit log: %w", err)
	}
	return &Doc{
		Schema:       Schema,
		Version:      Version,
		CreatedAt:    createdAt,
		ProxyVersion: proxyVersion,
		Users:        ToUsers(users),
		Audit:        entries,
	}, nil
}

// Marshal renders the document as indented JSON with a trailing newline.
func Marshal(doc *Doc) ([]byte, error) {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal backup: %w", err)
	}
	return append(data, '\n'), nil
}

// DefaultDir derives the default backup directory from the DB path so backups
// land on the same persistent volume (e.g. /data/proxy.db → /data/backup). For
// non-file backends (postgres) it falls back to ./backup.
func DefaultDir(cfg config.Config) string {
	dir := filepath.Dir(cfg.DatabasePath)
	if dir == "" || cfg.DatabasePath == "" {
		dir = "."
	}
	return filepath.Join(dir, "backup")
}

// Filename is the default basename for a backup written to a directory,
// derived from the document's creation time (UTC).
func Filename(t time.Time) string {
	return fmt.Sprintf("swc-proxy-backup-%s.json", t.UTC().Format("20060102-150405"))
}

// WriteToDir marshals doc and writes it into dir (created 0700 if absent) under
// the default Filename, mode 0600. It returns the full path written.
func WriteToDir(dir string, doc *Doc) (string, error) {
	data, err := Marshal(doc)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create backup dir %s: %w", dir, err)
	}
	path := filepath.Join(dir, Filename(doc.CreatedAt))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// ToUsers converts store users into their backup representation.
func ToUsers(users []store.User) []User {
	out := make([]User, len(users))
	for i, u := range users {
		out[i] = User{
			ID: u.ID, Username: u.Username, Role: u.Role, Enabled: u.Enabled,
			CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
			OnboardToken: u.OnboardToken, TokenIssuedAt: u.TokenIssuedAt,
			TokenConsumedAt: u.TokenConsumedAt,
		}
	}
	return out
}

// FromUsers converts backup users back into store users.
func FromUsers(users []User) []store.User {
	out := make([]store.User, len(users))
	for i, u := range users {
		out[i] = store.User{
			ID: u.ID, Username: u.Username, Role: u.Role, Enabled: u.Enabled,
			CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
			OnboardToken: u.OnboardToken, TokenIssuedAt: u.TokenIssuedAt,
			TokenConsumedAt: u.TokenConsumedAt,
		}
	}
	return out
}
