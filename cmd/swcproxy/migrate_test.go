// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import (
	"testing"

	"swarm-rbac-proxy/internal/config"
)

func TestParseMigrateArgs(t *testing.T) {
	cfg := config.Config{DatabasePath: "proxy.db", DatabaseURL: "postgres://cfg"}

	tests := []struct {
		name       string
		args       []string
		cfg        config.Config
		wantSQLite string
		wantPG     string
		wantForce  bool
		wantErr    bool
	}{
		{
			name:       "defaults from config",
			args:       nil,
			cfg:        cfg,
			wantSQLite: "proxy.db",
			wantPG:     "postgres://cfg",
		},
		{
			name:       "flags override config",
			args:       []string{"--sqlite", "/data/p.db", "--postgres", "postgres://flag", "--force"},
			cfg:        cfg,
			wantSQLite: "/data/p.db",
			wantPG:     "postgres://flag",
			wantForce:  true,
		},
		{
			name:    "missing postgres",
			args:    nil,
			cfg:     config.Config{DatabasePath: "proxy.db"},
			wantErr: true,
		},
		{
			name:    "missing sqlite",
			args:    nil,
			cfg:     config.Config{DatabaseURL: "postgres://cfg"},
			wantErr: true,
		},
		{
			name:    "unknown flag",
			args:    []string{"--bogus"},
			cfg:     cfg,
			wantErr: true,
		},
		{
			name:    "sqlite missing value",
			args:    []string{"--sqlite"},
			cfg:     cfg,
			wantErr: true,
		},
		{
			name:    "postgres missing value",
			args:    []string{"--postgres"},
			cfg:     cfg,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, err := parseMigrateArgs(tt.args, tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got opts %+v", o)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if o.sqlitePath != tt.wantSQLite {
				t.Errorf("sqlitePath = %q, want %q", o.sqlitePath, tt.wantSQLite)
			}
			if o.pgURL != tt.wantPG {
				t.Errorf("pgURL = %q, want %q", o.pgURL, tt.wantPG)
			}
			if o.force != tt.wantForce {
				t.Errorf("force = %v, want %v", o.force, tt.wantForce)
			}
		})
	}
}
