// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// DefaultOnboardingTokenTTL is the default lifetime for newly issued
// onboarding tokens when PROXY_ONBOARDING_TOKEN_TTL is unset. Leaked
// tokens in wikis, CI logs, or chat stop being usable after this window.
const DefaultOnboardingTokenTTL = 24 * time.Hour

// Config holds all proxy configuration values.
type Config struct {
	Listen          string `json:"listen"`
	DockerURL       string `json:"docker_url"`
	DockerSocket    string `json:"docker_socket"`
	TLSCert         string `json:"tls_cert"`
	TLSKey          string `json:"tls_key"`
	TLSClientCA     string `json:"tls_client_ca"`
	TLSClientCAKey  string `json:"tls_client_ca_key"`
	DockerTLSCA     string `json:"docker_tls_ca"`
	DockerTLSCert   string `json:"docker_tls_cert"`
	DockerTLSKey    string `json:"docker_tls_key"`
	Store           string `json:"store"`
	DatabasePath    string `json:"database_path"`
	DatabaseURL     string `json:"database_url"`
	AdminToken      string `json:"admin_token"`
	Env             string `json:"env"`
	LogLevel        string `json:"log_level"`
	AgentManagerURL string `json:"agent_manager_url"`
	SeedUsername    string `json:"seed_username"`
	SeedRole        string `json:"seed_role"`
	ExternalURL     string `json:"external_url"`
	InternalListen  string `json:"internal_listen"`
	ProtectedStack  string `json:"protected_stack"`

	// OnboardingTokenTTL is the expiry window for newly issued onboarding
	// tokens. Zero is interpreted as DefaultOnboardingTokenTTL after Load.
	// Must be strictly positive after defaults are applied; Load returns
	// an error on non-positive values.
	OnboardingTokenTTL time.Duration `json:"onboarding_token_ttl"`
}

// envOverrides maps Config fields to their environment variable names.
var envOverrides = []struct {
	key  string
	dest func(*Config) *string
}{
	{"PROXY_LISTEN", func(c *Config) *string { return &c.Listen }},
	{"PROXY_DOCKER_URL", func(c *Config) *string { return &c.DockerURL }},
	{"PROXY_DOCKER_SOCKET", func(c *Config) *string { return &c.DockerSocket }},
	{"PROXY_TLS_CERT", func(c *Config) *string { return &c.TLSCert }},
	{"PROXY_TLS_KEY", func(c *Config) *string { return &c.TLSKey }},
	{"PROXY_TLS_CLIENT_CA", func(c *Config) *string { return &c.TLSClientCA }},
	{"PROXY_TLS_CLIENT_CA_KEY", func(c *Config) *string { return &c.TLSClientCAKey }},
	{"PROXY_DOCKER_TLS_CA", func(c *Config) *string { return &c.DockerTLSCA }},
	{"PROXY_DOCKER_TLS_CERT", func(c *Config) *string { return &c.DockerTLSCert }},
	{"PROXY_DOCKER_TLS_KEY", func(c *Config) *string { return &c.DockerTLSKey }},
	{"PROXY_STORE", func(c *Config) *string { return &c.Store }},
	{"PROXY_DATABASE_PATH", func(c *Config) *string { return &c.DatabasePath }},
	{"PROXY_DATABASE_URL", func(c *Config) *string { return &c.DatabaseURL }},
	{"PROXY_ADMIN_TOKEN", func(c *Config) *string { return &c.AdminToken }},
	{"PROXY_ENV", func(c *Config) *string { return &c.Env }},
	{"PROXY_LOG_LEVEL", func(c *Config) *string { return &c.LogLevel }},
	{"PROXY_AGENT_MANAGER_URL", func(c *Config) *string { return &c.AgentManagerURL }},
	{"PROXY_SEED_USERNAME", func(c *Config) *string { return &c.SeedUsername }},
	{"PROXY_SEED_ROLE", func(c *Config) *string { return &c.SeedRole }},
	{"PROXY_EXTERNAL_URL", func(c *Config) *string { return &c.ExternalURL }},
	{"PROXY_INTERNAL_LISTEN", func(c *Config) *string { return &c.InternalListen }},
	{"PROXY_PROTECTED_STACK", func(c *Config) *string { return &c.ProtectedStack }},
}

// Load reads configuration from an optional JSON file, then applies
// environment variable overrides (env vars always win), then fills defaults.
func Load(path string) (Config, error) {
	var cfg Config

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config file: %w", err)
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return cfg, fmt.Errorf("parse config file: %w", err)
		}
	}

	for _, ov := range envOverrides {
		if v := os.Getenv(ov.key); v != "" {
			*ov.dest(&cfg) = v
		}
	}

	if v := os.Getenv("PROXY_ONBOARDING_TOKEN_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("parse PROXY_ONBOARDING_TOKEN_TTL %q: %w", v, err)
		}
		if d <= 0 {
			return cfg, fmt.Errorf("PROXY_ONBOARDING_TOKEN_TTL must be a positive duration, got %q", v)
		}
		cfg.OnboardingTokenTTL = d
	}

	if cfg.Store == "" {
		cfg.Store = "sqlite"
	}
	if cfg.DatabasePath == "" {
		cfg.DatabasePath = "proxy.db"
	}
	if cfg.OnboardingTokenTTL == 0 {
		cfg.OnboardingTokenTTL = DefaultOnboardingTokenTTL
	}
	if cfg.OnboardingTokenTTL < 0 {
		return cfg, fmt.Errorf("onboarding_token_ttl must be a positive duration, got %s", cfg.OnboardingTokenTTL)
	}

	return cfg, nil
}
