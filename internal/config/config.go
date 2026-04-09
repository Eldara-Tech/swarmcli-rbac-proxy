package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// Config holds all proxy configuration values.
type Config struct {
	Listen         string `json:"listen"`
	DockerURL      string `json:"docker_url"`
	DockerSocket   string `json:"docker_socket"`
	TLSCert        string `json:"tls_cert"`
	TLSKey         string `json:"tls_key"`
	TLSClientCA    string `json:"tls_client_ca"`
	TLSClientCAKey string `json:"tls_client_ca_key"`
	DockerTLSCA    string `json:"docker_tls_ca"`
	DockerTLSCert  string `json:"docker_tls_cert"`
	DockerTLSKey   string `json:"docker_tls_key"`
	Store          string `json:"store"`
	DatabasePath   string `json:"database_path"`
	DatabaseURL    string `json:"database_url"`
	AdminToken     string `json:"admin_token"`
	Env            string `json:"env"`
	LogLevel       string `json:"log_level"`
	AgentProxyURL  string `json:"agent_proxy_url"`
	SeedUsername   string `json:"seed_username"`
	SeedRole       string `json:"seed_role"`
	ExternalURL    string `json:"external_url"`
	InternalListen string `json:"internal_listen"`
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
	{"PROXY_AGENT_URL", func(c *Config) *string { return &c.AgentProxyURL }},
	{"PROXY_SEED_USERNAME", func(c *Config) *string { return &c.SeedUsername }},
	{"PROXY_SEED_ROLE", func(c *Config) *string { return &c.SeedRole }},
	{"PROXY_EXTERNAL_URL", func(c *Config) *string { return &c.ExternalURL }},
	{"PROXY_INTERNAL_LISTEN", func(c *Config) *string { return &c.InternalListen }},
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

	if cfg.Store == "" {
		cfg.Store = "sqlite"
	}
	if cfg.DatabasePath == "" {
		cfg.DatabasePath = "proxy.db"
	}

	return cfg, nil
}
