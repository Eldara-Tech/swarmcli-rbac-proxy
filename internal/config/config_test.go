package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_JSONOnly(t *testing.T) {
	f := writeJSON(t, `{"listen":":9999","store":"memory","admin_token":"secret"}`)

	cfg, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9999" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":9999")
	}
	if cfg.Store != "memory" {
		t.Errorf("Store = %q, want %q", cfg.Store, "memory")
	}
	if cfg.AdminToken != "secret" {
		t.Errorf("AdminToken = %q, want %q", cfg.AdminToken, "secret")
	}
}

func TestLoad_JSONAllFields(t *testing.T) {
	f := writeJSON(t, `{
		"listen":          ":9999",
		"docker_url":      "tcp://remote:2375",
		"docker_socket":   "/tmp/docker.sock",
		"tls_cert":        "/cert.pem",
		"tls_key":         "/key.pem",
		"tls_client_ca":     "/client-ca.pem",
		"tls_client_ca_key": "/client-ca-key.pem",
		"docker_tls_ca":   "/ca.pem",
		"docker_tls_cert": "/dcert.pem",
		"docker_tls_key":  "/dkey.pem",
		"store":           "memory",
		"database_path":   "/data/proxy.db",
		"database_url":    "postgres://localhost/db",
		"admin_token":     "secret",
		"env":             "dev",
		"log_level":       "debug",
		"agent_proxy_url": "tcp://agent:9090",
		"seed_username":   "admin"
	}`)

	cfg, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name, got, want string
	}{
		{"Listen", cfg.Listen, ":9999"},
		{"DockerURL", cfg.DockerURL, "tcp://remote:2375"},
		{"DockerSocket", cfg.DockerSocket, "/tmp/docker.sock"},
		{"TLSCert", cfg.TLSCert, "/cert.pem"},
		{"TLSKey", cfg.TLSKey, "/key.pem"},
		{"TLSClientCA", cfg.TLSClientCA, "/client-ca.pem"},
		{"TLSClientCAKey", cfg.TLSClientCAKey, "/client-ca-key.pem"},
		{"DockerTLSCA", cfg.DockerTLSCA, "/ca.pem"},
		{"DockerTLSCert", cfg.DockerTLSCert, "/dcert.pem"},
		{"DockerTLSKey", cfg.DockerTLSKey, "/dkey.pem"},
		{"Store", cfg.Store, "memory"},
		{"DatabasePath", cfg.DatabasePath, "/data/proxy.db"},
		{"DatabaseURL", cfg.DatabaseURL, "postgres://localhost/db"},
		{"AdminToken", cfg.AdminToken, "secret"},
		{"Env", cfg.Env, "dev"},
		{"LogLevel", cfg.LogLevel, "debug"},
		{"AgentProxyURL", cfg.AgentProxyURL, "tcp://agent:9090"},
		{"SeedUsername", cfg.SeedUsername, "admin"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestLoad_UnknownJSONKey(t *testing.T) {
	f := writeJSON(t, `{"listen":":9999","UnknownField":"value"}`)

	_, err := Load(f)
	if err == nil {
		t.Fatal("expected error for unknown JSON key")
	}
}

func TestLoad_EnvOverridesJSON(t *testing.T) {
	f := writeJSON(t, `{"listen":":9999","store":"memory"}`)
	t.Setenv("PROXY_LISTEN", ":8888")
	t.Setenv("PROXY_STORE", "postgres")

	cfg, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8888" {
		t.Errorf("Listen = %q, want %q (env override)", cfg.Listen, ":8888")
	}
	if cfg.Store != "postgres" {
		t.Errorf("Store = %q, want %q (env override)", cfg.Store, "postgres")
	}
}

func TestLoad_EmptyPath_EnvOnly(t *testing.T) {
	t.Setenv("PROXY_LISTEN", ":7777")
	t.Setenv("PROXY_STORE", "memory")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":7777" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":7777")
	}
	if cfg.Store != "memory" {
		t.Errorf("Store = %q, want %q", cfg.Store, "memory")
	}
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Store != "sqlite" {
		t.Errorf("Store = %q, want default %q", cfg.Store, "sqlite")
	}
	if cfg.DatabasePath != "proxy.db" {
		t.Errorf("DatabasePath = %q, want default %q", cfg.DatabasePath, "proxy.db")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	f := writeJSON(t, `{invalid}`)

	_, err := Load(f)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoad_AllEnvVars(t *testing.T) {
	envs := map[string]string{
		"PROXY_LISTEN":            ":1111",
		"PROXY_DOCKER_URL":        "tcp://remote:2375",
		"PROXY_DOCKER_SOCKET":     "/tmp/docker.sock",
		"PROXY_TLS_CERT":          "/cert.pem",
		"PROXY_TLS_KEY":           "/key.pem",
		"PROXY_TLS_CLIENT_CA":     "/client-ca.pem",
		"PROXY_TLS_CLIENT_CA_KEY": "/client-ca-key.pem",
		"PROXY_DOCKER_TLS_CA":     "/ca.pem",
		"PROXY_DOCKER_TLS_CERT":   "/dcert.pem",
		"PROXY_DOCKER_TLS_KEY":    "/dkey.pem",
		"PROXY_STORE":             "postgres",
		"PROXY_DATABASE_PATH":     "/data/proxy.db",
		"PROXY_DATABASE_URL":      "postgres://localhost/db",
		"PROXY_ADMIN_TOKEN":       "tok",
		"PROXY_ENV":               "dev",
		"PROXY_LOG_LEVEL":         "debug",
		"PROXY_AGENT_URL":         "tcp://agent:9090",
		"PROXY_SEED_USERNAME":     "admin",
	}
	for k, v := range envs {
		t.Setenv(k, v)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":1111" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.DockerURL != "tcp://remote:2375" {
		t.Errorf("DockerURL = %q", cfg.DockerURL)
	}
	if cfg.DockerSocket != "/tmp/docker.sock" {
		t.Errorf("DockerSocket = %q", cfg.DockerSocket)
	}
	if cfg.TLSCert != "/cert.pem" {
		t.Errorf("TLSCert = %q", cfg.TLSCert)
	}
	if cfg.TLSKey != "/key.pem" {
		t.Errorf("TLSKey = %q", cfg.TLSKey)
	}
	if cfg.TLSClientCA != "/client-ca.pem" {
		t.Errorf("TLSClientCA = %q", cfg.TLSClientCA)
	}
	if cfg.TLSClientCAKey != "/client-ca-key.pem" {
		t.Errorf("TLSClientCAKey = %q", cfg.TLSClientCAKey)
	}
	if cfg.DockerTLSCA != "/ca.pem" {
		t.Errorf("DockerTLSCA = %q", cfg.DockerTLSCA)
	}
	if cfg.DockerTLSCert != "/dcert.pem" {
		t.Errorf("DockerTLSCert = %q", cfg.DockerTLSCert)
	}
	if cfg.DockerTLSKey != "/dkey.pem" {
		t.Errorf("DockerTLSKey = %q", cfg.DockerTLSKey)
	}
	if cfg.Store != "postgres" {
		t.Errorf("Store = %q", cfg.Store)
	}
	if cfg.DatabasePath != "/data/proxy.db" {
		t.Errorf("DatabasePath = %q", cfg.DatabasePath)
	}
	if cfg.DatabaseURL != "postgres://localhost/db" {
		t.Errorf("DatabaseURL = %q", cfg.DatabaseURL)
	}
	if cfg.AdminToken != "tok" {
		t.Errorf("AdminToken = %q", cfg.AdminToken)
	}
	if cfg.Env != "dev" {
		t.Errorf("Env = %q", cfg.Env)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
	if cfg.AgentProxyURL != "tcp://agent:9090" {
		t.Errorf("AgentProxyURL = %q", cfg.AgentProxyURL)
	}
	if cfg.SeedUsername != "admin" {
		t.Errorf("SeedUsername = %q", cfg.SeedUsername)
	}
}

func writeJSON(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
