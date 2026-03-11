package proxylog

import (
	"testing"

	"go.uber.org/zap"
)

func TestDetectMode_Dev(t *testing.T) {
	t.Setenv("PROXY_ENV", "dev")
	if got := detectMode(); got != "dev" {
		t.Errorf("detectMode() = %q, want %q", got, "dev")
	}
}

func TestDetectMode_Development(t *testing.T) {
	t.Setenv("PROXY_ENV", "development")
	if got := detectMode(); got != "dev" {
		t.Errorf("detectMode() = %q, want %q", got, "dev")
	}
}

func TestDetectMode_Prod(t *testing.T) {
	t.Setenv("PROXY_ENV", "prod")
	if got := detectMode(); got != "prod" {
		t.Errorf("detectMode() = %q, want %q", got, "prod")
	}
}

func TestDetectMode_Empty(t *testing.T) {
	t.Setenv("PROXY_ENV", "")
	if got := detectMode(); got != "prod" {
		t.Errorf("detectMode() = %q, want %q", got, "prod")
	}
}

func TestDetectLogLevel_Debug(t *testing.T) {
	t.Setenv("PROXY_LOG_LEVEL", "debug")
	if got := detectLogLevel(); got != zap.DebugLevel {
		t.Errorf("detectLogLevel() = %v, want %v", got, zap.DebugLevel)
	}
}

func TestDetectLogLevel_Error(t *testing.T) {
	t.Setenv("PROXY_LOG_LEVEL", "error")
	if got := detectLogLevel(); got != zap.ErrorLevel {
		t.Errorf("detectLogLevel() = %v, want %v", got, zap.ErrorLevel)
	}
}

func TestDetectLogLevel_DefaultDev(t *testing.T) {
	t.Setenv("PROXY_LOG_LEVEL", "")
	t.Setenv("PROXY_ENV", "dev")
	if got := detectLogLevel(); got != zap.DebugLevel {
		t.Errorf("detectLogLevel() = %v, want %v", got, zap.DebugLevel)
	}
}

func TestDetectLogLevel_DefaultProd(t *testing.T) {
	t.Setenv("PROXY_LOG_LEVEL", "")
	t.Setenv("PROXY_ENV", "prod")
	if got := detectLogLevel(); got != zap.InfoLevel {
		t.Errorf("detectLogLevel() = %v, want %v", got, zap.InfoLevel)
	}
}

func TestL_Uninitialized(t *testing.T) {
	old := logger
	logger = nil
	defer func() { logger = old }()

	l := L()
	if l == nil {
		t.Fatal("L() returned nil, want noop logger")
	}
}

func TestInitTestIfTestLogEnv_NoEnv(t *testing.T) {
	old := logger
	defer func() { logger = old }()

	t.Setenv("TEST_LOG", "")
	InitTestIfTestLogEnv()
	if logger == nil {
		t.Fatal("logger is nil after InitTestIfTestLogEnv, want noop")
	}
}

func TestWith_NilSafe(t *testing.T) {
	var l *ProxyLogger
	got := l.With("key", "value")
	if got == nil {
		t.Fatal("With() on nil returned nil, want noop logger")
	}
}
