// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package proxylog

import (
	"testing"

	"go.uber.org/zap"
)

func TestParseMode_Dev(t *testing.T) {
	if got := parseMode("dev"); got != "dev" {
		t.Errorf("parseMode(\"dev\") = %q, want %q", got, "dev")
	}
}

func TestParseMode_Development(t *testing.T) {
	if got := parseMode("development"); got != "dev" {
		t.Errorf("parseMode(\"development\") = %q, want %q", got, "dev")
	}
}

func TestParseMode_Prod(t *testing.T) {
	if got := parseMode("prod"); got != "prod" {
		t.Errorf("parseMode(\"prod\") = %q, want %q", got, "prod")
	}
}

func TestParseMode_Empty(t *testing.T) {
	if got := parseMode(""); got != "prod" {
		t.Errorf("parseMode(\"\") = %q, want %q", got, "prod")
	}
}

func TestParseLogLevel_Debug(t *testing.T) {
	if got := parseLogLevel("debug", "prod"); got != zap.DebugLevel {
		t.Errorf("parseLogLevel(\"debug\", \"prod\") = %v, want %v", got, zap.DebugLevel)
	}
}

func TestParseLogLevel_Error(t *testing.T) {
	if got := parseLogLevel("error", "prod"); got != zap.ErrorLevel {
		t.Errorf("parseLogLevel(\"error\", \"prod\") = %v, want %v", got, zap.ErrorLevel)
	}
}

func TestParseLogLevel_Info(t *testing.T) {
	if got := parseLogLevel("info", "dev"); got != zap.InfoLevel {
		t.Errorf("parseLogLevel(\"info\", \"dev\") = %v, want %v", got, zap.InfoLevel)
	}
}

func TestParseLogLevel_DefaultDev(t *testing.T) {
	if got := parseLogLevel("", "dev"); got != zap.DebugLevel {
		t.Errorf("parseLogLevel(\"\", \"dev\") = %v, want %v", got, zap.DebugLevel)
	}
}

func TestParseLogLevel_DefaultProd(t *testing.T) {
	if got := parseLogLevel("", "prod"); got != zap.InfoLevel {
		t.Errorf("parseLogLevel(\"\", \"prod\") = %v, want %v", got, zap.InfoLevel)
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
