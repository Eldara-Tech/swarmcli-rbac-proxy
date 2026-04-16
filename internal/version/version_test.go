// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package version

import (
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	if Version != "dev" {
		t.Errorf("default Version = %q, want %q", Version, "dev")
	}
	if Commit != "none" {
		t.Errorf("default Commit = %q, want %q", Commit, "none")
	}
	if Date != "unknown" {
		t.Errorf("default Date = %q, want %q", Date, "unknown")
	}
}

func TestString(t *testing.T) {
	s := String()
	if !strings.HasPrefix(s, "swarm-rbac-proxy ") {
		t.Errorf("String() = %q, want prefix %q", s, "swarm-rbac-proxy ")
	}
	for _, want := range []string{Version, Commit, Date} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
}

func TestShort(t *testing.T) {
	if got := Short(); got != Version {
		t.Errorf("Short() = %q, want %q", got, Version)
	}
}
