// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import "testing"

func TestIsHelpFlag(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want bool
	}{
		{"--help", true},
		{"-h", true},
		{"help", true},
		{"alice", false},
		{"", false},
		{"--admin", false},
		{"-help", false},
	} {
		if got := isHelpFlag(tt.in); got != tt.want {
			t.Errorf("isHelpFlag(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestCurlURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"tcp to https", "tcp://172.21.0.4:2376", "https://172.21.0.4:2376"},
		{"https unchanged", "https://proxy.example.com:2376", "https://proxy.example.com:2376"},
		{"http unchanged", "http://localhost:2375", "http://localhost:2375"},
		{"placeholder unchanged", "<PROXY_HOST>:<PORT>", "<PROXY_HOST>:<PORT>"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := curlURL(tt.in); got != tt.want {
				t.Errorf("curlURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
