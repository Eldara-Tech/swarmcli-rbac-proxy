// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import "testing"

func TestParseBackupArgs(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantOut   string
		wantCA    bool
		wantError bool
	}{
		{"no args", nil, "", false, false},
		{"out short", []string{"-o", "b.json"}, "b.json", false, false},
		{"out long", []string{"--out", "b.json"}, "b.json", false, false},
		{"include-ca", []string{"--include-ca"}, "", true, false},
		{"both", []string{"-o", "dr.json", "--include-ca"}, "dr.json", true, false},
		{"missing out value", []string{"-o"}, "", false, true},
		{"unknown flag", []string{"--nope"}, "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, err := parseBackupArgs(tt.args)
			if (err != nil) != tt.wantError {
				t.Fatalf("err = %v, wantError %v", err, tt.wantError)
			}
			if err != nil {
				return
			}
			if o.outFile != tt.wantOut || o.includeCA != tt.wantCA {
				t.Errorf("got %+v, want out=%q ca=%v", o, tt.wantOut, tt.wantCA)
			}
		})
	}
}

func TestResolveBackupOutput(t *testing.T) {
	tests := []struct {
		name    string
		outFile string
		isTTY   bool
		want    outputMode
	}{
		{"explicit -o wins over tty", "b.json", true, outputFile},
		{"explicit -o wins over pipe", "b.json", false, outputFile},
		{"tty, no -o → default dir", "", true, outputDefaultDir},
		{"pipe, no -o → stdout", "", false, outputStdout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveBackupOutput(tt.outFile, tt.isTTY); got != tt.want {
				t.Errorf("resolveBackupOutput(%q, %v) = %d, want %d", tt.outFile, tt.isTTY, got, tt.want)
			}
		})
	}
}

func TestParseRestoreArgs(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantIn    string
		wantForce bool
		wantCAOut string
		wantError bool
	}{
		{"no args", nil, "", false, "", false},
		{"in short", []string{"-i", "b.json"}, "b.json", false, "", false},
		{"force", []string{"--force"}, "", true, "", false},
		{"ca-out", []string{"--ca-out", "/tmp/ca"}, "", false, "/tmp/ca", false},
		{"all", []string{"-i", "b.json", "--force", "--ca-out", "/tmp/ca"}, "b.json", true, "/tmp/ca", false},
		{"missing in value", []string{"--in"}, "", false, "", true},
		{"missing ca-out value", []string{"--ca-out"}, "", false, "", true},
		{"unknown flag", []string{"-x"}, "", false, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, err := parseRestoreArgs(tt.args)
			if (err != nil) != tt.wantError {
				t.Fatalf("err = %v, wantError %v", err, tt.wantError)
			}
			if err != nil {
				return
			}
			if o.inFile != tt.wantIn || o.force != tt.wantForce || o.caOut != tt.wantCAOut {
				t.Errorf("got %+v, want in=%q force=%v caOut=%q", o, tt.wantIn, tt.wantForce, tt.wantCAOut)
			}
		})
	}
}

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
