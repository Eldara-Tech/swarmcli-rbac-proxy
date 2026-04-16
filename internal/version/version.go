// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package version

import "fmt"

// Build-time variables, set via ldflags:
//
//	-X swarm-rbac-proxy/internal/version.Version={{.Version}}
//	-X swarm-rbac-proxy/internal/version.Commit={{.Commit}}
//	-X swarm-rbac-proxy/internal/version.Date={{.Date}}
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns the full version string.
func String() string {
	return fmt.Sprintf("swarm-rbac-proxy %s (commit: %s, built: %s)", Version, Commit, Date)
}

// Short returns just the version tag.
func Short() string {
	return Version
}
