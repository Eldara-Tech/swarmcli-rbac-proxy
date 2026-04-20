// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

// User represents a managed user of the proxy.
type User struct {
	ID              string     `json:"id"`
	Username        string     `json:"username"`
	Role            string     `json:"role"`
	Enabled         bool       `json:"enabled"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	OnboardToken    string     `json:"-"`
	TokenIssuedAt   *time.Time `json:"-"`
	TokenConsumedAt *time.Time `json:"-"`
}

// UserStore defines the persistence interface for user management.
type UserStore interface {
	CreateUser(ctx context.Context, u *User) error
	ListUsers(ctx context.Context) ([]User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	DeleteUser(ctx context.Context, username string) error
	SetOnboardToken(ctx context.Context, username string, token string) error
	ConsumeOnboardToken(ctx context.Context, token string) (*User, error)
}

// AuditAction enumerates the auditable actions.
type AuditAction string

const (
	AuditUserCreated      AuditAction = "user.created"
	AuditUserDeleted      AuditAction = "user.deleted"
	AuditCertIssued       AuditAction = "cert.issued"
	AuditOnboardCompleted AuditAction = "onboard.completed"
	AuditGuardBlocked     AuditAction = "guard.blocked"
	AuditTokenRegenerated AuditAction = "token.regenerated"
)

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	ID        string      `json:"id"`
	Timestamp time.Time   `json:"timestamp"`
	Actor     string      `json:"actor"` // username, "system", or "cli"
	Action    AuditAction `json:"action"`
	Resource  string      `json:"resource"`  // e.g. "user:alice", "swarm:leave"
	Status    string      `json:"status"`    // "success" or "denied"
	Detail    string      `json:"detail"`    // optional free-text context
	SourceIP  string      `json:"source_ip"` // client IP or empty for CLI
}

// AuditStore defines the persistence interface for audit logging.
type AuditStore interface {
	RecordAudit(ctx context.Context, e *AuditEntry) error
	ListAuditEntries(ctx context.Context, limit int) ([]AuditEntry, error)
}

var (
	ErrUsernameExists   = errors.New("username already exists")
	ErrUsernameRequired = errors.New("username is required")
	ErrUserNotFound     = errors.New("user not found")
	ErrTokenNotFound    = errors.New("onboard token not found")
	ErrTokenConsumed    = errors.New("onboard token already consumed")
	ErrTokenExpired     = errors.New("onboard token expired")
)

// newUUID generates a UUID v4 using crypto/rand.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
