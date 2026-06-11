// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"errors"
	"time"
)

// PermissionRule grants a set of verbs over a set of resources. A "*" entry in
// either slice is a wildcard that matches everything in that dimension.
type PermissionRule struct {
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

// Role is a named, reusable set of permission rules. Effective permission is
// additive (the union across all rules and all bound roles); there are no deny
// rules. Builtin roles are seeded on startup and cannot be deleted.
type Role struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Rules     []PermissionRule `json:"rules"`
	Builtin   bool             `json:"builtin"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

// RoleBinding associates a username with a role by name.
type RoleBinding struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	RoleName  string    `json:"role_name"`
	CreatedAt time.Time `json:"created_at"`
}

// EffectivePermissions is the flattened union of all rules from the roles a
// user is bound to — the input to an authorization decision.
type EffectivePermissions struct {
	Username string
	Rules    []PermissionRule
}

// RBACStore is the persistence interface for roles and role bindings. Kept
// separate from UserStore (like AuditStore) so each backend implements a clean
// contract block. Referential integrity is enforced at this layer (no DB FKs,
// matching the existing schema style): CreateBinding requires the role to
// exist; DeleteRole refuses a role that bindings still reference.
type RBACStore interface {
	CreateRole(ctx context.Context, r *Role) error
	GetRole(ctx context.Context, name string) (*Role, error)
	ListRoles(ctx context.Context) ([]Role, error)
	UpdateRole(ctx context.Context, r *Role) error
	DeleteRole(ctx context.Context, name string) error

	CreateBinding(ctx context.Context, b *RoleBinding) error
	ListBindings(ctx context.Context) ([]RoleBinding, error)
	ListBindingsForUser(ctx context.Context, username string) ([]RoleBinding, error)
	DeleteBinding(ctx context.Context, id string) error
}

var (
	ErrRoleExists       = errors.New("role already exists")
	ErrRoleNameRequired = errors.New("role name is required")
	ErrRoleNotFound     = errors.New("role not found")
	ErrRoleInUse        = errors.New("role is referenced by a binding")
	ErrRoleBuiltin      = errors.New("builtin role cannot be deleted")
	ErrBindingExists    = errors.New("binding already exists")
	ErrBindingNotFound  = errors.New("binding not found")
	ErrLastAdmin        = errors.New("operation would remove the last admin")
)

// Canonical resource vocabulary. mapRequest (internal/api) maps every request
// to one of these, and the built-in roles below grant verbs over them. Defined
// here (the lowest layer) so both the policy engine and the seeded roles share
// one source of truth.
const (
	ResourceAll         = "*"
	ResourceStacks      = "stacks"
	ResourceStackLogs   = "stack logs"
	ResourceServices    = "services"
	ResourceNodes       = "nodes"
	ResourceNetworks    = "networks"
	ResourceVolumes     = "volumes"
	ResourceConfigs     = "configs"
	ResourceSecrets     = "secrets"
	ResourceExec        = "exec"
	ResourcePortForward = "port-forward"
	ResourceSwarm       = "swarm"
	ResourceSystem      = "system"
	ResourceRoles       = "roles"
	ResourceBindings    = "bindings"
)

// Canonical verbs.
const (
	VerbAll    = "*"
	VerbGet    = "get"
	VerbList   = "list"
	VerbCreate = "create"
	VerbUpdate = "update"
	VerbDelete = "delete"
)

// Built-in role names.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// DefaultRoles returns the three built-in roles. Their rules encode the agreed
// permission matrix; they are seeded idempotently and never overwritten once
// present (an admin may customise them). See the proxy CLAUDE.md for the matrix.
func DefaultRoles() []Role {
	readVerbs := []string{VerbGet, VerbList}
	return []Role{
		{
			Name:    RoleViewer,
			Builtin: true,
			Rules: []PermissionRule{
				{Resources: []string{
					ResourceStacks, ResourceStackLogs, ResourceServices,
					ResourceNodes, ResourceNetworks, ResourceSystem,
				}, Verbs: readVerbs},
			},
		},
		{
			Name:    RoleOperator,
			Builtin: true,
			Rules: []PermissionRule{
				// Inherits viewer's reads, plus volumes/configs reads.
				{Resources: []string{
					ResourceStacks, ResourceStackLogs, ResourceServices,
					ResourceNodes, ResourceNetworks, ResourceSystem,
					ResourceVolumes, ResourceConfigs,
				}, Verbs: readVerbs},
				// Deploy & update stacks/services (no delete → no teardown).
				{Resources: []string{ResourceStacks, ResourceServices}, Verbs: []string{VerbCreate, VerbUpdate}},
				// Interactive access to non-infra workloads (the protected-stack
				// ExecGuard still gates the infra stack on top of this).
				{Resources: []string{ResourceExec, ResourcePortForward}, Verbs: []string{VerbCreate}},
			},
		},
		{
			Name:    RoleAdmin,
			Builtin: true,
			Rules:   []PermissionRule{{Resources: []string{ResourceAll}, Verbs: []string{VerbAll}}},
		},
	}
}

// Allows reports whether the effective permissions grant verb on any of the
// candidate resources. Candidates are OR'd: a labeled (stack) request passes
// {concreteResource, ResourceStacks}, so either permission suffices. Wildcards
// ("*") in a rule's Verbs or Resources match anything. Default-deny: nil perms
// or no matching rule returns false.
func (e *EffectivePermissions) Allows(candidates []string, verb string) bool {
	if e == nil {
		return false
	}
	for _, rule := range e.Rules {
		if !verbMatches(rule.Verbs, verb) {
			continue
		}
		for _, c := range candidates {
			if resourceMatches(rule.Resources, c) {
				return true
			}
		}
	}
	return false
}

func verbMatches(verbs []string, verb string) bool {
	for _, v := range verbs {
		if v == VerbAll || v == verb {
			return true
		}
	}
	return false
}

func resourceMatches(resources []string, resource string) bool {
	for _, r := range resources {
		if r == ResourceAll || r == resource {
			return true
		}
	}
	return false
}

// rulesGrantAdmin reports whether a rule set confers full admin — a single rule
// carrying both the resource and verb wildcard. This is the conservative
// definition used for last-admin lockout protection.
func rulesGrantAdmin(rules []PermissionRule) bool {
	for _, r := range rules {
		if containsWildcard(r.Resources) && containsWildcard(r.Verbs) {
			return true
		}
	}
	return false
}

func containsWildcard(ss []string) bool {
	for _, s := range ss {
		if s == ResourceAll {
			return true
		}
	}
	return false
}

// GetEffectivePermissions resolves a user's bound roles into the flattened
// union of their rules. Dangling bindings (role since deleted) are skipped.
func GetEffectivePermissions(ctx context.Context, rs RBACStore, username string) (*EffectivePermissions, error) {
	bindings, err := rs.ListBindingsForUser(ctx, username)
	if err != nil {
		return nil, err
	}
	eff := &EffectivePermissions{Username: username}
	for _, b := range bindings {
		role, err := rs.GetRole(ctx, b.RoleName)
		if errors.Is(err, ErrRoleNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		eff.Rules = append(eff.Rules, role.Rules...)
	}
	return eff, nil
}

// SeedDefaultRoles creates the built-in roles if they do not already exist. It
// never overwrites an existing role, so admin customisations to a built-in role
// survive restarts. Idempotent.
func SeedDefaultRoles(ctx context.Context, rs RBACStore) error {
	for _, r := range DefaultRoles() {
		if _, err := rs.GetRole(ctx, r.Name); err == nil {
			continue // already present — preserve any edits
		} else if !errors.Is(err, ErrRoleNotFound) {
			return err
		}
		role := r
		if err := rs.CreateRole(ctx, &role); err != nil && !errors.Is(err, ErrRoleExists) {
			return err
		}
	}
	return nil
}

// MigrateLegacyRoles creates a role binding for every user that has none yet,
// derived from the legacy User.Role field (admin → admin, anything else →
// viewer). Idempotent: users that already have a binding are left untouched.
// User.Role is retained as the source for the protected-stack admin gate.
func MigrateLegacyRoles(ctx context.Context, us UserStore, rs RBACStore) error {
	users, err := us.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, u := range users {
		existing, err := rs.ListBindingsForUser(ctx, u.Username)
		if err != nil {
			return err
		}
		if len(existing) > 0 {
			continue
		}
		roleName := RoleViewer
		if u.Role == RoleAdmin {
			roleName = RoleAdmin
		}
		b := &RoleBinding{Username: u.Username, RoleName: roleName}
		if err := rs.CreateBinding(ctx, b); err != nil && !errors.Is(err, ErrBindingExists) {
			return err
		}
	}
	return nil
}

// computeAdmins returns the set of usernames that effectively hold admin,
// optionally applying a role override (use the given Role in place of the
// stored one of the same name) and/or skipping a binding by ID. This lets the
// lockout checks below simulate a mutation without performing it.
func computeAdmins(ctx context.Context, us UserStore, rs RBACStore, override *Role, skipBindingID string) (map[string]bool, error) {
	users, err := us.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	roleCache := map[string]*Role{}
	getRole := func(name string) (*Role, error) {
		if override != nil && override.Name == name {
			return override, nil
		}
		if r, ok := roleCache[name]; ok {
			return r, nil
		}
		r, err := rs.GetRole(ctx, name)
		if err != nil {
			return nil, err
		}
		roleCache[name] = r
		return r, nil
	}
	admins := map[string]bool{}
	for _, u := range users {
		// A disabled user cannot authenticate (RequireClientCert rejects them),
		// so they do not count as a surviving admin for lockout purposes —
		// otherwise the last *enabled* admin's binding could be removed.
		if !u.Enabled {
			continue
		}
		bindings, err := rs.ListBindingsForUser(ctx, u.Username)
		if err != nil {
			return nil, err
		}
		for _, b := range bindings {
			if b.ID == skipBindingID {
				continue
			}
			r, err := getRole(b.RoleName)
			if errors.Is(err, ErrRoleNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if rulesGrantAdmin(r.Rules) {
				admins[u.Username] = true
				break
			}
		}
	}
	return admins, nil
}

// DeleteBindingChecked deletes a binding but refuses (ErrLastAdmin) when doing
// so would leave no user with admin. Use from handlers and the CLI instead of
// the raw store method.
func DeleteBindingChecked(ctx context.Context, us UserStore, rs RBACStore, id string) error {
	admins, err := computeAdmins(ctx, us, rs, nil, id)
	if err != nil {
		return err
	}
	if len(admins) == 0 {
		return ErrLastAdmin
	}
	return rs.DeleteBinding(ctx, id)
}

// UpdateRoleChecked updates a role but refuses (ErrLastAdmin) when the new
// rule set would leave no user with admin.
func UpdateRoleChecked(ctx context.Context, us UserStore, rs RBACStore, r *Role) error {
	admins, err := computeAdmins(ctx, us, rs, r, "")
	if err != nil {
		return err
	}
	if len(admins) == 0 {
		return ErrLastAdmin
	}
	return rs.UpdateRole(ctx, r)
}
