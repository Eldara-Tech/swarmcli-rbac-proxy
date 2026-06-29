// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"errors"
	"sync"
	"time"
)

// adminMu serializes the last-admin lockout-sensitive mutations below
// (Delete/SetUserEnabled/SetUserRole/DeleteBinding/UpdateRole *Checked). Each
// reads the current admin set via computeAdmins and then mutates; without
// serialization two concurrent management requests can each observe a surviving
// admin and both proceed, racing the count to zero (a TOCTOU that defeats the
// lockout guarantee). The proxy runs as a single replica against a single store
// (see stack.yml), so a process-level lock fully closes the window; a
// multi-replica deployment would instead need store-level row locking.
var adminMu sync.Mutex

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
// operator). operator (not viewer) is the non-admin default so an upgraded
// legacy user keeps the non-protected create/update/exec they had under the
// pre-RBAC model; viewer is a stricter, read-only tier an admin assigns
// explicitly. Idempotent: users that already have a binding are left untouched.
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
		roleName := RoleOperator
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
	adminMu.Lock()
	defer adminMu.Unlock()
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
	adminMu.Lock()
	defer adminMu.Unlock()
	admins, err := computeAdmins(ctx, us, rs, r, "")
	if err != nil {
		return err
	}
	if len(admins) == 0 {
		return ErrLastAdmin
	}
	return rs.UpdateRole(ctx, r)
}

// UserIsAdmin reports whether the user's effective permissions confer full
// admin (the *,* wildcard). This is the authorization predicate for the
// user/role/binding management plane — an mTLS-authenticated caller may manage
// users iff this returns true. Kept consistent with the lockout definition
// (rulesGrantAdmin) so "who may manage" and "who counts for lockout" never
// diverge. The Enabled axis that computeAdmins applies is already guaranteed
// for callers here: RequireClientCert (internal/api/mtls.go) rejects a disabled
// user's certificate upstream, so this predicate only ever runs for an enabled
// identity.
func UserIsAdmin(ctx context.Context, rs RBACStore, username string) (bool, error) {
	eff, err := GetEffectivePermissions(ctx, rs, username)
	if err != nil {
		return false, err
	}
	return rulesGrantAdmin(eff.Rules), nil
}

// bindingRoleForUserRole maps a legacy User.Role value to the RBAC role a user
// should be bound to, matching MigrateLegacyRoles / cmdUserAdd: admin → admin,
// an explicit built-in (operator/viewer) → itself, and any other value (the
// legacy "user") → operator.
func bindingRoleForUserRole(role string) string {
	switch role {
	case RoleAdmin, RoleOperator, RoleViewer:
		return role
	default:
		return RoleOperator
	}
}

// CreateUserWithBinding creates a user and a matching RBAC role binding in one
// step, keeping the legacy User.Role and the RBAC binding in sync (the
// invariant the protected-stack admin gate and the RBAC engine both rely on).
// Used by both the HTTP create handler and the swcproxy CLI so the two paths
// cannot drift. Returns the created user with ID/timestamps populated.
func CreateUserWithBinding(ctx context.Context, us UserStore, rs RBACStore, username, role string) (*User, error) {
	u := &User{Username: username, Role: role}
	if err := us.CreateUser(ctx, u); err != nil {
		return nil, err
	}
	bind := &RoleBinding{Username: username, RoleName: bindingRoleForUserRole(role)}
	if err := rs.CreateBinding(ctx, bind); err != nil && !errors.Is(err, ErrBindingExists) {
		// Roll back the user so a binding failure cannot strand a binding-less
		// (default-deny) account that would also block recreation under the same
		// name. Best-effort: a failed rollback is no worse than the prior state.
		_ = us.DeleteUser(ctx, username)
		return nil, err
	}
	return u, nil
}

// DeleteUserChecked deletes a user, cascading their role bindings, but refuses
// (ErrLastAdmin) when doing so would leave no enabled admin. Replaces the raw
// store DeleteUser in handlers/CLI so a user deletion can never orphan bindings
// or strip the last admin (the bare store method does neither).
func DeleteUserChecked(ctx context.Context, us UserStore, rs RBACStore, username string) error {
	adminMu.Lock()
	defer adminMu.Unlock()
	admins, err := computeAdmins(ctx, us, rs, nil, "")
	if err != nil {
		return err
	}
	delete(admins, username) // simulate the removal
	if len(admins) == 0 {
		return ErrLastAdmin
	}
	// Cascade bindings first: the worst case on a partial failure is a user with
	// no bindings (default-deny), never an orphaned binding granting access.
	bindings, err := rs.ListBindingsForUser(ctx, username)
	if err != nil {
		return err
	}
	for _, b := range bindings {
		if err := rs.DeleteBinding(ctx, b.ID); err != nil && !errors.Is(err, ErrBindingNotFound) {
			return err
		}
	}
	return us.DeleteUser(ctx, username)
}

// SetUserEnabledChecked toggles a user's enabled flag but refuses
// (ErrLastAdmin) when disabling would leave no enabled admin (a disabled user
// cannot authenticate, so it must not be the last one standing). Enabling is
// always allowed.
func SetUserEnabledChecked(ctx context.Context, us UserStore, rs RBACStore, username string, enabled bool) error {
	adminMu.Lock()
	defer adminMu.Unlock()
	if !enabled {
		admins, err := computeAdmins(ctx, us, rs, nil, "")
		if err != nil {
			return err
		}
		delete(admins, username)
		if len(admins) == 0 {
			return ErrLastAdmin
		}
	}
	return us.SetUserEnabled(ctx, username, enabled)
}

// SetUserRoleChecked changes a user's role, keeping the legacy User.Role and
// the RBAC binding in sync (all existing bindings are replaced by a single
// binding to the new role). It refuses (ErrLastAdmin) when the change would
// leave no enabled admin, and (ErrRoleNotFound) when the target role does not
// exist.
func SetUserRoleChecked(ctx context.Context, us UserStore, rs RBACStore, username, role string) error {
	adminMu.Lock()
	defer adminMu.Unlock()
	newRole, err := rs.GetRole(ctx, role)
	if err != nil {
		return err
	}
	u, err := us.GetUserByUsername(ctx, username)
	if err != nil {
		return err
	}
	// Replacing all of this user's bindings with the single new role means they
	// hold admin iff the new role grants it and they are enabled.
	admins, err := computeAdmins(ctx, us, rs, nil, "")
	if err != nil {
		return err
	}
	if u.Enabled && rulesGrantAdmin(newRole.Rules) {
		admins[username] = true
	} else {
		delete(admins, username)
	}
	if len(admins) == 0 {
		return ErrLastAdmin
	}
	// Create the new binding before removing the old ones so a partial failure
	// leaves the user with an extra binding (default-deny-safe) rather than a
	// binding-less account — i.e. it errs toward retained access, never lockout.
	// Idempotent if a binding to this role already exists.
	if err := rs.CreateBinding(ctx, &RoleBinding{Username: username, RoleName: role}); err != nil && !errors.Is(err, ErrBindingExists) {
		return err
	}
	if err := us.SetUserRole(ctx, username, role); err != nil {
		return err
	}
	existing, err := rs.ListBindingsForUser(ctx, username)
	if err != nil {
		return err
	}
	for _, b := range existing {
		if b.RoleName == role {
			continue // keep the (new) target-role binding
		}
		if err := rs.DeleteBinding(ctx, b.ID); err != nil && !errors.Is(err, ErrBindingNotFound) {
			return err
		}
	}
	return nil
}
