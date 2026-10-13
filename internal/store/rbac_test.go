// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import "testing"

func defaultRole(t *testing.T, name string) Role {
	t.Helper()
	for _, r := range DefaultRoles() {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no default role %q", name)
	return Role{}
}

// TestDefaultRoles_Responder pins the responder role to viewer's reads plus
// services:update. Create on services or stacks would switch off the
// scale/restart/rollback limit on its updates (operationalUpdateDenial), and
// exec or port-forward would make it root-equivalent like operator.
func TestDefaultRoles_Responder(t *testing.T) {
	responder := defaultRole(t, RoleResponder)
	if !responder.Builtin {
		t.Error("responder must be builtin")
	}
	r := &EffectivePermissions{Rules: responder.Rules}
	v := &EffectivePermissions{Rules: defaultRole(t, RoleViewer).Rules}

	resources := []string{
		ResourceStacks, ResourceStackLogs, ResourceServices, ResourceNodes,
		ResourceNetworks, ResourceVolumes, ResourceConfigs, ResourceSecrets,
		ResourceExec, ResourcePortForward, ResourceSwarm, ResourceSystem,
		ResourceRoles, ResourceBindings, "unmapped",
	}
	for _, res := range resources {
		for _, verb := range []string{VerbGet, VerbList} {
			if got, want := r.Allows([]string{res}, verb), v.Allows([]string{res}, verb); got != want {
				t.Errorf("%s:%s = %v, viewer has %v", res, verb, got, want)
			}
		}
		for _, verb := range []string{VerbCreate, VerbUpdate, VerbDelete} {
			want := res == ResourceServices && verb == VerbUpdate
			if got := r.Allows([]string{res}, verb); got != want {
				t.Errorf("%s:%s = %v, want %v", res, verb, got, want)
			}
		}
	}
	// The #166 limit is lifted by create on the service or, for a stack-labeled
	// service, on stacks; responder has neither.
	if r.Allows([]string{ResourceServices, ResourceStacks}, VerbCreate) {
		t.Error("responder may create a stack-labeled service")
	}
}

func TestBindingRoleForUserRole(t *testing.T) {
	for role, want := range map[string]string{
		RoleAdmin:     RoleAdmin,
		RoleOperator:  RoleOperator,
		RoleResponder: RoleResponder,
		RoleViewer:    RoleViewer,
		"user":        RoleOperator, // pre-RBAC non-admin
		"":            RoleOperator,
		"wizard":      RoleOperator,
	} {
		if got := bindingRoleForUserRole(role); got != want {
			t.Errorf("bindingRoleForUserRole(%q) = %q, want %q", role, got, want)
		}
	}
}
