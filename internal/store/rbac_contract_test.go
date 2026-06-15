// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package store

import (
	"context"
	"errors"
	"testing"
)

// rbacTestStore is the union of interfaces the RBAC contract exercises. The
// lockout helpers need both UserStore and RBACStore; all production stores
// (memory, sqlite, postgres) satisfy both.
type rbacTestStore interface {
	UserStore
	RBACStore
}

// testRBACStoreContract exercises the full RBACStore contract plus the shared
// helpers (effective-permission resolution, seeding, migration, lockout). All
// store backends must pass.
func testRBACStoreContract(t *testing.T, newStore func() rbacTestStore) {
	t.Helper()
	ctx := context.Background()

	viewerRule := PermissionRule{Resources: []string{ResourceServices}, Verbs: []string{VerbGet, VerbList}}

	t.Run("CreateGetList", func(t *testing.T) {
		s := newStore()
		r := &Role{Name: "viewer", Rules: []PermissionRule{viewerRule}}
		if err := s.CreateRole(ctx, r); err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
		if r.ID == "" || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() {
			t.Fatal("expected ID/CreatedAt/UpdatedAt to be set")
		}
		got, err := s.GetRole(ctx, "viewer")
		if err != nil {
			t.Fatalf("GetRole: %v", err)
		}
		if len(got.Rules) != 1 || got.Rules[0].Resources[0] != ResourceServices {
			t.Fatalf("rules not round-tripped: %+v", got.Rules)
		}
		roles, err := s.ListRoles(ctx)
		if err != nil {
			t.Fatalf("ListRoles: %v", err)
		}
		if len(roles) != 1 {
			t.Fatalf("got %d roles, want 1", len(roles))
		}
	})

	t.Run("CreateDuplicate", func(t *testing.T) {
		s := newStore()
		if err := s.CreateRole(ctx, &Role{Name: "dup"}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateRole(ctx, &Role{Name: "dup"}); !errors.Is(err, ErrRoleExists) {
			t.Fatalf("got %v, want ErrRoleExists", err)
		}
	})

	t.Run("CreateEmptyName", func(t *testing.T) {
		s := newStore()
		if err := s.CreateRole(ctx, &Role{Name: ""}); !errors.Is(err, ErrRoleNameRequired) {
			t.Fatalf("got %v, want ErrRoleNameRequired", err)
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		s := newStore()
		if _, err := s.GetRole(ctx, "nope"); !errors.Is(err, ErrRoleNotFound) {
			t.Fatalf("got %v, want ErrRoleNotFound", err)
		}
	})

	t.Run("UpdateRole", func(t *testing.T) {
		s := newStore()
		if err := s.CreateRole(ctx, &Role{Name: "r", Rules: []PermissionRule{viewerRule}}); err != nil {
			t.Fatal(err)
		}
		newRules := []PermissionRule{{Resources: []string{ResourceServices}, Verbs: []string{VerbGet, VerbList, VerbCreate}}}
		if err := s.UpdateRole(ctx, &Role{Name: "r", Rules: newRules}); err != nil {
			t.Fatalf("UpdateRole: %v", err)
		}
		got, _ := s.GetRole(ctx, "r")
		if len(got.Rules[0].Verbs) != 3 {
			t.Fatalf("update not persisted: %+v", got.Rules)
		}
	})

	t.Run("UpdateNotFound", func(t *testing.T) {
		s := newStore()
		if err := s.UpdateRole(ctx, &Role{Name: "ghost"}); !errors.Is(err, ErrRoleNotFound) {
			t.Fatalf("got %v, want ErrRoleNotFound", err)
		}
	})

	t.Run("DeleteBuiltin", func(t *testing.T) {
		s := newStore()
		if err := s.CreateRole(ctx, &Role{Name: "admin", Builtin: true}); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteRole(ctx, "admin"); !errors.Is(err, ErrRoleBuiltin) {
			t.Fatalf("got %v, want ErrRoleBuiltin", err)
		}
	})

	t.Run("DeleteInUse", func(t *testing.T) {
		s := newStore()
		if err := s.CreateRole(ctx, &Role{Name: "used"}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateBinding(ctx, &RoleBinding{Username: "alice", RoleName: "used"}); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteRole(ctx, "used"); !errors.Is(err, ErrRoleInUse) {
			t.Fatalf("got %v, want ErrRoleInUse", err)
		}
	})

	t.Run("DeleteRoleSuccess", func(t *testing.T) {
		s := newStore()
		if err := s.CreateRole(ctx, &Role{Name: "tmp"}); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteRole(ctx, "tmp"); err != nil {
			t.Fatalf("DeleteRole: %v", err)
		}
		if _, err := s.GetRole(ctx, "tmp"); !errors.Is(err, ErrRoleNotFound) {
			t.Fatalf("got %v, want ErrRoleNotFound after delete", err)
		}
	})

	t.Run("CreateBindingRoleNotFound", func(t *testing.T) {
		s := newStore()
		if err := s.CreateBinding(ctx, &RoleBinding{Username: "x", RoleName: "absent"}); !errors.Is(err, ErrRoleNotFound) {
			t.Fatalf("got %v, want ErrRoleNotFound", err)
		}
	})

	t.Run("CreateBindingDuplicate", func(t *testing.T) {
		s := newStore()
		if err := s.CreateRole(ctx, &Role{Name: "r"}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateBinding(ctx, &RoleBinding{Username: "u", RoleName: "r"}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateBinding(ctx, &RoleBinding{Username: "u", RoleName: "r"}); !errors.Is(err, ErrBindingExists) {
			t.Fatalf("got %v, want ErrBindingExists", err)
		}
	})

	t.Run("ListBindingsForUser", func(t *testing.T) {
		s := newStore()
		_ = s.CreateRole(ctx, &Role{Name: "r1"})
		_ = s.CreateRole(ctx, &Role{Name: "r2"})
		_ = s.CreateBinding(ctx, &RoleBinding{Username: "alice", RoleName: "r1"})
		_ = s.CreateBinding(ctx, &RoleBinding{Username: "alice", RoleName: "r2"})
		_ = s.CreateBinding(ctx, &RoleBinding{Username: "bob", RoleName: "r1"})
		alice, err := s.ListBindingsForUser(ctx, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if len(alice) != 2 {
			t.Fatalf("got %d bindings for alice, want 2", len(alice))
		}
		all, _ := s.ListBindings(ctx)
		if len(all) != 3 {
			t.Fatalf("got %d total bindings, want 3", len(all))
		}
	})

	t.Run("DeleteBinding", func(t *testing.T) {
		s := newStore()
		_ = s.CreateRole(ctx, &Role{Name: "r"})
		b := &RoleBinding{Username: "u", RoleName: "r"}
		_ = s.CreateBinding(ctx, b)
		if err := s.DeleteBinding(ctx, b.ID); err != nil {
			t.Fatalf("DeleteBinding: %v", err)
		}
		if err := s.DeleteBinding(ctx, b.ID); !errors.Is(err, ErrBindingNotFound) {
			t.Fatalf("got %v, want ErrBindingNotFound", err)
		}
	})

	t.Run("EffectivePermissionsUnion", func(t *testing.T) {
		s := newStore()
		_ = s.CreateRole(ctx, &Role{Name: "a", Rules: []PermissionRule{
			{Resources: []string{ResourceServices}, Verbs: []string{VerbGet}},
		}})
		_ = s.CreateRole(ctx, &Role{Name: "b", Rules: []PermissionRule{
			{Resources: []string{ResourceVolumes}, Verbs: []string{VerbList}},
		}})
		_ = s.CreateBinding(ctx, &RoleBinding{Username: "u", RoleName: "a"})
		_ = s.CreateBinding(ctx, &RoleBinding{Username: "u", RoleName: "b"})
		eff, err := GetEffectivePermissions(ctx, s, "u")
		if err != nil {
			t.Fatal(err)
		}
		if !eff.Allows([]string{ResourceServices}, VerbGet) {
			t.Error("expected services:get allowed")
		}
		if !eff.Allows([]string{ResourceVolumes}, VerbList) {
			t.Error("expected volumes:list allowed")
		}
		if eff.Allows([]string{ResourceSecrets}, VerbGet) {
			t.Error("did not expect secrets:get allowed")
		}
	})

	t.Run("Seed_Idempotent_PreservesEdits", func(t *testing.T) {
		s := newStore()
		if err := SeedDefaultRoles(ctx, s); err != nil {
			t.Fatalf("SeedDefaultRoles: %v", err)
		}
		roles, _ := s.ListRoles(ctx)
		if len(roles) != len(DefaultRoles()) {
			t.Fatalf("got %d seeded roles, want %d", len(roles), len(DefaultRoles()))
		}
		// Edit the viewer role, then re-seed: the edit must survive.
		edited := []PermissionRule{{Resources: []string{ResourceSecrets}, Verbs: []string{VerbGet}}}
		if err := s.UpdateRole(ctx, &Role{Name: RoleViewer, Rules: edited}); err != nil {
			t.Fatal(err)
		}
		if err := SeedDefaultRoles(ctx, s); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetRole(ctx, RoleViewer)
		if len(got.Rules) != 1 || got.Rules[0].Resources[0] != ResourceSecrets {
			t.Fatalf("re-seed clobbered admin edit: %+v", got.Rules)
		}
	})

	t.Run("MigrateLegacyRoles", func(t *testing.T) {
		s := newStore()
		_ = SeedDefaultRoles(ctx, s)
		if err := s.CreateUser(ctx, &User{Username: "adm", Role: "admin"}); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateUser(ctx, &User{Username: "usr", Role: "user"}); err != nil {
			t.Fatal(err)
		}
		if err := MigrateLegacyRoles(ctx, s, s); err != nil {
			t.Fatalf("MigrateLegacyRoles: %v", err)
		}
		admBindings, _ := s.ListBindingsForUser(ctx, "adm")
		if len(admBindings) != 1 || admBindings[0].RoleName != RoleAdmin {
			t.Fatalf("admin user not bound to admin role: %+v", admBindings)
		}
		usrBindings, _ := s.ListBindingsForUser(ctx, "usr")
		if len(usrBindings) != 1 || usrBindings[0].RoleName != RoleOperator {
			t.Fatalf("user not bound to operator role: %+v", usrBindings)
		}
		// Idempotent: running again adds no bindings.
		if err := MigrateLegacyRoles(ctx, s, s); err != nil {
			t.Fatal(err)
		}
		again, _ := s.ListBindingsForUser(ctx, "adm")
		if len(again) != 1 {
			t.Fatalf("migration not idempotent: %d bindings", len(again))
		}
	})

	t.Run("Lockout_DeleteLastAdminBinding", func(t *testing.T) {
		s := newStore()
		_ = SeedDefaultRoles(ctx, s)
		_ = s.CreateUser(ctx, &User{Username: "root", Role: "admin"})
		_ = MigrateLegacyRoles(ctx, s, s)
		bindings, _ := s.ListBindingsForUser(ctx, "root")
		if err := DeleteBindingChecked(ctx, s, s, bindings[0].ID); !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("got %v, want ErrLastAdmin", err)
		}
		// With a second admin, deleting the first is allowed.
		_ = s.CreateUser(ctx, &User{Username: "root2", Role: "admin"})
		_ = MigrateLegacyRoles(ctx, s, s)
		if err := DeleteBindingChecked(ctx, s, s, bindings[0].ID); err != nil {
			t.Fatalf("expected delete to succeed with a second admin, got %v", err)
		}
	})

	t.Run("Lockout_UpdateStripsLastAdmin", func(t *testing.T) {
		s := newStore()
		_ = SeedDefaultRoles(ctx, s)
		_ = s.CreateUser(ctx, &User{Username: "root", Role: "admin"})
		_ = MigrateLegacyRoles(ctx, s, s)
		// Stripping admin's wildcard rule would leave no admin.
		downgrade := &Role{Name: RoleAdmin, Rules: []PermissionRule{viewerRule}}
		if err := UpdateRoleChecked(ctx, s, s, downgrade); !errors.Is(err, ErrLastAdmin) {
			t.Fatalf("got %v, want ErrLastAdmin", err)
		}
	})
}
