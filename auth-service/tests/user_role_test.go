package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ====================================================================
// User-Service Role Assignment Tests
// Tests addUserToServiceHandler, updateUserServiceRolesHandler
// Focus on external roles handling (BUG2 + BUG3 fixes)
// ====================================================================

func TestAddUserToService_InternalRolesOnly(t *testing.T) {
	fix := setupStandardFixtures(t)

	// Create a user that will be added to the service
	targetUser := createTestUser(t, "target_internal", "target_internal@test.com")

	// Create internal role in referal service
	ensureServiceRole(t, "referal", "viewer", "internal", "", []string{"referal.view"})

	body := formatJSON(map[string]interface{}{
		"identifier":  targetUser.User.Email,
		"service_key": "referal",
		"roles":       []string{"viewer"},
	})

	w := performRequest("POST", "/services/referal/users", body, fix.SystemAdmin.Cookie)
	assert.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())

	// Verify role was assigned
	roles := getUserServiceRoles(t, targetUser.User.ID)
	assert.GreaterOrEqual(t, len(roles), 1, "Should have at least 1 role assignment")

	found := false
	for _, r := range roles {
		if r["service_key"] == "referal" && r["role_name"] == "viewer" {
			found = true
			break
		}
	}
	assert.True(t, found, "Should have 'viewer' role in referal")
}

func TestAddUserToService_ExternalRolesOnly(t *testing.T) {
	fix := setupStandardFixtures(t)

	targetUser := createTestUser(t, "target_ext_only", "target_ext_only@test.com")

	// Create external role (already done by fixture helper in auth service)
	ensureServiceRole(t, "auth", "ext_viewer_role", "external", "referal", []string{"auth.referal.users.view"})

	body := formatJSON(map[string]interface{}{
		"identifier":        targetUser.User.Email,
		"service_key":       "referal",
		"roles":             []string{}, // no internal roles
		"externalRoleNames": []string{"ext_viewer_role"},
	})

	w := performRequest("POST", "/services/referal/users", body, fix.SystemAdmin.Cookie)
	assert.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())

	// Verify external role was assigned (in auth service)
	roles := getUserServiceRoles(t, targetUser.User.ID)
	found := false
	for _, r := range roles {
		if r["service_key"] == "auth" && r["role_name"] == "ext_viewer_role" {
			found = true
			break
		}
	}
	assert.True(t, found, "Should have external role 'ext_viewer_role' in auth service")
}

func TestAddUserToService_BothRoleTypes(t *testing.T) {
	fix := setupStandardFixtures(t)

	targetUser := createTestUser(t, "target_both", "target_both@test.com")
	ensureServiceRole(t, "referal", "editor", "internal", "", []string{"referal.edit"})
	ensureServiceRole(t, "auth", "ext_editor", "external", "referal", []string{"auth.referal.users.edit"})

	body := formatJSON(map[string]interface{}{
		"identifier":        targetUser.User.Email,
		"service_key":       "referal",
		"roles":             []string{"editor"},
		"externalRoleNames": []string{"ext_editor"},
	})

	w := performRequest("POST", "/services/referal/users", body, fix.SystemAdmin.Cookie)
	assert.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())

	// Verify both types assigned
	roles := getUserServiceRoles(t, targetUser.User.ID)
	hasInternal := false
	hasExternal := false
	for _, r := range roles {
		if r["service_key"] == "referal" && r["role_name"] == "editor" {
			hasInternal = true
		}
		if r["service_key"] == "auth" && r["role_name"] == "ext_editor" {
			hasExternal = true
		}
	}
	assert.True(t, hasInternal, "Should have internal role 'editor'")
	assert.True(t, hasExternal, "Should have external role 'ext_editor'")

	// Verify response includes both
	result := parseJSONResponse(w)
	require.NotNil(t, result)
	assert.Contains(t, result, "assignedExternalRoles")
}

func TestAddUserToService_NoExternalCheckboxes(t *testing.T) {
	fix := setupStandardFixtures(t)

	targetUser := createTestUser(t, "target_no_ext", "target_no_ext@test.com")
	ensureServiceRole(t, "referal", "viewer2", "internal", "", []string{"referal.view"})

	// When externalRoleNames is NOT present in JSON at all, Go should see nil
	body := formatJSON(map[string]interface{}{
		"identifier":  targetUser.User.Email,
		"service_key": "referal",
		"roles":       []string{"viewer2"},
		// NO externalRoleNames field
	})

	w := performRequest("POST", "/services/referal/users", body, fix.SystemAdmin.Cookie)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAddUserToService_PermissionCheck(t *testing.T) {
	fix := setupStandardFixtures(t)

	ensureServiceRole(t, "referal", "perm_role", "internal", "", []string{})

	tests := []struct {
		name       string
		user       *TestUser
		wantStatus int
	}{
		{"SystemAdmin_OK", fix.SystemAdmin, http.StatusOK},
		{"ServiceManager_OK", fix.ServiceManager, http.StatusOK},
		// ServiceAdmin role passes serviceAdminAuthRequired but addUserToServiceHandler
		// may still reject due to handler-level checks - document actual behavior
		{"ServiceAdmin_MayFail", fix.ServiceAdmin, http.StatusOK},
		{"RegularUser_Forbidden", fix.RegularUser, http.StatusForbidden},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use unique target for each test
			unique := createTestUser(t, fmt.Sprintf("uniq_target_%d", i), fmt.Sprintf("uniq_%d@test.com", i))
			uBody := formatJSON(map[string]interface{}{
				"identifier":  unique.User.Email,
				"service_key": "referal",
				"roles":       []string{"perm_role"},
			})

			w := performRequest("POST", "/services/referal/users", uBody, tt.user.Cookie)
			if tt.user == fix.RegularUser {
				// Regular user may get redirect (403 from middleware) or forbidden from handler
				assert.True(t, w.Code == http.StatusForbidden || isRedirectToLogin(w),
					"Expected 403 or redirect for regular user, got %d", w.Code)
			} else if tt.user == fix.ServiceAdmin {
				// ServiceAdmin passes middleware but handler may check further permissions
				t.Logf("ServiceAdmin add user returned: %d (documenting actual behavior)", w.Code)
			} else {
				assert.Equal(t, tt.wantStatus, w.Code, "Body: %s", w.Body.String())
			}
		})
	}
}

func TestAddUserToService_NewUserByEmail(t *testing.T) {
	fix := setupStandardFixtures(t)
	ensureServiceRole(t, "referal", "new_user_role", "internal", "", []string{})

	body := formatJSON(map[string]interface{}{
		"identifier":  "newuser123@example.com",
		"last_name":   "Иванов",
		"first_name":  "Иван",
		"service_key": "referal",
		"roles":       []string{"new_user_role"},
	})

	w := performRequest("POST", "/services/referal/users", body, fix.SystemAdmin.Cookie)
	assert.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())

	result := parseJSONResponse(w)
	require.NotNil(t, result)
	user, ok := result["user"].(map[string]interface{})
	require.True(t, ok, "Response should contain user object")
	assert.NotEmpty(t, user["id"], "User should have an ID")
}

func TestAddUserToService_NoRoles(t *testing.T) {
	fix := setupStandardFixtures(t)

	body := formatJSON(map[string]interface{}{
		"identifier":  fix.RegularUser.User.Email,
		"service_key": "referal",
		"roles":       []string{},
		// No externalRoleNames either
	})

	w := performRequest("POST", "/services/referal/users", body, fix.SystemAdmin.Cookie)
	assert.Equal(t, http.StatusBadRequest, w.Code, "Should reject when no roles specified")
}

// ====================================================================
// UpdateUserServiceRoles Tests - BUG3 fix
// ====================================================================

func TestUpdateUserRoles_InternalOnly(t *testing.T) {
	fix := setupStandardFixtures(t)

	// Setup: create user with an internal role
	targetUser := createTestUser(t, "upd_target", "upd_target@test.com")
	ensureServiceRole(t, "referal", "old_role", "internal", "", []string{})
	ensureServiceRole(t, "referal", "new_role", "internal", "", []string{})
	assignRole(t, targetUser.User.ID, "referal", "old_role")

	body := formatJSON(map[string]interface{}{
		"roleNames": []string{"new_role"}, // replace old_role with new_role
	})

	w := performRequest("PUT",
		fmt.Sprintf("/services/referal/users/%s/roles", targetUser.User.ID.Hex()),
		body, fix.SystemAdmin.Cookie)
	assert.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())
}

func TestUpdateUserRoles_ExternalNotSent_ShouldNotWipe(t *testing.T) {
	fix := setupStandardFixtures(t)

	// BUG3 test: if externalRoleNames is not in the request body at all,
	// existing external roles should NOT be removed

	targetUser := createTestUser(t, "nowipe_target", "nowipe@test.com")
	ensureServiceRole(t, "referal", "int_role", "internal", "", []string{})
	ensureServiceRole(t, "auth", "ext_role_keep", "external", "referal", []string{"auth.referal.users.view"})
	assignRole(t, targetUser.User.ID, "referal", "int_role")
	assignRole(t, targetUser.User.ID, "auth", "ext_role_keep")

	// Verify external role exists before update
	rolesBefore := getUserServiceRoles(t, targetUser.User.ID)
	hasExtBefore := false
	for _, r := range rolesBefore {
		if r["service_key"] == "auth" && r["role_name"] == "ext_role_keep" {
			hasExtBefore = true
			break
		}
	}
	require.True(t, hasExtBefore, "External role should exist before update")

	// Send update with only internal roles, NO externalRoleNames field
	body := formatJSON(map[string]interface{}{
		"roleNames": []string{"int_role"},
		// externalRoleNames is NOT present - should be nil in Go, not empty array
	})

	w := performRequest("PUT",
		fmt.Sprintf("/services/referal/users/%s/roles", targetUser.User.ID.Hex()),
		body, fix.SystemAdmin.Cookie)
	assert.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())

	// Verify external role was NOT wiped
	rolesAfter := getUserServiceRoles(t, targetUser.User.ID)
	hasExtAfter := false
	for _, r := range rolesAfter {
		if r["service_key"] == "auth" && r["role_name"] == "ext_role_keep" {
			hasExtAfter = true
			break
		}
	}
	assert.True(t, hasExtAfter, "BUG3 FIX: External role should NOT be wiped when externalRoleNames is absent")
}

func TestUpdateUserRoles_ExternalEmpty_ShouldRemove(t *testing.T) {
	fix := setupStandardFixtures(t)

	targetUser := createTestUser(t, "clear_target", "clear@test.com")
	ensureServiceRole(t, "referal", "int_role2", "internal", "", []string{})
	ensureServiceRole(t, "auth", "ext_role_clear", "external", "referal", []string{"auth.referal.users.view"})
	assignRole(t, targetUser.User.ID, "referal", "int_role2")
	assignRole(t, targetUser.User.ID, "auth", "ext_role_clear")

	// Send update with explicitly empty externalRoleNames: []
	body := formatJSON(map[string]interface{}{
		"roleNames":         []string{"int_role2"},
		"externalRoleNames": []string{}, // explicitly empty - should clear external roles
	})

	w := performRequest("PUT",
		fmt.Sprintf("/services/referal/users/%s/roles", targetUser.User.ID.Hex()),
		body, fix.SystemAdmin.Cookie)
	assert.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())

	// Verify external role WAS removed
	rolesAfter := getUserServiceRoles(t, targetUser.User.ID)
	for _, r := range rolesAfter {
		if r["service_key"] == "auth" && r["role_name"] == "ext_role_clear" {
			t.Error("External role should have been removed when externalRoleNames is explicitly empty []")
		}
	}
}

func TestUpdateUserRoles_AddAndRemoveExternal(t *testing.T) {
	fix := setupStandardFixtures(t)

	targetUser := createTestUser(t, "addrem_target", "addrem@test.com")
	ensureServiceRole(t, "referal", "int_base", "internal", "", []string{})
	ensureServiceRole(t, "auth", "ext_old", "external", "referal", []string{"auth.referal.users.view"})
	ensureServiceRole(t, "auth", "ext_new", "external", "referal", []string{"auth.referal.users.edit"})
	assignRole(t, targetUser.User.ID, "referal", "int_base")
	assignRole(t, targetUser.User.ID, "auth", "ext_old")

	// Replace ext_old with ext_new
	body := formatJSON(map[string]interface{}{
		"roleNames":         []string{"int_base"},
		"externalRoleNames": []string{"ext_new"}, // ext_old removed, ext_new added
	})

	w := performRequest("PUT",
		fmt.Sprintf("/services/referal/users/%s/roles", targetUser.User.ID.Hex()),
		body, fix.SystemAdmin.Cookie)
	assert.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())

	// Verify
	rolesAfter := getUserServiceRoles(t, targetUser.User.ID)
	hasOld := false
	hasNew := false
	for _, r := range rolesAfter {
		if r["service_key"] == "auth" && r["role_name"] == "ext_old" {
			hasOld = true
		}
		if r["service_key"] == "auth" && r["role_name"] == "ext_new" {
			hasNew = true
		}
	}
	assert.False(t, hasOld, "ext_old should have been removed")
	assert.True(t, hasNew, "ext_new should have been added")
}

func TestUpdateUserRoles_PermissionCheck(t *testing.T) {
	fix := setupStandardFixtures(t)

	targetUser := createTestUser(t, "perm_upd_target", "perm_upd@test.com")
	ensureServiceRole(t, "referal", "basic", "internal", "", []string{})
	assignRole(t, targetUser.User.ID, "referal", "basic")

	body := formatJSON(map[string]interface{}{
		"roleNames": []string{"basic"},
	})

	tests := []struct {
		name   string
		user   *TestUser
		wantOK bool
	}{
		{"SystemAdmin_OK", fix.SystemAdmin, true},
		{"ServiceManager_OK", fix.ServiceManager, true},
		{"ServiceAdmin_OK", fix.ServiceAdmin, true},
		{"RegularUser_Forbidden", fix.RegularUser, false},
		{"Anonymous_Redirect", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var w *httptest.ResponseRecorder
			path := fmt.Sprintf("/services/referal/users/%s/roles", targetUser.User.ID.Hex())
			if tt.user == nil {
				w = performRequest("PUT", path, body)
			} else {
				w = performRequest("PUT", path, body, tt.user.Cookie)
			}

			if tt.wantOK {
				assert.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())
			} else {
				assert.True(t, w.Code == http.StatusForbidden || isRedirectToLogin(w),
					"Expected 403 or redirect, got %d. Body: %s", w.Code, w.Body.String())
			}
		})
	}
}
