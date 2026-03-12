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
// External Role CRUD Tests
// Tests create/update/delete external role handlers with all permission
// combinations: systemAdmin, serviceManager, serviceAdmin,
// externalRoleHolder, permissionUser, regularUser, anonymous
// ====================================================================

func TestCreateExternalRole(t *testing.T) {
	fix := setupStandardFixtures(t)

	validBody := formatJSON(map[string]interface{}{
		"name":        "test_ext_role",
		"description": "A test external role",
		"permissions": []string{"auth.referal.users.view"},
	})

	tests := []struct {
		name       string
		user       *TestUser // nil = anonymous
		serviceKey string
		body       string
		wantStatus int
		wantJSON   bool // true if expecting JSON response
	}{
		{
			name:       "SystemAdmin_OK",
			user:       fix.SystemAdmin,
			serviceKey: "referal",
			body:       validBody,
			wantStatus: http.StatusOK,
			wantJSON:   true,
		},
		{
			name:       "ServiceManager_OK",
			user:       fix.ServiceManager,
			serviceKey: "referal",
			body: formatJSON(map[string]interface{}{
				"name":        "svcmgr_ext_role",
				"description": "Created by service manager",
				"permissions": []string{"auth.referal.users.view"},
			}),
			wantStatus: http.StatusOK,
			wantJSON:   true,
		},
		{
			name:       "PermissionUser_WithCreate_OK",
			user:       fix.PermissionUser,
			serviceKey: "referal",
			body: formatJSON(map[string]interface{}{
				"name":        "perm_ext_role",
				"description": "Created by permission user",
				"permissions": []string{"auth.referal.users.view"},
			}),
			wantStatus: http.StatusOK,
			wantJSON:   true,
		},
		{
			name:       "ServiceAdmin_Forbidden",
			user:       fix.ServiceAdmin,
			serviceKey: "referal",
			body:       validBody,
			wantStatus: http.StatusForbidden,
			wantJSON:   true,
		},
		{
			name:       "ExternalRoleUser_Forbidden",
			user:       fix.ExternalRoleUser,
			serviceKey: "referal",
			body:       validBody,
			wantStatus: http.StatusForbidden,
			wantJSON:   true,
		},
		{
			name:       "RegularUser_NoAccess",
			user:       fix.RegularUser,
			serviceKey: "referal",
			body:       validBody,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "Anonymous_Redirect",
			user:       nil,
			serviceKey: "referal",
			body:       validBody,
			wantStatus: http.StatusFound, // redirect to login
		},
		{
			name:       "WrongService_ServiceManager",
			user:       fix.ServiceManager,
			serviceKey: "test-svc", // manager for referal, not test-svc
			body: formatJSON(map[string]interface{}{
				"name":        "wrong_svc_role",
				"description": "Wrong service",
				"permissions": []string{"auth.test-svc.users.view"},
			}),
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := performExternalRoleRequest(t, "POST",
				fmt.Sprintf("/services/%s/external-roles", tt.serviceKey),
				tt.body, tt.user)

			if tt.user == nil {
				// Anonymous - expect redirect
				assert.True(t, isRedirectToLogin(recorder) || recorder.Code == http.StatusForbidden,
					"Expected redirect or 403 for anonymous, got %d", recorder.Code)
				return
			}

			assert.Equal(t, tt.wantStatus, recorder.Code,
				"Status mismatch. Body: %s", truncateBody(recorder))

			if tt.wantJSON && tt.wantStatus == http.StatusOK {
				result := parseJSONResponse(recorder)
				require.NotNil(t, result, "Expected JSON response")
				assert.Equal(t, true, result["success"])
			}
		})
	}
}

func TestCreateExternalRole_DuplicateName(t *testing.T) {
	fix := setupStandardFixtures(t)

	body := formatJSON(map[string]interface{}{
		"name":        "dup_role",
		"description": "First creation",
		"permissions": []string{"auth.referal.users.view"},
	})

	// First creation should succeed
	w := performExternalRoleRequest(t, "POST", "/services/referal/external-roles", body, fix.SystemAdmin)
	require.Equal(t, http.StatusOK, w.Code, "First creation should succeed")

	// Second creation with same name should conflict
	w = performExternalRoleRequest(t, "POST", "/services/referal/external-roles", body, fix.SystemAdmin)
	assert.Equal(t, http.StatusConflict, w.Code, "Duplicate should return 409")
}

func TestCreateExternalRole_InvalidPermissionPrefix(t *testing.T) {
	fix := setupStandardFixtures(t)

	// Try to create external role for referal with wrong permission prefix
	body := formatJSON(map[string]interface{}{
		"name":        "bad_prefix_role",
		"description": "Bad prefix",
		"permissions": []string{"auth.other-service.users.view"}, // wrong prefix for referal
	})

	w := performExternalRoleRequest(t, "POST", "/services/referal/external-roles", body, fix.SystemAdmin)
	assert.Equal(t, http.StatusBadRequest, w.Code, "Invalid permission prefix should be rejected")
}

// ====================
// Update External Role
// ====================

func TestUpdateExternalRole(t *testing.T) {
	fix := setupStandardFixtures(t)

	// First, create a role to update
	createBody := formatJSON(map[string]interface{}{
		"name":        "update_target",
		"description": "To be updated",
		"permissions": []string{"auth.referal.users.view"},
	})
	w := performExternalRoleRequest(t, "POST", "/services/referal/external-roles", createBody, fix.SystemAdmin)
	require.Equal(t, http.StatusOK, w.Code, "Setup: create role failed")

	updateBody := formatJSON(map[string]interface{}{
		"description": "Updated description",
		"permissions": []string{"auth.referal.users.view", "auth.referal.users.edit"},
	})

	tests := []struct {
		name       string
		user       *TestUser
		serviceKey string
		roleName   string
		body       string
		wantStatus int
	}{
		{
			name:       "SystemAdmin_OK",
			user:       fix.SystemAdmin,
			serviceKey: "referal",
			roleName:   "update_target",
			body:       updateBody,
			wantStatus: http.StatusOK,
		},
		{
			name:       "ServiceManager_OK",
			user:       fix.ServiceManager,
			serviceKey: "referal",
			roleName:   "update_target",
			body:       updateBody,
			wantStatus: http.StatusOK,
		},
		{
			name:       "PermissionUser_WithEdit_OK",
			user:       fix.PermissionUser,
			serviceKey: "referal",
			roleName:   "update_target",
			body:       updateBody,
			wantStatus: http.StatusOK,
		},
		{
			name:       "ServiceAdmin_Forbidden",
			user:       fix.ServiceAdmin,
			serviceKey: "referal",
			roleName:   "update_target",
			body:       updateBody,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "RegularUser_NoAccess",
			user:       fix.RegularUser,
			serviceKey: "referal",
			roleName:   "update_target",
			body:       updateBody,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "Anonymous_Redirect",
			user:       nil,
			serviceKey: "referal",
			roleName:   "update_target",
			body:       updateBody,
			wantStatus: http.StatusFound,
		},
		{
			name:       "NonExistent_NotFound",
			user:       fix.SystemAdmin,
			serviceKey: "referal",
			roleName:   "nonexistent_role",
			body:       updateBody,
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := performExternalRoleRequest(t, "PUT",
				fmt.Sprintf("/services/%s/external-roles/%s", tt.serviceKey, tt.roleName),
				tt.body, tt.user)

			if tt.user == nil {
				assert.True(t, isRedirectToLogin(w) || w.Code == http.StatusForbidden)
				return
			}

			assert.Equal(t, tt.wantStatus, w.Code,
				"Status mismatch. Body: %s", truncateBody(w))
		})
	}
}

// ====================
// Update External Role — Name Conflict (Regression: 500 → 409)
// ====================

func TestUpdateExternalRole_NameConflict(t *testing.T) {
	fix := setupStandardFixtures(t)

	// Create two external roles
	role1Body := formatJSON(map[string]interface{}{
		"name":        "conflict_role_a",
		"description": "First role",
		"permissions": []string{"auth.referal.users.view"},
	})
	w := performExternalRoleRequest(t, "POST", "/services/referal/external-roles", role1Body, fix.SystemAdmin)
	require.Equal(t, http.StatusOK, w.Code, "Setup: create role A failed")

	role2Body := formatJSON(map[string]interface{}{
		"name":        "conflict_role_b",
		"description": "Second role",
		"permissions": []string{"auth.referal.users.view"},
	})
	w = performExternalRoleRequest(t, "POST", "/services/referal/external-roles", role2Body, fix.SystemAdmin)
	require.Equal(t, http.StatusOK, w.Code, "Setup: create role B failed")

	// Try to rename role A to role B's name — should get 409 Conflict
	renameBody := formatJSON(map[string]interface{}{
		"name":        "conflict_role_b",
		"description": "Attempting rename to existing name",
		"permissions": []string{"auth.referal.users.view"},
	})
	w = performExternalRoleRequest(t, "PUT", "/services/referal/external-roles/conflict_role_a", renameBody, fix.SystemAdmin)
	assert.Equal(t, http.StatusConflict, w.Code,
		"Renaming to existing role name should return 409, not 500. Body: %s", truncateBody(w))

	// Verify response has meaningful error
	result := parseJSONResponse(w)
	require.NotNil(t, result)
	assert.Contains(t, result["error"], "conflict_role_b",
		"Error should mention the conflicting name")
}

func TestUpdateExternalRole_RenameSuccess(t *testing.T) {
	fix := setupStandardFixtures(t)

	// Create a role
	createBody := formatJSON(map[string]interface{}{
		"name":        "rename_me",
		"description": "Will be renamed",
		"permissions": []string{"auth.referal.users.view"},
	})
	w := performExternalRoleRequest(t, "POST", "/services/referal/external-roles", createBody, fix.SystemAdmin)
	require.Equal(t, http.StatusOK, w.Code, "Setup: create role failed")

	// Rename to a new unique name — should succeed
	renameBody := formatJSON(map[string]interface{}{
		"name":        "renamed_ok",
		"description": "Successfully renamed",
		"permissions": []string{"auth.referal.users.view"},
	})
	w = performExternalRoleRequest(t, "PUT", "/services/referal/external-roles/rename_me", renameBody, fix.SystemAdmin)
	assert.Equal(t, http.StatusOK, w.Code,
		"Renaming to a unique name should succeed. Body: %s", truncateBody(w))
}

// ====================
// Delete External Role
// ====================

func TestDeleteExternalRole(t *testing.T) {
	fix := setupStandardFixtures(t)

	tests := []struct {
		name       string
		user       *TestUser
		serviceKey string
		wantStatus int
	}{
		{"SystemAdmin_OK", fix.SystemAdmin, "referal", http.StatusOK},
		{"ServiceManager_OK", fix.ServiceManager, "referal", http.StatusOK},
		{"PermissionUser_OK", fix.PermissionUser, "referal", http.StatusOK},
		{"ServiceAdmin_Forbidden", fix.ServiceAdmin, "referal", http.StatusForbidden},
		{"RegularUser_Forbidden", fix.RegularUser, "referal", http.StatusForbidden},
		{"Anonymous_Redirect", nil, "referal", http.StatusFound},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a unique role for each delete test
			roleName := fmt.Sprintf("del_target_%d", i)
			createBody := formatJSON(map[string]interface{}{
				"name":        roleName,
				"description": "Will be deleted",
				"permissions": []string{"auth.referal.users.view"},
			})
			w := performExternalRoleRequest(t, "POST", "/services/referal/external-roles",
				createBody, fix.SystemAdmin)

			if w.Code != http.StatusOK && w.Code != http.StatusConflict {
				t.Fatalf("Setup: failed to create role for deletion test: %d %s", w.Code, w.Body.String())
			}

			// Attempt deletion
			w = performExternalRoleRequest(t, "DELETE",
				fmt.Sprintf("/services/%s/external-roles/%s", tt.serviceKey, roleName),
				"", tt.user)

			if tt.user == nil {
				assert.True(t, isRedirectToLogin(w) || w.Code == http.StatusForbidden)
				return
			}

			assert.Equal(t, tt.wantStatus, w.Code,
				"Status mismatch. Body: %s", truncateBody(w))
		})
	}
}

func TestDeleteExternalRole_CascadeCleanup(t *testing.T) {
	fix := setupStandardFixtures(t)

	// Create external role
	createBody := formatJSON(map[string]interface{}{
		"name":        "cascade_role",
		"description": "Will be deleted with cascade",
		"permissions": []string{"auth.referal.users.view"},
	})
	w := performExternalRoleRequest(t, "POST", "/services/referal/external-roles", createBody, fix.SystemAdmin)
	require.Equal(t, http.StatusOK, w.Code)

	// Assign it to a user
	assignRole(t, fix.RegularUser.User.ID, "auth", "cascade_role")

	// Verify assignment exists
	roles := getUserServiceRoles(t, fix.RegularUser.User.ID)
	found := false
	for _, r := range roles {
		if r["role_name"] == "cascade_role" {
			found = true
			break
		}
	}
	require.True(t, found, "Role should be assigned before deletion")

	// Delete the role
	w = performExternalRoleRequest(t, "DELETE", "/services/referal/external-roles/cascade_role", "", fix.SystemAdmin)
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify role assignment was cascade-deleted
	roles = getUserServiceRoles(t, fix.RegularUser.User.ID)
	for _, r := range roles {
		assert.NotEqual(t, "cascade_role", r["role_name"],
			"Role assignment should be cascade-deleted")
	}
}

// ====================
// Permission User with Wildcard
// ====================

func TestCreateExternalRole_WildcardPermission(t *testing.T) {
	fix := setupStandardFixtures(t)

	// Create a user with auth.referal.roles.* wildcard
	wildcardUser := createUserWithPermissions(t, "wildcard", []string{
		"auth.referal.roles.*",
		"auth.services.view",
	})

	body := formatJSON(map[string]interface{}{
		"name":        "wildcard_created_role",
		"description": "Created by wildcard permission user",
		"permissions": []string{"auth.referal.users.view"},
	})

	w := performExternalRoleRequest(t, "POST", "/services/referal/external-roles", body, wildcardUser)
	assert.Equal(t, http.StatusOK, w.Code, "Wildcard permission user should be able to create roles")

	_ = fix
}

func TestCreateExternalRole_CrossServiceIsolation(t *testing.T) {
	fix := setupStandardFixtures(t)

	// PermissionUser has auth.referal.roles.create but NOT auth.test-svc.roles.create
	// They should NOT be able to create roles for test-svc
	body := formatJSON(map[string]interface{}{
		"name":        "cross_service_role",
		"description": "Should not work for test-svc",
		"permissions": []string{"auth.test-svc.users.view"},
	})

	w := performExternalRoleRequest(t, "POST", "/services/test-svc/external-roles", body, fix.PermissionUser)
	assert.Equal(t, http.StatusForbidden, w.Code,
		"User with referal permissions should NOT create roles for test-svc")
}

// ====================
// Helper functions
// ====================

func performExternalRoleRequest(t *testing.T, method, path, body string, user *TestUser) *httptest.ResponseRecorder {
	t.Helper()

	if user == nil {
		return performRequest(method, path, body)
	}

	return performRequest(method, path, body, user.Cookie)
}

func truncateBody(w *httptest.ResponseRecorder) string {
	body := w.Body.String()
	if len(body) > 500 {
		return body[:500] + "..."
	}
	return body
}
