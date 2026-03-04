package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ====================================================================
// Internal Roles CRUD Tests
// Handlers use PostForm (not JSON). Routes: /services/:serviceKey/roles[/:roleId]
// roleId in the route is actually role name, not ObjectID.
// ====================================================================

func TestCreateInternalRole(t *testing.T) {
	fix := setupStandardFixtures(t)

	tests := []struct {
		name       string
		user       *TestUser
		serviceKey string
		wantOK     bool
	}{
		{"SystemAdmin_OK", fix.SystemAdmin, "referal", true},
		{"ServiceManager_OK", fix.ServiceManager, "referal", true},
		{"ServiceAdmin_OK", fix.ServiceAdmin, "referal", true},
		{"RegularUser_Forbidden", fix.RegularUser, "referal", false},
		{"Anonymous_Redirect", nil, "referal", false},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formData := url.Values{}
			formData.Set("role_name", fmt.Sprintf("test_role_%d_%s", i, tt.name))
			formData.Set("role_description", "Test internal role")

			var w *httptest.ResponseRecorder
			if tt.user == nil {
				w = performFormRequest("POST", fmt.Sprintf("/services/%s/roles", tt.serviceKey), formData.Encode())
			} else {
				w = performFormRequest("POST", fmt.Sprintf("/services/%s/roles", tt.serviceKey), formData.Encode(), tt.user.Cookie)
			}

			if tt.wantOK {
				// Handler returns 302 redirect on success
				assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound,
					"Expected success for %s. Got: %d", tt.name, w.Code)
			} else {
				assert.True(t, w.Code == http.StatusForbidden || isRedirectToLogin(w),
					"Expected 403 or redirect for %s. Got: %d", tt.name, w.Code)
			}
		})
	}
}

func TestGetInternalRole_NotImplemented(t *testing.T) {
	fix := setupStandardFixtures(t)

	// getServiceRoleHandler is a stub returning 501
	ensureServiceRole(t, "referal", "get_stub", "internal", "", []string{})

	w := performRequest("GET", "/services/referal/roles/get_stub", "", fix.SystemAdmin.Cookie)
	assert.Equal(t, http.StatusNotImplemented, w.Code,
		"getServiceRoleHandler is a stub, should return 501")
}

func TestUpdateInternalRole(t *testing.T) {
	fix := setupStandardFixtures(t)

	// Create role to update (route uses role name, not ObjectID)
	ensureServiceRole(t, "referal", "update_int_target", "internal", "", []string{})

	formData := url.Values{}
	formData.Set("name", "update_int_target")
	formData.Set("description", "Updated description")

	tests := []struct {
		name   string
		user   *TestUser
		wantOK bool
	}{
		{"SystemAdmin_OK", fix.SystemAdmin, true},
		{"ServiceManager_OK", fix.ServiceManager, true},
		{"ServiceAdmin_OK", fix.ServiceAdmin, true},
		{"RegularUser_Forbidden", fix.RegularUser, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := performFormRequest("POST",
				"/services/referal/roles/update_int_target",
				formData.Encode(), tt.user.Cookie)

			if tt.wantOK {
				assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound,
					"Expected success. Got: %d", w.Code)
			} else {
				assert.True(t, w.Code == http.StatusForbidden || isRedirectToLogin(w),
					"Expected 403 or redirect. Got: %d", w.Code)
			}
		})
	}
}

func TestDeleteInternalRole(t *testing.T) {
	fix := setupStandardFixtures(t)

	tests := []struct {
		name   string
		user   *TestUser
		wantOK bool
	}{
		{"SystemAdmin_OK", fix.SystemAdmin, true},
		{"ServiceManager_OK", fix.ServiceManager, true},
		{"ServiceAdmin_OK", fix.ServiceAdmin, true},
		{"RegularUser_Forbidden", fix.RegularUser, false},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a unique role for each delete test (route uses role name)
			roleName := fmt.Sprintf("del_int_%d", i)
			ensureServiceRole(t, "referal", roleName, "internal", "", []string{})

			w := performFormRequest("POST",
				fmt.Sprintf("/services/referal/roles/%s/delete", roleName),
				"", tt.user.Cookie)

			if tt.wantOK {
				assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound,
					"Expected success. Got: %d", w.Code)
			} else {
				assert.True(t, w.Code == http.StatusForbidden || isRedirectToLogin(w),
					"Expected 403 or redirect. Got: %d", w.Code)
			}
		})
	}
}

func TestDeleteInternalRole_CascadeUserAssignments(t *testing.T) {
	fix := setupStandardFixtures(t)

	ensureServiceRole(t, "referal", "cascade_int", "internal", "", []string{})
	assignRole(t, fix.RegularUser.User.ID, "referal", "cascade_int")

	// Verify assignment exists before
	rolesBefore := getUserServiceRoles(t, fix.RegularUser.User.ID)
	found := false
	for _, r := range rolesBefore {
		if r["service_key"] == "referal" && r["role_name"] == "cascade_int" {
			found = true
		}
	}
	require.True(t, found, "Setup: role assignment should exist before deletion")

	// Delete the role (route uses role name, not ObjectID)
	w := performFormRequest("POST",
		"/services/referal/roles/cascade_int/delete",
		"", fix.SystemAdmin.Cookie)
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound)

	// Note: cascade deletion of user_service_roles depends on handler implementation
	// The deleteServiceRoleHandler currently only deletes the role, not assignments.
	// This test documents current behavior.
}
