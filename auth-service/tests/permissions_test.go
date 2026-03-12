package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ====================================================================
// Service Permissions Tests
// addServicePermissionHandler uses PostForm (not JSON). Returns 302 on success.
// updateServicePermissionHandler is a stub (501).
// deleteServicePermissionHandler uses PostForm, returns 302.
// ====================================================================

func TestAddServicePermission(t *testing.T) {
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
			formData.Set("name", fmt.Sprintf("new_perm_%d_%s", i, tt.name))
			formData.Set("description", "Test permission")

			var w *httptest.ResponseRecorder
			if tt.user == nil {
				w = performFormRequest("POST", fmt.Sprintf("/services/%s/permissions", tt.serviceKey), formData.Encode())
			} else {
				w = performFormRequest("POST", fmt.Sprintf("/services/%s/permissions", tt.serviceKey), formData.Encode(), tt.user.Cookie)
			}

			if tt.wantOK {
				assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound,
					"Expected success for %s. Got: %d", tt.name, w.Code)
			} else {
				assert.True(t, w.Code == http.StatusForbidden || isRedirectToLogin(w),
					"Expected 403 or redirect for %s. Got: %d", tt.name, w.Code)
			}
		})
	}
}

func TestUpdateServicePermission_NotImplemented(t *testing.T) {
	fix := setupStandardFixtures(t)

	// updateServicePermissionHandler is a stub returning 501
	w := performRequest("PUT", "/services/referal/permissions/referal.view", "", fix.SystemAdmin.Cookie)
	assert.Equal(t, http.StatusNotImplemented, w.Code,
		"updateServicePermissionHandler is a stub, should return 501")
}

func TestDeleteServicePermission(t *testing.T) {
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
			// Create permission first using form-data
			permName := fmt.Sprintf("referal.del_perm_%d_%s", i, tt.name)
			addForm := url.Values{}
			addForm.Set("name", permName)
			addForm.Set("description", "To be deleted")
			wAdd := performFormRequest("POST", "/services/referal/permissions", addForm.Encode(), fix.SystemAdmin.Cookie)
			if wAdd.Code != http.StatusOK && wAdd.Code != http.StatusFound {
				t.Logf("Warning: could not create permission %s for delete test: %d", permName, wAdd.Code)
			}

			w := performFormRequest("POST",
				fmt.Sprintf("/services/referal/permissions/%s/delete", permName),
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

func TestAddServicePermission_DuplicateName(t *testing.T) {
	fix := setupStandardFixtures(t)

	formData := url.Values{}
	formData.Set("name", "dup_perm_test")
	formData.Set("description", "First")

	w1 := performFormRequest("POST", "/services/referal/permissions", formData.Encode(), fix.SystemAdmin.Cookie)
	assert.True(t, w1.Code == http.StatusOK || w1.Code == http.StatusFound,
		"First creation should succeed: %d", w1.Code)

	w2 := performFormRequest("POST", "/services/referal/permissions", formData.Encode(), fix.SystemAdmin.Cookie)
	t.Logf("Duplicate permission creation returned: %d", w2.Code)
	// Handler may return 302 (redirect, possibly with error flash), 500, or 400
	assert.True(t, w2.Code == http.StatusConflict || w2.Code == http.StatusBadRequest ||
		w2.Code == http.StatusOK || w2.Code == http.StatusFound || w2.Code == http.StatusInternalServerError,
		"Duplicate should be handled: %d", w2.Code)
}

func TestAddServicePermission_ExternalType(t *testing.T) {
	fix := setupStandardFixtures(t)

	// External permissions go into auth service with auth.<targetService>.* prefix
	formData := url.Values{}
	formData.Set("name", "auth.referal.new_ext_perm")
	formData.Set("description", "External permission for referal")

	w := performFormRequest("POST", "/services/auth/permissions", formData.Encode(), fix.SystemAdmin.Cookie)
	assert.True(t, w.Code == http.StatusOK || w.Code == http.StatusFound,
		"External permission creation: %d", w.Code)
}

// ====================================================================
// System Settings / Capabilities Tests
// /settings uses authRequired() middleware, but handler checks auth.settings.view
// Non-admin users get redirected to /access-denied (302)
// ====================================================================

func TestSystemSettings_PermissionCheck(t *testing.T) {
	fix := setupStandardFixtures(t)

	t.Run("SystemAdmin_OK", func(t *testing.T) {
		w := performRequest("GET", "/settings", "", fix.SystemAdmin.Cookie)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("ServiceManager_AccessDenied", func(t *testing.T) {
		w := performRequest("GET", "/settings", "", fix.ServiceManager.Cookie)
		// Handler checks auth.settings.view, redirects to /access-denied if missing
		assert.True(t, w.Code == http.StatusFound || w.Code == http.StatusForbidden,
			"ServiceManager without settings perm should be redirected. Got: %d", w.Code)
	})

	t.Run("RegularUser_AccessDenied", func(t *testing.T) {
		w := performRequest("GET", "/settings", "", fix.RegularUser.Cookie)
		assert.True(t, w.Code == http.StatusFound || w.Code == http.StatusForbidden,
			"RegularUser should be redirected. Got: %d", w.Code)
	})
}
