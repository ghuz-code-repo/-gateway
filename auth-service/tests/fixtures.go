package tests

import (
	"context"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// TestFixtures holds all test data for a test suite
type TestFixtures struct {
	// Services
	AuthServiceKey    string
	ReferalServiceKey string
	TestServiceKey    string

	// Users
	SystemAdmin      *TestUser
	ServiceManager   *TestUser
	ServiceAdmin     *TestUser
	ExternalRoleUser *TestUser
	RegularUser      *TestUser
	PermissionUser   *TestUser // user with specific auth.referal.roles.create permission
}

// setupStandardFixtures creates a full set of test data for role system tests
func setupStandardFixtures(t *testing.T) *TestFixtures {
	t.Helper()

	cleanAllCollections()

	fix := &TestFixtures{
		AuthServiceKey:    "auth",
		ReferalServiceKey: "referal",
		TestServiceKey:    "test-svc",
	}

	// Create auth service in services collection
	createTestServiceWithExternalPermissions(t, "auth", "Auth Service")

	// Create referal service
	createTestService(t, "referal", "Referal Service")

	// Create another test service
	createTestService(t, "test-svc", "Test Service")

	// Create users with different access levels
	fix.SystemAdmin = createSystemAdmin(t, "fix")
	fix.ServiceManager = createServiceManager(t, "referal", "fix")
	fix.ServiceAdmin = createServiceAdmin(t, "referal", "fix")
	fix.ExternalRoleUser = createExternalRoleHolder(t, "referal", "referal_ext_manager", "fix")
	fix.RegularUser = createRegularUser(t, "fix")
	fix.PermissionUser = createUserWithPermissions(t, "fix", []string{
		"auth.referal.roles.create",
		"auth.referal.roles.edit",
		"auth.referal.roles.delete",
		"auth.referal.users.add",
		"auth.services.view",
	})

	return fix
}

// createTestServiceWithExternalPermissions creates the auth service with external permissions
// that follow the auth.<serviceKey>.* pattern
func createTestServiceWithExternalPermissions(t *testing.T, key, name string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	permissions := []bson.M{
		// Internal auth permissions
		{"name": "auth.users.view", "description": "View users", "external": false},
		{"name": "auth.users.create", "description": "Create users", "external": false},
		{"name": "auth.users.edit", "description": "Edit users", "external": false},
		{"name": "auth.users.delete", "description": "Delete users", "external": false},
		{"name": "auth.users.assign_roles", "description": "Assign roles", "external": false},
		{"name": "auth.users.reset_password", "description": "Reset password", "external": false},
		{"name": "auth.services.view", "description": "View services", "external": false},
		{"name": "auth.services.manage", "description": "Manage services", "external": false},
		{"name": "auth.external_roles.create", "description": "Create external roles", "external": false},
		{"name": "auth.external_roles.edit", "description": "Edit external roles", "external": false},
		{"name": "auth.external_roles.delete", "description": "Delete external roles", "external": false},
		// External permissions for referal
		{"name": "auth.referal.users.view", "description": "View referal users", "external": true},
		{"name": "auth.referal.users.add", "description": "Add referal users", "external": true},
		{"name": "auth.referal.users.edit", "description": "Edit referal users", "external": true},
		{"name": "auth.referal.roles.create", "description": "Create referal roles", "external": true},
		{"name": "auth.referal.roles.edit", "description": "Edit referal roles", "external": true},
		{"name": "auth.referal.roles.delete", "description": "Delete referal roles", "external": true},
		{"name": "auth.referal.roles.*", "description": "All referal role permissions", "external": true},
		// External permissions for test-svc
		{"name": "auth.test-svc.users.view", "description": "View test-svc users", "external": true},
		{"name": "auth.test-svc.roles.create", "description": "Create test-svc roles", "external": true},
	}

	_, err := testDB.Collection("services").InsertOne(ctx, bson.M{
		"_id":                   primitive.NewObjectID(),
		"key":                   key,
		"name":                  name,
		"description":           "Auth service with external permissions",
		"base_url":              "http://auth-service:80",
		"is_active":             true,
		"created_at":            time.Now(),
		"updated_at":            time.Now(),
		"available_permissions": permissions,
	})
	if err != nil {
		t.Fatalf("Failed to create auth service with permissions: %v", err)
	}
}
