package tests

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"auth-service/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

const testPassword = "TestPassword123!"

// TestUser holds a test user with their auth cookie
type TestUser struct {
	User   *models.User
	Cookie *http.Cookie
	Token  string
}

// hashedTestPassword pre-computes the bcrypt hash for the test password
var hashedTestPassword string

func init() {
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		panic("failed to hash test password: " + err.Error())
	}
	hashedTestPassword = string(hash)
}

// createTestUser creates a user directly in MongoDB (bypasses email sending)
// and generates a valid JWT cookie for authentication
func createTestUser(t *testing.T, username, email string) *TestUser {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user := &models.User{
		ID:        primitive.NewObjectID(),
		Username:  username,
		Email:     email,
		Password:  hashedTestPassword,
		FullName:  username + " Test",
		LastName:  "Test",
		FirstName: username,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_, err := testDB.Collection("users").InsertOne(ctx, user)
	if err != nil {
		t.Fatalf("Failed to create test user '%s': %v", username, err)
	}

	// Generate JWT token
	token, err := models.GenerateToken(user)
	if err != nil {
		t.Fatalf("Failed to generate token for user '%s': %v", username, err)
	}

	cookie := &http.Cookie{
		Name:  "token",
		Value: token,
	}

	return &TestUser{
		User:   user,
		Cookie: cookie,
		Token:  token,
	}
}

// createSystemAdmin creates a test user with system admin role (auth.GOD)
func createSystemAdmin(t *testing.T, suffix string) *TestUser {
	t.Helper()
	tu := createTestUser(t, "sysadmin_"+suffix, fmt.Sprintf("sysadmin_%s@test.com", suffix))

	// Create the GOD role in auth service if not exists
	ensureServiceRole(t, "auth", "GOD", "internal", "", []string{"auth.*"})

	// Assign GOD role
	assignRole(t, tu.User.ID, "auth", "GOD")

	return tu
}

// createServiceManager creates a test user with service-manager role in the given service
func createServiceManager(t *testing.T, serviceKey, suffix string) *TestUser {
	t.Helper()
	tu := createTestUser(t, "svcmgr_"+suffix, fmt.Sprintf("svcmgr_%s@test.com", suffix))

	// Need at least 1 auth permission to pass adminAuthRequired middleware
	ensureServiceRole(t, "auth", "basic_admin_"+suffix, "internal", "", []string{"auth.services.view"})
	assignRole(t, tu.User.ID, "auth", "basic_admin_"+suffix)

	// Create and assign service-manager role
	ensureServiceRole(t, serviceKey, "service-manager", "internal", "", []string{})
	assignRole(t, tu.User.ID, serviceKey, "service-manager")

	return tu
}

// createServiceAdmin creates a test user with admin role in the given service
func createServiceAdmin(t *testing.T, serviceKey, suffix string) *TestUser {
	t.Helper()
	tu := createTestUser(t, "svcadm_"+suffix, fmt.Sprintf("svcadm_%s@test.com", suffix))

	// Need at least 1 auth permission to pass adminAuthRequired middleware
	ensureServiceRole(t, "auth", "basic_admin_"+suffix, "internal", "", []string{"auth.services.view"})
	assignRole(t, tu.User.ID, "auth", "basic_admin_"+suffix)

	// Create and assign admin role in the service
	ensureServiceRole(t, serviceKey, "admin", "internal", "", []string{})
	assignRole(t, tu.User.ID, serviceKey, "admin")

	return tu
}

// createExternalRoleHolder creates a test user with an external role that manages the given service
func createExternalRoleHolder(t *testing.T, serviceKey, externalRoleName, suffix string) *TestUser {
	t.Helper()
	tu := createTestUser(t, "extuser_"+suffix, fmt.Sprintf("extuser_%s@test.com", suffix))

	// External roles live in auth service but manage another service
	ensureServiceRole(t, "auth", externalRoleName, "external", serviceKey, []string{
		fmt.Sprintf("auth.%s.users.view", serviceKey),
	})
	assignRole(t, tu.User.ID, "auth", externalRoleName)

	return tu
}

// createRegularUser creates an authenticated user with no admin permissions
func createRegularUser(t *testing.T, suffix string) *TestUser {
	t.Helper()
	return createTestUser(t, "regular_"+suffix, fmt.Sprintf("regular_%s@test.com", suffix))
}

// createUserWithPermissions creates a user with specific auth-service permissions
func createUserWithPermissions(t *testing.T, suffix string, permissions []string) *TestUser {
	t.Helper()
	tu := createTestUser(t, "permuser_"+suffix, fmt.Sprintf("permuser_%s@test.com", suffix))

	roleName := "custom_role_" + suffix
	ensureServiceRole(t, "auth", roleName, "internal", "", permissions)
	assignRole(t, tu.User.ID, "auth", roleName)

	return tu
}

// ensureServiceRole creates a service role if it doesn't exist
func ensureServiceRole(t *testing.T, serviceKey, roleName, roleType, managedService string, permissions []string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	col := testDB.Collection("service_roles")

	// Check if already exists
	var existing bson.M
	err := col.FindOne(ctx, bson.M{
		"$or": []bson.M{
			{"service": serviceKey, "name": roleName},
			{"service_key": serviceKey, "name": roleName},
		},
	}).Decode(&existing)
	if err == nil {
		return // Already exists
	}

	role := bson.M{
		"_id":         primitive.NewObjectID(),
		"service":     serviceKey,
		"name":        roleName,
		"description": "Test role: " + roleName,
		"permissions": permissions,
		"role_type":   roleType,
		"createdAt":   time.Now(),
		"updatedAt":   time.Now(),
	}
	if managedService != "" {
		role["managed_service"] = managedService
	}

	_, err = col.InsertOne(ctx, role)
	if err != nil {
		t.Fatalf("Failed to create service role '%s/%s': %v", serviceKey, roleName, err)
	}
}

// assignRole assigns a role to a user in a service
func assignRole(t *testing.T, userID primitive.ObjectID, serviceKey, roleName string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	col := testDB.Collection("user_service_roles")
	_, err := col.InsertOne(ctx, bson.M{
		"_id":         primitive.NewObjectID(),
		"user_id":     userID,
		"service_key": serviceKey,
		"role_name":   roleName,
		"assigned_at": time.Now(),
		"is_active":   true,
	})
	if err != nil {
		t.Fatalf("Failed to assign role '%s/%s' to user %s: %v", serviceKey, roleName, userID.Hex(), err)
	}
}

// createTestService creates a test service directly in MongoDB
func createTestService(t *testing.T, key, name string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	col := testDB.Collection("services")

	// Check if already exists
	var existing bson.M
	err := col.FindOne(ctx, bson.M{"key": key}).Decode(&existing)
	if err == nil {
		return // Already exists
	}

	_, err = col.InsertOne(ctx, bson.M{
		"_id":                   primitive.NewObjectID(),
		"key":                   key,
		"name":                  name,
		"description":           "Test service: " + name,
		"base_url":              "http://test-" + key + ":8080",
		"is_active":             true,
		"created_at":            time.Now(),
		"updated_at":            time.Now(),
		"available_permissions": []bson.M{},
	})
	if err != nil {
		t.Fatalf("Failed to create test service '%s': %v", key, err)
	}
}

// createTestServiceWithPermissions creates a service with predefined permissions
func createTestServiceWithPermissions(t *testing.T, key, name string, permissions []bson.M) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	col := testDB.Collection("services")

	_, err := col.InsertOne(ctx, bson.M{
		"_id":                   primitive.NewObjectID(),
		"key":                   key,
		"name":                  name,
		"description":           "Test service: " + name,
		"base_url":              "http://test-" + key + ":8080",
		"is_active":             true,
		"created_at":            time.Now(),
		"updated_at":            time.Now(),
		"available_permissions": permissions,
	})
	if err != nil {
		t.Fatalf("Failed to create test service '%s' with permissions: %v", key, err)
	}
}

// cleanTestData removes all test data (call between test functions)
func cleanTestData(t *testing.T) {
	t.Helper()
	cleanAllCollections()
}

// getUserServiceRoles gets all active role assignments for a user
func getUserServiceRoles(t *testing.T, userID primitive.ObjectID) []bson.M {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := testDB.Collection("user_service_roles").Find(ctx, bson.M{
		"user_id":   userID,
		"is_active": true,
	})
	if err != nil {
		t.Fatalf("Failed to query user service roles: %v", err)
	}

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		t.Fatalf("Failed to decode user service roles: %v", err)
	}
	return results
}

// countServiceRoles counts roles in a service
func countServiceRoles(t *testing.T, serviceKey string) int {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	count, err := testDB.Collection("service_roles").CountDocuments(ctx, bson.M{
		"service": serviceKey,
	})
	if err != nil {
		t.Fatalf("Failed to count service roles: %v", err)
	}
	return int(count)
}

// getServiceRole retrieves a specific service role
func getServiceRole(t *testing.T, serviceKey, roleName string) bson.M {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result bson.M
	err := testDB.Collection("service_roles").FindOne(ctx, bson.M{
		"service": serviceKey,
		"name":    roleName,
	}).Decode(&result)
	if err != nil {
		return nil
	}
	return result
}
