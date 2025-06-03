package models

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Permission represents a service permission in the system
type Permission struct {
	ID          primitive.ObjectID `bson:"_id" json:"id"`
	Service     string             `bson:"service" json:"service"`
	DisplayName string             `bson:"display_name" json:"display_name"` // Отображаемое имя сервиса
	Icon        string             `bson:"icon" json:"icon"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}

// CreatePermission creates a new service permission
func CreatePermission(service string, displayName string) error {
	collection := client.Database("authdb").Collection("permissions")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use service name as display name if none provided
	if displayName == "" {
		displayName = service
	}

	// Check if permission already exists
	var existingPermission Permission
	err := collection.FindOne(ctx, bson.M{"service": service}).Decode(&existingPermission)
	if err == nil {
		// Permission already exists
		return fmt.Errorf("permission already exists for service: %s", service)
	}

	// Create new permission
	permission := Permission{
		ID:          primitive.NewObjectID(),
		Service:     service,
		DisplayName: displayName,
		Icon:        "link", // Default icon
		CreatedAt:   time.Now(),
	}

	_, err = collection.InsertOne(ctx, permission)
	if err != nil {
		return fmt.Errorf("failed to create permission: %v", err)
	}

	return nil
}

// GetPermissionByID returns a permission by its ID
func GetPermissionByID(id primitive.ObjectID) (*Permission, error) {
	collection := client.Database("authdb").Collection("permissions")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var permission Permission
	err := collection.FindOne(ctx, bson.M{"_id": id}).Decode(&permission)
	if err != nil {
		return nil, fmt.Errorf("permission not found: %v", err)
	}

	return &permission, nil
}

// GetPermissionByService returns a permission by its service name
func GetPermissionByService(service string) (*Permission, error) {
	collection := client.Database("authdb").Collection("permissions")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var permission Permission
	err := collection.FindOne(ctx, bson.M{"service": service}).Decode(&permission)
	if err != nil {
		return nil, fmt.Errorf("permission not found: %v", err)
	}

	return &permission, nil
}

// UpdatePermissionDisplayName updates the display name of a permission
func UpdatePermissionDisplayName(id primitive.ObjectID, displayName string) error {
	collection := client.Database("authdb").Collection("permissions")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := collection.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"display_name": displayName}},
	)
	if err != nil {
		return fmt.Errorf("failed to update permission display name: %v", err)
	}

	return nil
}

// GetAllPermissions returns all permissions in the system
func GetAllPermissions() ([]Permission, error) {
	collection := client.Database("authdb").Collection("permissions")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("error finding permissions: %v", err)
	}
	defer cursor.Close(ctx)

	var permissions []Permission
	if err = cursor.All(ctx, &permissions); err != nil {
		return nil, fmt.Errorf("error decoding permissions: %v", err)
	}

	return permissions, nil
}

// DeletePermission deletes a permission by ID
func DeletePermission(id primitive.ObjectID) error {
	collection := client.Database("authdb").Collection("permissions")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete permission: %v", err)
	}

	return nil
}

// InitializeDefaultDisplayNames ensures all permissions have proper display names
func InitializeDefaultDisplayNames() {
	defaultDisplayNames := map[string]string{
		"referal":     "Реферальная программа",
		"calculators": "Калькуляторы",
	}

	permissions, err := GetAllPermissions()
	if err != nil {
		fmt.Println("Error loading permissions:", err)
		return
	}

	for _, permission := range permissions {
		if displayName, ok := defaultDisplayNames[permission.Service]; ok {
			if permission.DisplayName != displayName && permission.DisplayName == "" {
				UpdatePermissionDisplayName(permission.ID, displayName)
				fmt.Printf("Updated display name for %s to '%s'\n", permission.Service, displayName)
			}
		}
	}
}

// InitializeDefaultPermissions ensures admin user and role exist
func InitializeDefaultPermissions() {
	// Only ensure the admin role exists, no other hardcoded services

	fmt.Println("Checking for admin role...")

	// Check if admin role exists
	adminRoles, err := GetRolesByName("admin")
	if err != nil || len(adminRoles) == 0 {
		// Create admin role if it doesn't exist
		fmt.Println("Creating admin role...")
		_, err := CreateRole("admin", "Administrator with full access", []string{})
		if err != nil {
			fmt.Printf("Error creating admin role: %v\n", err)
		} else {
			fmt.Println("Admin role created successfully")
		}
	}

	// Check if admin user exists
	adminUser, err := GetUserByUsername("admin")
	if err != nil {
		// Create admin user if it doesn't exist
		fmt.Println("Creating admin user...")
		_, err := CreateUser("admin", "admin@example.com", "admin", "Administrator", []string{"admin"})
		if err != nil {
			fmt.Printf("Error creating admin user: %v\n", err)
		} else {
			fmt.Println("Admin user created successfully")
		}
	} else {
		fmt.Println("Admin user already exists with roles:", adminUser.Roles)
	}
}

// CheckPermission checks if a user has permission for a service
func CheckPermission(userID string, service string) bool {
	// Get user
	user, err := GetUserByID(userID)
	if err != nil {
		return false
	}

	// Admin role always has permission
	for _, roleName := range user.Roles {
		if roleName == "admin" {
			return true
		}
	}

	// For non-admin users, check roles and permissions
	roles, err := GetAllRoles()
	if err != nil {
		return false
	}

	// Check if any of the user's roles grant permission to the service
	for _, roleName := range user.Roles {
		for _, role := range roles {
			if role.Name == roleName {
				for _, perm := range role.Permissions {
					if perm == service {
						return true
					}
				}
			}
		}
	}

	return false
}

// Helper function to get keys from a map
func getMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Helper function to check if a slice contains a string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// GetRolesByName returns roles by name
func GetRolesByName(name string) ([]Role, error) {
	collection := client.Database("authdb").Collection("roles")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var roles []Role
	cursor, err := collection.Find(ctx, bson.M{"name": name})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch roles: %v", err)
	}
	defer cursor.Close(ctx)

	if err = cursor.All(ctx, &roles); err != nil {
		return nil, fmt.Errorf("failed to decode roles: %v", err)
	}

	return roles, nil
}
