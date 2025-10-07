package models

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Role represents a user role with permissions for a specific service
type Role struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ServiceKey  string             `bson:"service" json:"service" validate:"required"`       // Foreign key to services.key
	Name        string             `bson:"name" json:"name" validate:"required"`            // Role name
	Description string             `bson:"description" json:"description"`                  // Role description
	Permissions []string           `bson:"permissions" json:"permissions"`                  // Array of permission names (free-form)
	CreatedAt   time.Time          `bson:"createdAt" json:"createdAt"`                      // Creation timestamp
	UpdatedAt   time.Time          `bson:"updatedAt" json:"updatedAt"`                      // Update timestamp
}

// CreateRole creates a new role for a specific service
func CreateRole(serviceKey, name, description string, permissions []string) (*Role, error) {
	ctx := context.Background()

	log.Printf("DEBUG CreateRole: serviceKey=%s, name=%s, permissions=%v", serviceKey, name, permissions)

	// Validate that permissions are valid for the service
	if valid, invalidPerms := ValidateRolePermissions(serviceKey, permissions); !valid {
		log.Printf("ERROR CreateRole: Invalid permissions: %v", invalidPerms)
		return nil, fmt.Errorf("invalid permissions for service %s: %v", serviceKey, invalidPerms)
	}

	log.Printf("DEBUG CreateRole: Permissions validated successfully")

	role := &Role{
		ServiceKey:  serviceKey,
		Name:        name,
		Description: description,
		Permissions: permissions,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	log.Printf("DEBUG CreateRole: Inserting role into database: %+v", role)

	result, err := rolesCol.InsertOne(ctx, role)
	if err != nil {
		log.Printf("ERROR CreateRole: Database insert failed: %v", err)
		return nil, err
	}

	role.ID = result.InsertedID.(primitive.ObjectID)
	log.Printf("SUCCESS CreateRole: Role created with ID: %s", role.ID.Hex())
	return role, nil
}

// GetAllRoles returns all roles
func GetAllRoles() ([]Role, error) {
	ctx := context.Background()

	cursor, err := rolesCol.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []Role
	if err = cursor.All(ctx, &roles); err != nil {
		return nil, err
	}

	return roles, nil
}

// GetRoleByName retrieves a role by its name
func GetRoleByName(name string) (*Role, error) {
	ctx := context.Background()

	var role Role
	err := rolesCol.FindOne(ctx, bson.M{"name": name}).Decode(&role)
	if err != nil {
		return nil, err
	}

	return &role, nil
}

// GetSystemRoles returns only system roles (not service-specific roles)
// Prioritizes roles with service="system" over legacy roles without service field
func GetSystemRoles() ([]Role, error) {
	ctx := context.Background()

	// Find roles that either have no service field (legacy) or have service="system"
	filter := bson.M{
		"$or": []bson.M{
			{"service": bson.M{"$exists": false}}, // Legacy roles without service field
			{"service": ""},                       // Empty service field
			{"service": "system"},                 // Explicitly system roles
		},
	}

	cursor, err := rolesCol.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var allRoles []Role
	if err = cursor.All(ctx, &allRoles); err != nil {
		return nil, err
	}

	// Deduplicate roles by name, prioritizing system service roles
	roleMap := make(map[string]Role)
	
	// First pass: add legacy roles (without service field or empty service)
	for _, role := range allRoles {
		if role.ServiceKey == "" {
			roleMap[role.Name] = role
		}
	}
	
	// Second pass: override with system service roles if they exist (higher priority)
	for _, role := range allRoles {
		if role.ServiceKey == "system" {
			roleMap[role.Name] = role
		}
	}
	
	// Skip non-system roles that have the same name as system roles
	systemRoleNames := make(map[string]bool)
	for _, role := range allRoles {
		if role.ServiceKey == "system" {
			systemRoleNames[role.Name] = true
		}
	}

	// Convert map back to slice
	var roles []Role
	for _, role := range roleMap {
		// Only include if it's a system role or doesn't conflict with system role names
		if role.ServiceKey == "system" || role.ServiceKey == "" {
			roles = append(roles, role)
		}
	}

	return roles, nil
}

// GetRoleByID retrieves a role by ID
func GetRoleByID(id primitive.ObjectID) (*Role, error) {
	ctx := context.Background()

	var role Role
	err := rolesCol.FindOne(ctx, bson.M{"_id": id}).Decode(&role)
	if err != nil {
		return nil, err
	}

	return &role, nil
}

// UpdateRole updates an existing role
func UpdateRole(id primitive.ObjectID, serviceKey, name, description string, permissions []string) error {
	ctx := context.Background()

	// Validate that permissions are valid for the service
	if valid, invalidPerms := ValidateRolePermissions(serviceKey, permissions); !valid {
		return fmt.Errorf("invalid permissions for service %s: %v", serviceKey, invalidPerms)
	}

	_, err := rolesCol.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{
			"$set": bson.M{
				"service":     serviceKey,
				"name":        name,
				"description": description,
				"permissions": permissions,
				"updatedAt":   time.Now(),
			},
		},
	)

	return err
}

// DeleteRole removes a role
func DeleteRole(id primitive.ObjectID) error {
	ctx := context.Background()

	_, err := rolesCol.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

// GetRolesWithPermission returns all roles that use a specific permission
func GetRolesWithPermission(permission string) ([]Role, error) {
	ctx := context.Background()

	cursor, err := rolesCol.Find(ctx, bson.M{"permissions": permission})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []Role
	if err = cursor.All(ctx, &roles); err != nil {
		return nil, err
	}

	return roles, nil
}

// GetRolesByService returns all roles for a specific service
func GetRolesByService(serviceKey string) ([]Role, error) {
	ctx := context.Background()

	cursor, err := rolesCol.Find(ctx, bson.M{"service": serviceKey})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []Role
	if err = cursor.All(ctx, &roles); err != nil {
		return nil, err
	}

	return roles, nil
}

// GetRoleByServiceAndName retrieves a role by service key and name
func GetRoleByServiceAndName(serviceKey, name string) (*Role, error) {
	ctx := context.Background()

	var role Role
	err := rolesCol.FindOne(ctx, bson.M{
		"service": serviceKey,
		"name":    name,
	}).Decode(&role)
	if err != nil {
		return nil, err
	}

	return &role, nil
}

// AddPermissionToRole adds a permission to a role
func AddPermissionToRole(id primitive.ObjectID, permission string) error {
	ctx := context.Background()

	// Get the role to check service
	role, err := GetRoleByID(id)
	if err != nil {
		return err
	}

	// Validate permission for service
	if valid, _ := ValidateRolePermissions(role.ServiceKey, []string{permission}); !valid {
		return fmt.Errorf("permission %s is not valid for service %s", permission, role.ServiceKey)
	}

	_, err = rolesCol.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{
			"$addToSet": bson.M{
				"permissions": permission,
			},
		},
	)

	return err
}

// RemovePermissionFromRole removes a permission from a role
func RemovePermissionFromRole(id primitive.ObjectID, permission string) error {
	ctx := context.Background()

	_, err := rolesCol.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{
			"$pull": bson.M{
				"permissions": permission,
			},
		},
	)

	return err
}

// ServiceRole represents a role specifically for service management
type ServiceRole struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ServiceKey  string             `bson:"service_key" json:"service_key" validate:"required"`
	Name        string             `bson:"name" json:"name" validate:"required"`
	DisplayName string             `bson:"display_name" json:"display_name"`
	Description string             `bson:"description" json:"description"`
	Permissions []string           `bson:"permissions" json:"permissions"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// GetServiceRoleByID retrieves a service role by its ID
func GetServiceRoleByID(id primitive.ObjectID) (*ServiceRole, error) {
	ctx := context.Background()
	
	var role ServiceRole
	err := serviceRolesCol.FindOne(ctx, bson.M{"_id": id}).Decode(&role)
	if err != nil {
		return nil, err
	}
	
	return &role, nil
}

// DeleteServiceRole removes a service role by ID
func DeleteServiceRole(id primitive.ObjectID) error {
	ctx := context.Background()
	
	_, err := serviceRolesCol.DeleteOne(ctx, bson.M{"_id": id})
	return err
}
