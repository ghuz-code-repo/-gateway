package models

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// RoleType constants for distinguishing internal vs external roles
const (
	RoleTypeInternal = "internal" // Internal role: controls access within its own service
	RoleTypeExternal = "external" // External role: defined in auth-service but controls access to another service
)

// Role represents a user role with permissions for a specific service
type Role struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ServiceKey     string             `bson:"service" json:"service" validate:"required"`                 // Foreign key to services.key
	Name           string             `bson:"name" json:"name" validate:"required"`                       // Role name
	Description    string             `bson:"description" json:"description"`                             // Role description
	Permissions    []string           `bson:"permissions" json:"permissions"`                             // Array of permission names (free-form)
	RoleType       string             `bson:"role_type" json:"role_type"`                                 // "internal" or "external" (default: "internal")
	ManagedService string             `bson:"managed_service,omitempty" json:"managed_service,omitempty"` // For external roles: the service key this role manages
	CreatedAt      time.Time          `bson:"createdAt" json:"createdAt"`                                 // Creation timestamp
	UpdatedAt      time.Time          `bson:"updatedAt" json:"updatedAt"`                                 // Update timestamp
	DeletedAt      *time.Time         `bson:"deletedAt,omitempty" json:"deletedAt,omitempty"`             // Soft delete timestamp
}

// IsExternal returns true if this role is an external role (manages another service)
func (r *Role) IsExternal() bool {
	return r.RoleType == RoleTypeExternal
}

// IsInternal returns true if this role is an internal role
func (r *Role) IsInternal() bool {
	return r.RoleType != RoleTypeExternal // default to internal if empty
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
		RoleType:    RoleTypeInternal, // Default to internal
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	log.Printf("DEBUG CreateRole: Inserting role into database: %+v", role)

	result, err := serviceRolesCol.InsertOne(ctx, role)
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

	cursor, err := serviceRolesCol.Find(ctx, bson.M{})
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
	err := serviceRolesCol.FindOne(ctx, bson.M{"name": name}).Decode(&role)
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

	cursor, err := serviceRolesCol.Find(ctx, filter)
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
	err := serviceRolesCol.FindOne(ctx, bson.M{"_id": id}).Decode(&role)
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

	_, err := serviceRolesCol.UpdateOne(
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

	// Delete from service_roles collection (used by UI)
	_, err := serviceRolesCol.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

// GetRolesWithPermission returns all roles that use a specific permission
func GetRolesWithPermission(permission string) ([]Role, error) {
	ctx := context.Background()

	cursor, err := serviceRolesCol.Find(ctx, bson.M{"permissions": permission})
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

	// Search by both "service_key" (new format) and "service" (legacy format)
	cursor, err := serviceRolesCol.Find(ctx, bson.M{
		"$or": []bson.M{
			{"service_key": serviceKey},
			{"service": serviceKey},
		},
	})
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

// GetInternalRolesByService returns only internal roles for a service
// Uses the role_type field to filter (no more hardcoded string parsing)
func GetInternalRolesByService(serviceKey string) ([]Role, error) {
	allRoles, err := GetRolesByService(serviceKey)
	if err != nil {
		return nil, err
	}

	var internalRoles []Role
	for _, role := range allRoles {
		if role.IsInternal() {
			internalRoles = append(internalRoles, role)
		}
	}

	return internalRoles, nil
}

// GetRoleByServiceAndName retrieves a role by service key and name
func GetRoleByServiceAndName(serviceKey, name string) (*Role, error) {
	ctx := context.Background()

	var role Role
	// Use service_roles collection, search by both "service_key" (new) and "service" (legacy)
	err := serviceRolesCol.FindOne(ctx, bson.M{
		"$or": []bson.M{
			{"service_key": serviceKey, "name": name},
			{"service": serviceKey, "name": name},
		},
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

	_, err = serviceRolesCol.UpdateOne(
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

	_, err := serviceRolesCol.UpdateOne(
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
// BSON tags are aligned with Role struct to avoid field mismatch in the shared service_roles collection.
type ServiceRole struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ServiceKey     string             `bson:"service" json:"service_key" validate:"required"`
	Name           string             `bson:"name" json:"name" validate:"required"`
	DisplayName    string             `bson:"display_name" json:"display_name"`
	Description    string             `bson:"description" json:"description"`
	Permissions    []string           `bson:"permissions" json:"permissions"`
	RoleType       string             `bson:"role_type" json:"role_type"`
	ManagedService string             `bson:"managed_service,omitempty" json:"managed_service,omitempty"`
	CreatedAt      time.Time          `bson:"createdAt" json:"created_at"`
	UpdatedAt      time.Time          `bson:"updatedAt" json:"updated_at"`
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

// DeleteServiceRole removes a service role by ID with cascade deletion of role assignments
func DeleteServiceRole(id primitive.ObjectID) error {
	ctx := context.Background()

	log.Printf("INFO: Starting deletion of service role %s", id.Hex())

	// First, get the role to log its details
	var role Role
	err := serviceRolesCol.FindOne(ctx, bson.M{"_id": id}).Decode(&role)
	if err != nil {
		log.Printf("ERROR: Role %s not found: %v", id.Hex(), err)
		return fmt.Errorf("role not found: %w", err)
	}

	// Delete all user assignments of this role
	// We need to match by both service_key and role_name to find assignments
	assignmentResult, err := userServiceRolesCol.DeleteMany(
		ctx,
		bson.M{
			"service_key": role.ServiceKey,
			"role_name":   role.Name,
		},
	)
	if err != nil {
		log.Printf("ERROR: Failed to delete user role assignments for role %s: %v", id.Hex(), err)
		return fmt.Errorf("failed to delete user role assignments: %w", err)
	}
	log.Printf("INFO: Deleted %d user assignments for role '%s' in service '%s'",
		assignmentResult.DeletedCount, role.Name, role.ServiceKey)

	// Delete the role itself
	result, err := serviceRolesCol.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		log.Printf("ERROR: Failed to delete role %s: %v", id.Hex(), err)
		return fmt.Errorf("failed to delete role: %w", err)
	}
	if result.DeletedCount == 0 {
		log.Printf("WARNING: Role %s was not deleted (may have been already deleted)", id.Hex())
	}

	log.Printf("INFO: Successfully deleted service role %s ('%s' in '%s')",
		id.Hex(), role.Name, role.ServiceKey)
	return nil
}

// CreateServiceRole creates a new service role
func CreateServiceRole(role *ServiceRole) error {
	ctx := context.Background()

	// Check if role with same name already exists in the service
	// Search by both "service" (canonical) and "service_key" (legacy) fields
	var existing ServiceRole
	err := serviceRolesCol.FindOne(ctx, bson.M{
		"$or": []bson.M{
			{"service": role.ServiceKey, "name": role.Name},
			{"service_key": role.ServiceKey, "name": role.Name},
		},
	}).Decode(&existing)
	if err == nil {
		return fmt.Errorf("role '%s' already exists in service '%s'", role.Name, role.ServiceKey)
	}

	if role.ID.IsZero() {
		role.ID = primitive.NewObjectID()
	}
	if role.CreatedAt.IsZero() {
		role.CreatedAt = time.Now()
	}
	role.UpdatedAt = time.Now()

	_, err = serviceRolesCol.InsertOne(ctx, role)
	if err != nil {
		return fmt.Errorf("failed to create service role: %w", err)
	}

	return nil
}

// GetServiceRoleByName retrieves a service role by service key and role name
func GetServiceRoleByName(serviceKey, roleName string) (*ServiceRole, error) {
	ctx := context.Background()

	var role ServiceRole
	// Search by both "service_key" (new format) and "service" (legacy format)
	err := serviceRolesCol.FindOne(ctx, bson.M{
		"$or": []bson.M{
			{"service_key": serviceKey, "name": roleName},
			{"service": serviceKey, "name": roleName},
		},
	}).Decode(&role)
	if err != nil {
		return nil, err
	}

	return &role, nil
}

// UpdateServiceRole updates an existing service role
func UpdateServiceRole(role *ServiceRole) error {
	ctx := context.Background()

	role.UpdatedAt = time.Now()

	_, err := serviceRolesCol.UpdateOne(
		ctx,
		bson.M{"_id": role.ID},
		bson.M{
			"$set": bson.M{
				"service":         role.ServiceKey,
				"name":            role.Name,
				"description":     role.Description,
				"permissions":     role.Permissions,
				"role_type":       role.RoleType,
				"managed_service": role.ManagedService,
				"updatedAt":       role.UpdatedAt,
			},
		},
	)

	return err
}

// RemoveRoleFromAllUsers removes a specific role from all users
func RemoveRoleFromAllUsers(serviceKey, roleName string) error {
	ctx := context.Background()

	result, err := userServiceRolesCol.DeleteMany(
		ctx,
		bson.M{
			"service_key": serviceKey,
			"role_name":   roleName,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to remove role assignments: %w", err)
	}

	log.Printf("INFO: Removed role '%s' from %d users in service '%s'",
		roleName, result.DeletedCount, serviceKey)
	return nil
}
