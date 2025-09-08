package models

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// PermissionDef represents a permission definition with metadata
type PermissionDef struct {
	Name        string    `bson:"name" json:"name"`                              // Permission identifier (e.g., "users.read")
	DisplayName string    `bson:"displayName" json:"displayName"`               // Human-readable name
	Description string    `bson:"description" json:"description"`               // Description of what this permission allows
	DeletedAt   time.Time `bson:"deletedAt,omitempty" json:"deletedAt,omitempty"` // Soft delete timestamp
}

// Service represents a service with its master permission list
type Service struct {
	ID                   primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Key                  string             `bson:"key" json:"key" validate:"required"`                          // e.g. "referal"
	Name                 string             `bson:"name" json:"name"`                                            // Display name
	Description          string             `bson:"description" json:"description"`                             // Service description
	AvailablePermissions []PermissionDef    `bson:"availablePermissions" json:"availablePermissions"`           // Canonical list of permissions
	Status               string             `bson:"status" json:"status"`                                        // active, deprecated, disabled
	CreatedAt            time.Time          `bson:"created_at" json:"created_at"`                               // Creation timestamp
	UpdatedAt            time.Time          `bson:"updated_at" json:"updated_at"`                               // Update timestamp
	
	// Legacy field for backward compatibility - will be removed after migration
	Permissions []string `bson:"permissions,omitempty" json:"permissions,omitempty"`
}

// CreateService creates a new service with the new schema
func CreateService(key, name, description string, availablePermissions []PermissionDef) (*Service, error) {
	ctx := context.Background()

	service := &Service{
		Key:                  key,
		Name:                 name,
		Description:          description,
		AvailablePermissions: availablePermissions,
		Status:               "active",
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	result, err := servicesCol.InsertOne(ctx, service)
	if err != nil {
		return nil, err
	}

	service.ID = result.InsertedID.(primitive.ObjectID)
	return service, nil
}

// CreateServiceLegacy creates a service using legacy permission format (for migration purposes)
func CreateServiceLegacy(key, name, description string, permissions []string) (*Service, error) {
	ctx := context.Background()

	// Convert legacy permissions to new format
	availablePermissions := make([]PermissionDef, len(permissions))
	for i, perm := range permissions {
		availablePermissions[i] = PermissionDef{
			Name:        perm,
			DisplayName: strings.Title(perm),
			Description: fmt.Sprintf("Permission to %s", perm),
		}
	}

	service := &Service{
		Key:                  key,
		Name:                 name,
		Description:          description,
		AvailablePermissions: availablePermissions,
		Status:               "active",
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
		Permissions:          permissions, // Keep for backward compatibility
	}

	result, err := servicesCol.InsertOne(ctx, service)
	if err != nil {
		return nil, err
	}

	service.ID = result.InsertedID.(primitive.ObjectID)
	return service, nil
}

// GetAllServices returns all services
func GetAllServices() ([]Service, error) {
	ctx := context.Background()

	cursor, err := servicesCol.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var services []Service
	if err = cursor.All(ctx, &services); err != nil {
		return nil, err
	}

	return services, nil
}

// GetServiceByID retrieves a service by ID
func GetServiceByID(id primitive.ObjectID) (*Service, error) {
	ctx := context.Background()

	var service Service
	err := servicesCol.FindOne(ctx, bson.M{"_id": id}).Decode(&service)
	if err != nil {
		return nil, err
	}

	return &service, nil
}

// GetServiceByKey retrieves a service by its key
func GetServiceByKey(key string) (*Service, error) {
	ctx := context.Background()

	var service Service
	err := servicesCol.FindOne(ctx, bson.M{"key": key}).Decode(&service)
	if err != nil {
		return nil, err
	}

	return &service, nil
}

// UpdateService updates an existing service with new schema
func UpdateService(id primitive.ObjectID, key, name, description string, availablePermissions []PermissionDef) error {
	ctx := context.Background()

	_, err := servicesCol.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{
			"$set": bson.M{
				"key":                  key,
				"name":                 name,
				"description":          description,
				"availablePermissions": availablePermissions,
				"updated_at":           time.Now(),
			},
		},
	)

	return err
}

// UpdateServiceLegacy updates a service using legacy format (for migration purposes)
func UpdateServiceLegacy(id primitive.ObjectID, key, name, description string, permissions []string) error {
	ctx := context.Background()

	// Convert legacy permissions to new format
	availablePermissions := make([]PermissionDef, len(permissions))
	for i, perm := range permissions {
		availablePermissions[i] = PermissionDef{
			Name:        perm,
			DisplayName: strings.Title(perm),
			Description: fmt.Sprintf("Permission to %s", perm),
		}
	}

	_, err := servicesCol.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{
			"$set": bson.M{
				"key":                  key,
				"name":                 name,
				"description":          description,
				"availablePermissions": availablePermissions,
				"permissions":          permissions, // Keep for backward compatibility
				"updated_at":           time.Now(),
			},
		},
	)

	return err
}

// DeleteService removes a service
func DeleteService(id primitive.ObjectID) error {
	ctx := context.Background()

	_, err := servicesCol.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

// AddPermissionToService adds a new permission to a service (new schema)
func AddPermissionToService(serviceKey string, permissionDef PermissionDef) error {
	ctx := context.Background()

	_, err := servicesCol.UpdateOne(
		ctx,
		bson.M{"key": serviceKey},
		bson.M{
			"$addToSet": bson.M{
				"availablePermissions": permissionDef,
			},
			"$set": bson.M{
				"updated_at": time.Now(),
			},
		},
	)

	return err
}

// AddPermissionToServiceLegacy adds a permission using legacy format (for migration)
func AddPermissionToServiceLegacy(serviceKey string, permission string) error {
	ctx := context.Background()

	// Add to both new and legacy fields
	permissionDef := PermissionDef{
		Name:        permission,
		DisplayName: strings.Title(permission),
		Description: fmt.Sprintf("Permission to %s", permission),
	}

	_, err := servicesCol.UpdateOne(
		ctx,
		bson.M{"key": serviceKey},
		bson.M{
			"$addToSet": bson.M{
				"permissions":          permission,
				"availablePermissions": permissionDef,
			},
			"$set": bson.M{
				"updated_at": time.Now(),
			},
		},
	)

	return err
}

// RemovePermissionFromService removes a permission from a service (soft delete)
func RemovePermissionFromService(serviceKey string, permissionName string) error {
	ctx := context.Background()

	// Mark permission as deleted instead of removing it
	_, err := servicesCol.UpdateOne(
		ctx,
		bson.M{
			"key": serviceKey,
			"availablePermissions.name": permissionName,
		},
		bson.M{
			"$set": bson.M{
				"availablePermissions.$.deletedAt": time.Now(),
				"updated_at":                       time.Now(),
			},
		},
	)

	return err
}

// GetServicePermissions returns available permissions for a service
func GetServicePermissions(serviceKey string) ([]PermissionDef, error) {
	service, err := GetServiceByKey(serviceKey)
	if err != nil {
		return nil, err
	}

	// Filter out deleted permissions
	activePermissions := make([]PermissionDef, 0)
	for _, perm := range service.AvailablePermissions {
		// Check if permission has deletedAt field (means it's deleted)
		if perm.DeletedAt.IsZero() {
			activePermissions = append(activePermissions, perm)
		}
	}

	return activePermissions, nil
}

// ValidateRolePermissions checks if all permissions in a role are valid for a service
func ValidateRolePermissions(serviceKey string, permissions []string) (bool, []string) {
	service, err := GetServiceByKey(serviceKey)
	if err != nil {
		return false, []string{"service not found"}
	}

	// Get active permissions
	activePermissions := make(map[string]bool)
	for _, perm := range service.AvailablePermissions {
		if perm.DeletedAt.IsZero() { // Only active permissions
			activePermissions[perm.Name] = true
		}
	}

	// Also check legacy permissions for backward compatibility
	for _, perm := range service.Permissions {
		activePermissions[perm] = true
	}

	// Check which permissions are invalid
	var invalidPerms []string
	for _, perm := range permissions {
		if !activePermissions[perm] {
			invalidPerms = append(invalidPerms, perm)
		}
	}

	return len(invalidPerms) == 0, invalidPerms
}

// GetUserServicePermissions returns all permissions a user has for a specific service
func GetUserServicePermissions(userID, serviceKey string) ([]string, error) {
	user, err := GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	// Admin users have all permissions
	for _, roleName := range user.Roles {
		if roleName == "admin" {
			service, err := GetServiceByKey(serviceKey)
			if err != nil {
				return []string{}, nil // Return empty if service not found
			}
			
			// Return all active permissions for admin
			allPerms := make([]string, 0)
			for _, perm := range service.AvailablePermissions {
				if perm.DeletedAt.IsZero() {
					allPerms = append(allPerms, perm.Name)
				}
			}
			
			// Also include legacy permissions
			for _, perm := range service.Permissions {
				allPerms = append(allPerms, perm)
			}
			
			// Remove duplicates
			permMap := make(map[string]bool)
			uniquePerms := make([]string, 0)
			for _, perm := range allPerms {
				if !permMap[perm] {
					permMap[perm] = true
					uniquePerms = append(uniquePerms, perm)
				}
			}
			
			return uniquePerms, nil
		}
	}

	// For regular users, collect permissions from roles
	roles, err := GetRolesByService(serviceKey)
	if err != nil {
		return []string{}, nil
	}

	permissionSet := make(map[string]bool)
	
	// Check each role the user has
	for _, roleName := range user.Roles {
		for _, role := range roles {
			if role.Name == roleName {
				for _, perm := range role.Permissions {
					permissionSet[perm] = true
				}
			}
		}
	}

	// Convert set to slice
	permissions := make([]string, 0, len(permissionSet))
	for perm := range permissionSet {
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// GetUserServiceRoles returns all role names a user has for a specific service
func GetUserServiceRoles(userID, serviceKey string) ([]string, error) {
	user, err := GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	// For admin users, return admin role if it exists in the service
	for _, roleName := range user.Roles {
		if roleName == "admin" {
			// Check if admin role exists for this service
			_, err := GetRoleByServiceAndName(serviceKey, "admin")
			if err == nil {
				return []string{"admin"}, nil
			}
			// If no admin role for this service, return empty
			return []string{}, nil
		}
	}

	// Get all roles for the service
	serviceRoles, err := GetRolesByService(serviceKey)
	if err != nil {
		return []string{}, nil
	}

	// Filter user roles to only include roles from this service
	userServiceRoles := make([]string, 0)
	serviceRoleMap := make(map[string]bool)
	
	for _, role := range serviceRoles {
		serviceRoleMap[role.Name] = true
	}

	for _, roleName := range user.Roles {
		if serviceRoleMap[roleName] {
			userServiceRoles = append(userServiceRoles, roleName)
		}
	}

	return userServiceRoles, nil
}

// CreateDefaultServices creates default services if they don't exist
func CreateDefaultServices() error {
	// Default services with their permissions in new format
	defaultServices := []struct {
		key         string
		name        string
		description string
		permissions []PermissionDef
	}{
		{
			key:         "referal",
			name:        "Referral Program",
			description: "Referral program management service",
			permissions: []PermissionDef{
				{Name: "view", DisplayName: "View", Description: "Permission to view referral data"},
				{Name: "create", DisplayName: "Create", Description: "Permission to create referrals"},
				{Name: "edit", DisplayName: "Edit", Description: "Permission to edit referrals"},
				{Name: "delete", DisplayName: "Delete", Description: "Permission to delete referrals"},
				{Name: "export", DisplayName: "Export", Description: "Permission to export referral data"},
				{Name: "manage_users", DisplayName: "Manage Users", Description: "Permission to manage referral users"},
			},
		},
		{
			key:         "calculators",
			name:        "Calculators",
			description: "Calculator tools service",
			permissions: []PermissionDef{
				{Name: "view", DisplayName: "View", Description: "Permission to view calculators"},
				{Name: "use", DisplayName: "Use", Description: "Permission to use calculators"},
				{Name: "create", DisplayName: "Create", Description: "Permission to create calculators"},
				{Name: "edit", DisplayName: "Edit", Description: "Permission to edit calculators"},
				{Name: "delete", DisplayName: "Delete", Description: "Permission to delete calculators"},
				{Name: "share", DisplayName: "Share", Description: "Permission to share calculators"},
			},
		},
	}

	for _, defaultService := range defaultServices {
		// Check if service already exists
		_, err := GetServiceByKey(defaultService.key)
		if err == mongo.ErrNoDocuments {
			// Service doesn't exist, create it
			_, err := CreateService(
				defaultService.key,
				defaultService.name,
				defaultService.description,
				defaultService.permissions,
			)
			if err != nil {
				return fmt.Errorf("failed to create default service %s: %v", defaultService.key, err)
			}
		} else if err != nil {
			return fmt.Errorf("error checking service %s: %v", defaultService.key, err)
		}
	}

	return nil
}

// GetServicesForRole returns all services that a role has access to
func GetServicesForRole(roleID primitive.ObjectID) ([]Service, error) {
	ctx := context.Background()

	// Get the role
	var role Role
	err := rolesCol.FindOne(ctx, bson.M{"_id": roleID}).Decode(&role)
	if err != nil {
		return nil, err
	}

	// Get the service
	var service Service
	err = servicesCol.FindOne(ctx, bson.M{"key": role.ServiceKey}).Decode(&service)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return []Service{}, nil
		}
		return nil, err
	}

	return []Service{service}, nil
}
