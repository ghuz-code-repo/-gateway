package models

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// PermissionDef represents a permission definition with metadata
type PermissionDef struct {
	Name        string    `bson:"name" json:"name"`                               // Permission identifier (e.g., "users.read")
	DisplayName string    `bson:"displayName" json:"displayName"`                 // Human-readable name
	Description string    `bson:"description" json:"description"`                 // Description of what this permission allows
	External    bool      `bson:"external" json:"external"`                       // True if this permission can be assigned to external roles
	DeletedAt   time.Time `bson:"deletedAt,omitempty" json:"deletedAt,omitempty"` // Soft delete timestamp
}

// Service represents a service with its master permission list
type Service struct {
	ID                   primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Key                  string             `bson:"key" json:"key" validate:"required"`               // e.g. "referal"
	Name                 string             `bson:"name" json:"name"`                                 // Display name
	Description          string             `bson:"description" json:"description"`                   // Service description
	AvailablePermissions []PermissionDef    `bson:"availablePermissions" json:"availablePermissions"` // Canonical list of permissions
	Status               string             `bson:"status" json:"status"`                             // active, deprecated, disabled
	CreatedAt            time.Time          `bson:"created_at" json:"created_at"`                     // Creation timestamp
	UpdatedAt            time.Time          `bson:"updated_at" json:"updated_at"`                     // Update timestamp
	DeletedAt            *time.Time         `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"` // Soft delete timestamp

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

// RegisterExternalServicePermissions creates external permissions in auth-service
// for managing this service from auth-service UI
// These permissions have format: auth.<service-key>.<action>
// Example: auth.referal.users.manage, auth.calculator.settings.view
func RegisterExternalServicePermissions(serviceKey, serviceName string) error {
	ctx := context.Background()

	// Get auth-service
	var authService Service
	err := servicesCol.FindOne(ctx, bson.M{"key": "auth"}).Decode(&authService)
	if err != nil {
		return fmt.Errorf("auth service not found: %w", err)
	}

	// Build set of existing permission names
	existingPerms := make(map[string]bool)
	for _, perm := range authService.AvailablePermissions {
		existingPerms[perm.Name] = true
	}

	// Standard external permission templates - GRANULAR permissions
	// Each action has its own permission for fine-grained access control
	templates := []struct {
		suffix      string
		displayName string
		description string
		category    string
	}{
		// Users Management
		{"users.view", fmt.Sprintf("View %s users", serviceName), "View list of users in this service", "users"},
		{"users.add", fmt.Sprintf("Add %s users", serviceName), "Add new users to this service", "users"},
		{"users.edit", fmt.Sprintf("Edit %s users", serviceName), "Edit existing users in this service", "users"},
		{"users.delete", fmt.Sprintf("Delete %s users", serviceName), "Delete users from this service", "users"},
		{"users.assign_roles", fmt.Sprintf("Assign roles to %s users", serviceName), "Assign or remove roles from users in this service", "users"},

		// Roles Management (External Roles)
		{"roles.view", fmt.Sprintf("View %s external roles", serviceName), "View external roles that control this service from auth-service", "roles"},
		{"roles.create", fmt.Sprintf("Create %s external roles", serviceName), "Create new external roles for controlling this service", "roles"},
		{"roles.edit", fmt.Sprintf("Edit %s external roles", serviceName), "Edit existing external roles for this service", "roles"},
		{"roles.delete", fmt.Sprintf("Delete %s external roles", serviceName), "Delete external roles for this service", "roles"},
		{"roles.assign", fmt.Sprintf("Assign %s external roles", serviceName), "Assign external roles to users", "roles"},

		// Settings Management
		{"settings.view", fmt.Sprintf("View %s settings", serviceName), "View service settings and configuration", "settings"},
		{"settings.edit", fmt.Sprintf("Edit %s settings", serviceName), "Modify service settings and configuration", "settings"},

		// Logs (Read-only)
		{"logs.view", fmt.Sprintf("View %s logs", serviceName), "View service logs and activity", "logs"},
	}

	// Build new permissions
	newPermissions := []PermissionDef{}
	for _, tmpl := range templates {
		permName := fmt.Sprintf("auth.%s.%s", serviceKey, tmpl.suffix)

		// Skip if already exists
		if existingPerms[permName] {
			continue
		}

		newPermissions = append(newPermissions, PermissionDef{
			Name:        permName,
			DisplayName: tmpl.displayName,
			Description: tmpl.description,
			External:    true, // External permissions can be assigned to external roles
		})
	}

	// Add new permissions to auth-service
	if len(newPermissions) > 0 {
		_, err = servicesCol.UpdateOne(
			ctx,
			bson.M{"key": "auth"},
			bson.M{
				"$push": bson.M{
					"availablePermissions": bson.M{"$each": newPermissions},
				},
				"$set": bson.M{
					"updatedAt": time.Now(),
				},
			},
		)
		if err != nil {
			return fmt.Errorf("failed to add external permissions: %w", err)
		}

		log.Printf("✅ Added %d external permissions for service %s to auth-service", len(newPermissions), serviceKey)
	}

	return nil
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

// GetAllServices returns all non-deleted services by default
func GetAllServices() ([]Service, error) {
	return GetAllServicesWithOptions(false)
}

// GetAllServicesWithOptions returns services with optional inclusion of deleted ones
func GetAllServicesWithOptions(includeDeleted bool) ([]Service, error) {
	ctx := context.Background()

	// Build filter to exclude deleted services by default
	filter := bson.M{}
	if !includeDeleted {
		filter["deleted_at"] = bson.M{"$exists": false}
	}

	cursor, err := servicesCol.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var services []Service
	if err = cursor.All(ctx, &services); err != nil {
		return nil, err
	}

	log.Printf("DEBUG: GetAllServicesWithOptions(includeDeleted=%v) found %d services:", includeDeleted, len(services))
	for i, service := range services {
		deletedStatus := "active"
		if service.DeletedAt != nil {
			deletedStatus = "deleted"
		}
		log.Printf("DEBUG: Service %d - Key: '%s', Name: '%s', Status: %s", i+1, service.Key, service.Name, deletedStatus)
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

// GetServiceByKey retrieves a non-deleted service by its key
func GetServiceByKey(key string) (*Service, error) {
	return GetServiceByKeyWithOptions(key, false)
}

// GetServiceByKeyWithOptions retrieves a service by its key with optional inclusion of deleted
func GetServiceByKeyWithOptions(key string, includeDeleted bool) (*Service, error) {
	ctx := context.Background()

	log.Printf("DEBUG: Searching for service with key: '%s' (includeDeleted=%v)", key, includeDeleted)

	filter := bson.M{"key": key}
	if !includeDeleted {
		filter["deleted_at"] = bson.M{"$exists": false}
	}

	var service Service
	err := servicesCol.FindOne(ctx, filter).Decode(&service)
	if err != nil {
		log.Printf("DEBUG: Service with key '%s' not found in database: %v", key, err)
		return nil, err
	}

	deletedStatus := "active"
	if service.DeletedAt != nil {
		deletedStatus = "deleted"
	}
	log.Printf("DEBUG: Found service with key '%s', name: '%s', status: %s", service.Key, service.Name, deletedStatus)
	return &service, nil
}

// GetServiceByName retrieves a service by its name
func GetServiceByName(name string) (*Service, error) {
	ctx := context.Background()

	var service Service
	err := servicesCol.FindOne(ctx, bson.M{"name": name}).Decode(&service)
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

// DeleteService removes a service (hard delete - use with caution!)
func DeleteService(id primitive.ObjectID) error {
	ctx := context.Background()

	_, err := servicesCol.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

// DeleteServiceByKey removes a service by its key (hard delete - use with caution!)
func DeleteServiceByKey(key string) error {
	ctx := context.Background()

	_, err := servicesCol.DeleteOne(ctx, bson.M{"key": key})
	return err
}

// SoftDeleteService performs a soft delete of a service and all related entities
// This marks the service as deleted but keeps all data for potential restoration
func SoftDeleteService(serviceKey string) error {
	ctx := context.Background()
	now := time.Now()

	log.Printf("INFO: Starting soft delete for service '%s'", serviceKey)

	// 1. Mark the service as deleted
	result, err := servicesCol.UpdateOne(
		ctx,
		bson.M{"key": serviceKey, "deleted_at": bson.M{"$exists": false}},
		bson.M{
			"$set": bson.M{
				"deleted_at": now,
				"updated_at": now,
			},
		},
	)
	if err != nil {
		log.Printf("ERROR: Failed to soft delete service '%s': %v", serviceKey, err)
		return fmt.Errorf("failed to soft delete service: %w", err)
	}
	if result.MatchedCount == 0 {
		log.Printf("WARNING: Service '%s' not found or already deleted", serviceKey)
		return fmt.Errorf("service not found or already deleted")
	}
	log.Printf("INFO: Service '%s' marked as deleted", serviceKey)

	// 2. Soft delete all roles of this service
	roleResult, err := serviceRolesCol.UpdateMany(
		ctx,
		bson.M{"service": serviceKey, "deletedAt": bson.M{"$exists": false}},
		bson.M{
			"$set": bson.M{
				"deletedAt": now,
				"updatedAt": now,
			},
		},
	)
	if err != nil {
		log.Printf("ERROR: Failed to soft delete roles for service '%s': %v", serviceKey, err)
		return fmt.Errorf("failed to soft delete service roles: %w", err)
	}
	log.Printf("INFO: Soft deleted %d roles for service '%s'", roleResult.ModifiedCount, serviceKey)

	// 3. Delete all user role assignments for this service (hard delete as these are references)
	assignmentResult, err := userServiceRolesCol.DeleteMany(
		ctx,
		bson.M{"service_key": serviceKey},
	)
	if err != nil {
		log.Printf("ERROR: Failed to delete user role assignments for service '%s': %v", serviceKey, err)
		return fmt.Errorf("failed to delete user role assignments: %w", err)
	}
	log.Printf("INFO: Deleted %d user role assignments for service '%s'", assignmentResult.DeletedCount, serviceKey)

	// 4. Soft delete all permissions for this service
	permResult, err := permsCol.UpdateMany(
		ctx,
		bson.M{"service": serviceKey, "deleted_at": bson.M{"$exists": false}},
		bson.M{
			"$set": bson.M{
				"deleted_at": now,
			},
		},
	)
	if err != nil {
		log.Printf("ERROR: Failed to soft delete permissions for service '%s': %v", serviceKey, err)
		return fmt.Errorf("failed to soft delete service permissions: %w", err)
	}
	log.Printf("INFO: Soft deleted %d permissions for service '%s'", permResult.ModifiedCount, serviceKey)

	// 5. Remove serviceKey from allowed_services in all user documents
	docResult, err := usersCol.UpdateMany(
		ctx,
		bson.M{"documents.allowed_services": serviceKey},
		bson.M{
			"$pull": bson.M{
				"documents.$[].allowed_services": serviceKey,
			},
		},
	)
	if err != nil {
		log.Printf("ERROR: Failed to remove service '%s' from user documents: %v", serviceKey, err)
		return fmt.Errorf("failed to update user documents: %w", err)
	}
	log.Printf("INFO: Removed service '%s' from %d user document entries", serviceKey, docResult.ModifiedCount)

	log.Printf("INFO: Successfully completed soft delete for service '%s'", serviceKey)
	return nil
}

// HardDeleteService permanently deletes a service and all related data
// WARNING: This operation cannot be undone! Use SoftDeleteService for recoverable deletion.
func HardDeleteService(serviceKey string) error {
	ctx := context.Background()

	log.Printf("WARNING: Starting HARD DELETE for service '%s' - this cannot be undone!", serviceKey)

	// 1. Delete the service itself
	result, err := servicesCol.DeleteOne(ctx, bson.M{"key": serviceKey})
	if err != nil {
		log.Printf("ERROR: Failed to hard delete service '%s': %v", serviceKey, err)
		return fmt.Errorf("failed to delete service: %w", err)
	}
	if result.DeletedCount == 0 {
		log.Printf("WARNING: Service '%s' not found", serviceKey)
		return fmt.Errorf("service not found")
	}
	log.Printf("INFO: Service '%s' deleted from database", serviceKey)

	// 2. Delete all roles of this service
	roleResult, err := serviceRolesCol.DeleteMany(ctx, bson.M{"service": serviceKey})
	if err != nil {
		log.Printf("ERROR: Failed to delete roles for service '%s': %v", serviceKey, err)
		return fmt.Errorf("failed to delete service roles: %w", err)
	}
	log.Printf("INFO: Deleted %d roles for service '%s'", roleResult.DeletedCount, serviceKey)

	// 3. Delete all user role assignments for this service
	assignmentResult, err := userServiceRolesCol.DeleteMany(ctx, bson.M{"service_key": serviceKey})
	if err != nil {
		log.Printf("ERROR: Failed to delete user role assignments for service '%s': %v", serviceKey, err)
		return fmt.Errorf("failed to delete user role assignments: %w", err)
	}
	log.Printf("INFO: Deleted %d user role assignments for service '%s'", assignmentResult.DeletedCount, serviceKey)

	// 4. Delete all permissions for this service
	permResult, err := permsCol.DeleteMany(ctx, bson.M{"service": serviceKey})
	if err != nil {
		log.Printf("ERROR: Failed to delete permissions for service '%s': %v", serviceKey, err)
		return fmt.Errorf("failed to delete service permissions: %w", err)
	}
	log.Printf("INFO: Deleted %d permissions for service '%s'", permResult.DeletedCount, serviceKey)

	// 5. Delete import logs for this service
	importLogsCol := db.Collection("import_logs")
	logResult, err := importLogsCol.DeleteMany(ctx, bson.M{"service_key": serviceKey})
	if err != nil {
		log.Printf("ERROR: Failed to delete import logs for service '%s': %v", serviceKey, err)
		// Don't fail the entire operation if logs can't be deleted
		log.Printf("WARNING: Continuing despite import log deletion failure")
	} else {
		log.Printf("INFO: Deleted %d import logs for service '%s'", logResult.DeletedCount, serviceKey)
	}

	// 6. Remove serviceKey from allowed_services in all user documents
	docResult, err := usersCol.UpdateMany(
		ctx,
		bson.M{"documents.allowed_services": serviceKey},
		bson.M{
			"$pull": bson.M{
				"documents.$[].allowed_services": serviceKey,
			},
		},
	)
	if err != nil {
		log.Printf("ERROR: Failed to remove service '%s' from user documents: %v", serviceKey, err)
		return fmt.Errorf("failed to update user documents: %w", err)
	}
	log.Printf("INFO: Removed service '%s' from %d user document entries", serviceKey, docResult.ModifiedCount)

	log.Printf("INFO: Successfully completed HARD DELETE for service '%s'", serviceKey)
	return nil
}

// RestoreService restores a soft-deleted service and its related entities
func RestoreService(serviceKey string) error {
	ctx := context.Background()

	log.Printf("INFO: Starting restore for service '%s'", serviceKey)

	// 1. Check if service exists and is deleted
	var service Service
	err := servicesCol.FindOne(ctx, bson.M{"key": serviceKey}).Decode(&service)
	if err != nil {
		log.Printf("ERROR: Service '%s' not found: %v", serviceKey, err)
		return fmt.Errorf("service not found: %w", err)
	}
	if service.DeletedAt == nil {
		log.Printf("WARNING: Service '%s' is not deleted, nothing to restore", serviceKey)
		return fmt.Errorf("service is not deleted")
	}

	// 2. Restore the service
	result, err := servicesCol.UpdateOne(
		ctx,
		bson.M{"key": serviceKey},
		bson.M{
			"$unset": bson.M{"deleted_at": ""},
			"$set":   bson.M{"updated_at": time.Now()},
		},
	)
	if err != nil {
		log.Printf("ERROR: Failed to restore service '%s': %v", serviceKey, err)
		return fmt.Errorf("failed to restore service: %w", err)
	}
	if result.ModifiedCount == 0 {
		log.Printf("WARNING: Service '%s' was not modified during restore", serviceKey)
	}
	log.Printf("INFO: Service '%s' restored", serviceKey)

	// 3. Restore all roles of this service
	roleResult, err := serviceRolesCol.UpdateMany(
		ctx,
		bson.M{"service": serviceKey, "deletedAt": bson.M{"$exists": true}},
		bson.M{
			"$unset": bson.M{"deletedAt": ""},
			"$set":   bson.M{"updatedAt": time.Now()},
		},
	)
	if err != nil {
		log.Printf("ERROR: Failed to restore roles for service '%s': %v", serviceKey, err)
		return fmt.Errorf("failed to restore service roles: %w", err)
	}
	log.Printf("INFO: Restored %d roles for service '%s'", roleResult.ModifiedCount, serviceKey)

	// 4. Restore all permissions for this service
	permResult, err := permsCol.UpdateMany(
		ctx,
		bson.M{"service": serviceKey, "deleted_at": bson.M{"$exists": true}},
		bson.M{
			"$unset": bson.M{"deleted_at": ""},
		},
	)
	if err != nil {
		log.Printf("ERROR: Failed to restore permissions for service '%s': %v", serviceKey, err)
		return fmt.Errorf("failed to restore service permissions: %w", err)
	}
	log.Printf("INFO: Restored %d permissions for service '%s'", permResult.ModifiedCount, serviceKey)

	// Note: We do NOT restore user_service_roles assignments automatically
	// These should be reassigned manually by administrators after restoration
	log.Printf("INFO: Note - User role assignments were not restored and must be reassigned manually")

	log.Printf("INFO: Successfully completed restore for service '%s'", serviceKey)
	return nil
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

// UpdateServicePermission updates a permission in a service
func UpdateServicePermission(serviceKey string, originalPermName string, newPermissionDef PermissionDef) error {
	ctx := context.Background()

	// Сначала удаляем старое разрешение
	_, err := servicesCol.UpdateOne(
		ctx,
		bson.M{"key": serviceKey},
		bson.M{
			"$pull": bson.M{
				"availablePermissions": bson.M{"name": originalPermName},
			},
		},
	)
	if err != nil {
		return err
	}

	// Затем добавляем новое разрешение
	_, err = servicesCol.UpdateOne(
		ctx,
		bson.M{"key": serviceKey},
		bson.M{
			"$addToSet": bson.M{
				"availablePermissions": newPermissionDef,
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
			"key":                       serviceKey,
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

	// For regular users, collect permissions from service-specific roles
	// First, get user's service-specific roles from user_service_roles collection
	serviceRoleNames, err := GetUserServiceRolesFromCollection(userID, serviceKey)
	if err != nil {
		log.Printf("DEBUG GetUserServicePermissions: error getting service roles: %v", err)
		serviceRoleNames = []string{}
	}

	log.Printf("DEBUG GetUserServicePermissions: user=%s, service=%s, serviceRoleNames=%v", userID, serviceKey, serviceRoleNames)

	// Get all available roles for the service
	roles, err := GetRolesByService(serviceKey)
	if err != nil {
		log.Printf("DEBUG GetUserServicePermissions: error getting roles by service: %v", err)
		return []string{}, nil
	}

	permissionSet := make(map[string]bool)

	// Check service-specific roles (user_service_roles)
	for _, roleName := range serviceRoleNames {
		for _, role := range roles {
			if role.Name == roleName {
				log.Printf("DEBUG GetUserServicePermissions: found matching role '%s' with %d permissions", roleName, len(role.Permissions))
				for _, perm := range role.Permissions {
					permissionSet[perm] = true
				}
			}
		}
	}

	// Also check global roles (for backward compatibility)
	for _, roleName := range user.Roles {
		for _, role := range roles {
			if role.Name == roleName {
				log.Printf("DEBUG GetUserServicePermissions: found matching global role '%s' with %d permissions", roleName, len(role.Permissions))
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

	log.Printf("DEBUG GetUserServicePermissions: returning %d permissions: %v", len(permissions), permissions)

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

// GetUserServiceRolesFromCollection returns all role names a user has for a specific service from user_service_roles collection
func GetUserServiceRolesFromCollection(userID, serviceKey string) ([]string, error) {
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, err
	}

	filter := bson.M{
		"user_id":     objID,
		"service_key": serviceKey,
		"is_active":   true,
	}

	cursor, err := userServiceRolesCol.Find(context.Background(), filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())

	var roles []string
	for cursor.Next(context.Background()) {
		var userServiceRole UserServiceRole
		if err := cursor.Decode(&userServiceRole); err != nil {
			continue
		}
		roles = append(roles, userServiceRole.RoleName)
	}

	return roles, nil
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
	err := serviceRolesCol.FindOne(ctx, bson.M{"_id": roleID}).Decode(&role)
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

// UpdateServicePermissions updates the available permissions for a service
func UpdateServicePermissions(serviceKey string, permissions []PermissionDef) error {
	ctx := context.Background()

	// Check if service exists
	_, err := GetServiceByKey(serviceKey)
	if err != nil {
		return fmt.Errorf("service not found: %w", err)
	}

	// Update permissions and timestamp
	update := bson.M{
		"$set": bson.M{
			"availablePermissions": permissions,
			"updated_at":           time.Now(),
		},
	}

	_, err = servicesCol.UpdateOne(
		ctx,
		bson.M{"key": serviceKey},
		update,
	)

	if err != nil {
		return fmt.Errorf("failed to update service permissions: %w", err)
	}

	log.Printf("Updated permissions for service %s: %d permissions synced", serviceKey, len(permissions))
	return nil
}
