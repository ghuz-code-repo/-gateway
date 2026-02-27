package models

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// MigrationResult represents the result of a migration operation
type MigrationResult struct {
	ServicesUpdated int       `json:"servicesUpdated"`
	RolesUpdated    int       `json:"rolesUpdated"`
	Errors          []string  `json:"errors"`
	StartedAt       time.Time `json:"startedAt"`
	CompletedAt     time.Time `json:"completedAt"`
}

// MigrateToADR001Schema migrates existing data to ADR-001 compliant schema
func MigrateToADR001Schema() (*MigrationResult, error) {
	result := &MigrationResult{
		StartedAt: time.Now(),
		Errors:    make([]string, 0),
	}

	log.Println("Starting migration to ADR-001 schema...")

	// Phase 1: Migrate Services Collection
	err := migrateServicesSchema(result)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Service migration failed: %v", err))
		return result, err
	}

	// Phase 2: Migrate Roles Collection
	err = migrateRolesSchema(result)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Role migration failed: %v", err))
		return result, err
	}

	// Phase 3: Create default services if they don't exist
	// COMMENTED OUT: Auto-creation of default services disabled
	// err = ensureDefaultServices(result)
	// if err != nil {
	// 	result.Errors = append(result.Errors, fmt.Sprintf("Default services creation failed: %v", err))
	// }

	// Phase 4: Migrate role_type field on existing roles
	err = migrateRoleTypes(result)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Role type migration failed: %v", err))
		// Non-fatal: continue
	}

	// Phase 5: Remove unwanted system administration service
	err = DeleteServiceByKey("system")
	if err != nil {
		log.Printf("Could not remove system service (might not exist): %v", err)
	} else {
		log.Println("Removed unwanted 'System Administration' service")
	}

	result.CompletedAt = time.Now()
	log.Printf("Migration completed: %d services updated, %d roles updated",
		result.ServicesUpdated, result.RolesUpdated)

	return result, nil
}

// migrateServicesSchema updates services to use the new availablePermissions schema
func migrateServicesSchema(result *MigrationResult) error {
	ctx := context.Background()

	// Find all services that need migration (have permissions but no availablePermissions)
	cursor, err := servicesCol.Find(ctx, bson.M{
		"permissions":          bson.M{"$exists": true, "$ne": nil},
		"availablePermissions": bson.M{"$exists": false},
	})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var service Service
		if err := cursor.Decode(&service); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to decode service: %v", err))
			continue
		}

		// Convert legacy permissions to new format
		availablePermissions := make([]PermissionDef, len(service.Permissions))
		for i, perm := range service.Permissions {
			availablePermissions[i] = PermissionDef{
				Name:        perm,
				DisplayName: titleCase(perm),
				Description: fmt.Sprintf("Permission to %s", perm),
			}
		}

		// Update the service with new schema
		_, err := servicesCol.UpdateOne(
			ctx,
			bson.M{"_id": service.ID},
			bson.M{
				"$set": bson.M{
					"availablePermissions": availablePermissions,
					"status":               "active",
					"updated_at":           time.Now(),
				},
			},
		)

		if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("Failed to update service %s: %v", service.Key, err))
		} else {
			result.ServicesUpdated++
			log.Printf("Migrated service: %s (%s)", service.Key, service.Name)
		}
	}

	return nil
}

// migrateRolesSchema updates roles to include timestamps
func migrateRolesSchema(result *MigrationResult) error {
	ctx := context.Background()

	// Find all roles that need timestamps
	cursor, err := serviceRolesCol.Find(ctx, bson.M{
		"createdAt": bson.M{"$exists": false},
	})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	now := time.Now()
	for cursor.Next(ctx) {
		var role Role
		if err := cursor.Decode(&role); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to decode role: %v", err))
			continue
		}

		// Add timestamps to existing role
		_, err := serviceRolesCol.UpdateOne(
			ctx,
			bson.M{"_id": role.ID},
			bson.M{
				"$set": bson.M{
					"createdAt": now,
					"updatedAt": now,
				},
			},
		)

		if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("Failed to update role %s: %v", role.Name, err))
		} else {
			result.RolesUpdated++
			log.Printf("Migrated role: %s (service: %s)", role.Name, role.ServiceKey)
		}
	}

	return nil
}

// migrateRoleTypes sets role_type and managed_service fields on existing roles
// that don't have them yet. Uses heuristic: auth-service roles whose permissions
// match "auth.<serviceKey>.*" pattern are external, all others are internal.
func migrateRoleTypes(result *MigrationResult) error {
	ctx := context.Background()

	// Find roles without role_type field
	cursor, err := serviceRolesCol.Find(ctx, bson.M{
		"role_type": bson.M{"$exists": false},
	})
	if err != nil {
		return fmt.Errorf("failed to query roles: %v", err)
	}
	defer cursor.Close(ctx)

	// Get all registered services to detect external permission patterns
	servicesCursor, err := servicesCol.Find(ctx, bson.M{
		"key": bson.M{"$ne": "auth"},
	})
	if err != nil {
		return fmt.Errorf("failed to query services: %v", err)
	}
	defer servicesCursor.Close(ctx)

	serviceKeys := make(map[string]bool)
	for servicesCursor.Next(ctx) {
		var svc Service
		if err := servicesCursor.Decode(&svc); err != nil {
			continue
		}
		serviceKeys[svc.Key] = true
	}

	// System roles that should always be internal
	systemRoleNames := map[string]bool{
		"GOD": true, "god": true,
		"admin": true, "Admin": true, "ADMIN": true,
		"service-manager": true, "user-manager": true,
		"viewer": true, "support": true,
	}

	updated := 0
	for cursor.Next(ctx) {
		var role Role
		if err := cursor.Decode(&role); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to decode role for type migration: %v", err))
			continue
		}

		roleType := RoleTypeInternal
		managedService := ""

		// For auth-service roles, check if they manage an external service
		serviceField := role.ServiceKey
		if serviceField == "" {
			// Try reading from bson directly
			continue
		}

		if serviceField == "auth" && !systemRoleNames[role.Name] {
			// Check if role has permissions matching auth.<serviceKey>.* for a known service
			for _, perm := range role.Permissions {
				if perm == "auth.*" {
					// Wildcard — this is a system admin role, keep internal
					break
				}
				// Parse auth.<serviceKey>.<action>
				parts := strings.Split(perm, ".")
				if len(parts) >= 3 && parts[0] == "auth" {
					candidateService := parts[1]
					if serviceKeys[candidateService] {
						roleType = RoleTypeExternal
						managedService = candidateService
						break
					}
				}
			}
		}

		// Update the role
		update := bson.M{
			"$set": bson.M{
				"role_type": roleType,
				"updatedAt": time.Now(),
			},
		}
		if managedService != "" {
			update["$set"].(bson.M)["managed_service"] = managedService
		}

		_, err := serviceRolesCol.UpdateOne(ctx, bson.M{"_id": role.ID}, update)
		if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("Failed to set role_type for role %s: %v", role.Name, err))
		} else {
			updated++
			log.Printf("Set role_type=%s for role '%s' (service: %s, managed: %s)",
				roleType, role.Name, serviceField, managedService)
		}
	}

	log.Printf("Role type migration: updated %d roles", updated)
	return nil
}

// ensureDefaultServices creates default services according to ADR-001
func ensureDefaultServices(result *MigrationResult) error {
	defaultServices := []struct {
		key         string
		name        string
		description string
		permissions []PermissionDef
	}{
		{
			key:         "referal",
			name:        "Referral System",
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
			name:        "Calculators Service",
			description: "Financial and business calculators",
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
				result.Errors = append(result.Errors,
					fmt.Sprintf("Failed to create default service %s: %v", defaultService.key, err))
			} else {
				log.Printf("Created default service: %s", defaultService.key)
			}
		} else if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("Error checking service %s: %v", defaultService.key, err))
		} else {
			log.Printf("Default service %s already exists", defaultService.key)
		}
	}

	return nil
}

// ValidateMigration verifies that the migration was successful
func ValidateMigration() error {
	ctx := context.Background()

	// Check that all services have the new schema
	cursor, err := servicesCol.Find(ctx, bson.M{
		"availablePermissions": bson.M{"$exists": false},
		"permissions":          bson.M{"$exists": true, "$ne": nil},
	})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	var unmigrated []string
	for cursor.Next(ctx) {
		var service Service
		if err := cursor.Decode(&service); err != nil {
			continue
		}
		unmigrated = append(unmigrated, service.Key)
	}

	if len(unmigrated) > 0 {
		return fmt.Errorf("unmigrated services found: %v", unmigrated)
	}

	// Check that all roles have timestamps
	count, err := serviceRolesCol.CountDocuments(ctx, bson.M{
		"createdAt": bson.M{"$exists": false},
	})
	if err != nil {
		return err
	}

	if count > 0 {
		return fmt.Errorf("%d roles without timestamps found", count)
	}

	log.Println("Migration validation successful")
	return nil
}

// RollbackMigration provides a way to rollback the migration if needed
func RollbackMigration() error {
	ctx := context.Background()

	log.Println("Starting migration rollback...")

	// Remove new fields from services (keeping legacy permissions)
	_, err := servicesCol.UpdateMany(
		ctx,
		bson.M{},
		bson.M{
			"$unset": bson.M{
				"availablePermissions": "",
				"status":               "",
				"updated_at":           "",
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to rollback services: %v", err)
	}

	// Remove timestamps from roles
	_, err = serviceRolesCol.UpdateMany(
		ctx,
		bson.M{},
		bson.M{
			"$unset": bson.M{
				"createdAt": "",
				"updatedAt": "",
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to rollback roles: %v", err)
	}

	log.Println("Migration rollback completed")
	return nil
}
