package models

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CleanupResult represents the result of orphaned data cleanup
type CleanupResult struct {
	EmptyRecordsRemoved  int       `json:"emptyRecordsRemoved"`
	OrphanedRolesRemoved int       `json:"orphanedRolesRemoved"`
	ServiceKeysFixed     int       `json:"serviceKeysFixed"`
	BackupCreated        bool      `json:"backupCreated"`
	Details              []string  `json:"details"`
	Errors               []string  `json:"errors"`
	StartedAt            time.Time `json:"startedAt"`
	CompletedAt          time.Time `json:"completedAt"`
}

// CleanupOrphanedUserServiceRoles removes orphaned records from user_service_roles
// This migration:
// 1. Backs up all affected records to a backup collection
// 2. Removes records with empty service_key AND empty role_name
// 3. Fixes service_key "client" → "client-service"
// 4. Removes records referencing roles that don't exist in service_roles
func CleanupOrphanedUserServiceRoles() (*CleanupResult, error) {
	ctx := context.Background()
	result := &CleanupResult{
		StartedAt: time.Now(),
		Details:   make([]string, 0),
		Errors:    make([]string, 0),
	}

	log.Println("=== Starting orphaned user_service_roles cleanup ===")

	// Step 0: Create backup of ALL user_service_roles before any changes
	backupColName := fmt.Sprintf("user_service_roles_backup_%s", time.Now().Format("20060102_150405"))
	backupCol := db.Collection(backupColName)

	cursor, err := userServiceRolesCol.Find(ctx, bson.M{})
	if err != nil {
		return result, fmt.Errorf("failed to read user_service_roles for backup: %v", err)
	}

	var allDocs []interface{}
	for cursor.Next(ctx) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			continue
		}
		allDocs = append(allDocs, doc)
	}
	cursor.Close(ctx)

	if len(allDocs) > 0 {
		_, err = backupCol.InsertMany(ctx, allDocs)
		if err != nil {
			return result, fmt.Errorf("failed to create backup collection %s: %v", backupColName, err)
		}
		result.BackupCreated = true
		result.Details = append(result.Details, fmt.Sprintf("Backup created: %s (%d records)", backupColName, len(allDocs)))
		log.Printf("Backup created: %s with %d records", backupColName, len(allDocs))
	}

	// Step 1: Remove records with empty service_key AND empty role_name
	emptyFilter := bson.M{
		"$or": []bson.M{
			{"service_key": "", "role_name": ""},
			{"service_key": bson.M{"$exists": false}},
			{"role_name": bson.M{"$exists": false}},
		},
	}

	// Log what we're about to delete
	emptyCursor, _ := userServiceRolesCol.Find(ctx, emptyFilter)
	var emptyCount int
	for emptyCursor.Next(ctx) {
		var doc bson.M
		if err := emptyCursor.Decode(&doc); err == nil {
			emptyCount++
			log.Printf("  Will remove empty record: userID=%v, service=%v, role=%v",
				doc["user_id"], doc["service_key"], doc["role_name"])
		}
	}
	emptyCursor.Close(ctx)

	if emptyCount > 0 {
		delResult, err := userServiceRolesCol.DeleteMany(ctx, emptyFilter)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to remove empty records: %v", err))
		} else {
			result.EmptyRecordsRemoved = int(delResult.DeletedCount)
			result.Details = append(result.Details, fmt.Sprintf("Removed %d empty records (no service/role)", delResult.DeletedCount))
			log.Printf("Removed %d empty records", delResult.DeletedCount)
		}
	}

	// Step 2: Fix service_key "client" → "client-service" in user_service_roles
	fixFilter := bson.M{"service_key": "client"}
	fixCursor, _ := userServiceRolesCol.Find(ctx, fixFilter)
	var fixCount int
	for fixCursor.Next(ctx) {
		fixCount++
	}
	fixCursor.Close(ctx)

	if fixCount > 0 {
		updateResult, err := userServiceRolesCol.UpdateMany(ctx, fixFilter,
			bson.M{"$set": bson.M{"service_key": "client-service"}})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to fix 'client' → 'client-service' in user_service_roles: %v", err))
		} else {
			result.ServiceKeysFixed = int(updateResult.ModifiedCount)
			result.Details = append(result.Details, fmt.Sprintf("Fixed %d records in user_service_roles: 'client' → 'client-service'", updateResult.ModifiedCount))
			log.Printf("Fixed %d records in user_service_roles: 'client' → 'client-service'", updateResult.ModifiedCount)
		}
	}

	// Step 2b: Fix service "client" → "client-service" in service_roles collection
	fixRolesFilter := bson.M{"service": "client"}
	fixRolesCursor, _ := serviceRolesCol.Find(ctx, fixRolesFilter)
	var fixRolesCount int
	for fixRolesCursor.Next(ctx) {
		fixRolesCount++
	}
	fixRolesCursor.Close(ctx)

	if fixRolesCount > 0 {
		updateResult, err := serviceRolesCol.UpdateMany(ctx, fixRolesFilter,
			bson.M{"$set": bson.M{"service": "client-service"}})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to fix 'client' → 'client-service' in service_roles: %v", err))
		} else {
			result.Details = append(result.Details, fmt.Sprintf("Fixed %d records in service_roles: 'client' → 'client-service'", updateResult.ModifiedCount))
			log.Printf("Fixed %d records in service_roles: 'client' → 'client-service'", updateResult.ModifiedCount)
		}
	}

	// Step 2c: Remove orphan service with key="client" from services collection (if "client-service" exists)
	_, csErr := GetServiceByKey("client-service")
	if csErr == nil {
		// "client-service" exists, so "client" is a stale duplicate
		delResult, err := servicesCol.DeleteMany(ctx, bson.M{"key": "client"})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to remove orphan 'client' service: %v", err))
		} else if delResult.DeletedCount > 0 {
			result.Details = append(result.Details, fmt.Sprintf("Removed %d orphan service(s) with key='client'", delResult.DeletedCount))
			log.Printf("Removed %d orphan service(s) with key='client'", delResult.DeletedCount)
		}
	}

	// Step 3: Remove records referencing roles that don't exist in service_roles
	// Get all valid service+role combinations from service_roles
	validRoles := make(map[string]bool)
	rolesCursor, err := serviceRolesCol.Find(ctx, bson.M{})
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read service_roles: %v", err))
	} else {
		for rolesCursor.Next(ctx) {
			var role bson.M
			if err := rolesCursor.Decode(&role); err == nil {
				serviceKey := ""
				if sk, ok := role["service_key"].(string); ok {
					serviceKey = sk
				} else if sk, ok := role["service"].(string); ok {
					serviceKey = sk
				}
				roleName := ""
				if rn, ok := role["name"].(string); ok {
					roleName = rn
				}
				if serviceKey != "" && roleName != "" {
					validRoles[serviceKey+":"+roleName] = true
				}
			}
		}
		rolesCursor.Close(ctx)
		log.Printf("Found %d valid service:role combinations", len(validRoles))
	}

	// Check each user_service_role against valid roles
	if len(validRoles) > 0 {
		allAssignments, err := userServiceRolesCol.Find(ctx, bson.M{
			"service_key": bson.M{"$ne": ""},
			"role_name":   bson.M{"$ne": ""},
		})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to read assignments: %v", err))
		} else {
			var orphanIDs []primitive.ObjectID
			for allAssignments.Next(ctx) {
				var doc bson.M
				if err := allAssignments.Decode(&doc); err == nil {
					serviceKey := ""
					if sk, ok := doc["service_key"].(string); ok {
						serviceKey = sk
					}
					roleName := ""
					if rn, ok := doc["role_name"].(string); ok {
						roleName = rn
					}
					key := serviceKey + ":" + roleName
					if !validRoles[key] {
						if id, ok := doc["_id"].(primitive.ObjectID); ok {
							orphanIDs = append(orphanIDs, id)
							log.Printf("  Orphaned assignment: userID=%v, service=%s, role=%s (role not in service_roles)",
								doc["user_id"], serviceKey, roleName)
						}
					}
				}
			}
			allAssignments.Close(ctx)

			if len(orphanIDs) > 0 {
				delResult, err := userServiceRolesCol.DeleteMany(ctx, bson.M{
					"_id": bson.M{"$in": orphanIDs},
				})
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Failed to remove orphaned roles: %v", err))
				} else {
					result.OrphanedRolesRemoved = int(delResult.DeletedCount)
					result.Details = append(result.Details, fmt.Sprintf("Removed %d orphaned role assignments (role doesn't exist in service_roles)", delResult.DeletedCount))
					log.Printf("Removed %d orphaned role assignments", delResult.DeletedCount)
				}
			}
		}
	}

	result.CompletedAt = time.Now()
	log.Printf("=== Cleanup completed: %d empty removed, %d service keys fixed, %d orphans removed, %d errors ===",
		result.EmptyRecordsRemoved, result.ServiceKeysFixed, result.OrphanedRolesRemoved, len(result.Errors))

	return result, nil
}
