package models

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// GetUserAuthPermissions returns all permissions user has in auth-service
// This function aggregates permissions from all active roles the user has in auth-service
func GetUserAuthPermissions(userID primitive.ObjectID) ([]string, error) {
	// Get user's service roles in auth-service
	userServiceRoles, err := GetUserServiceRolesByUserIDAndService(userID, "auth")
	if err != nil {
		log.Printf("DEBUG GetUserAuthPermissions: failed to get user service roles: %v", err)
		return []string{}, nil
	}

	// Aggregate permissions from all active roles
	permissionSet := make(map[string]bool)

	for _, userRole := range userServiceRoles {
		if !userRole.IsActive {
			continue
		}

		// Get the role details
		// For external roles with managed_service, use precise lookup to avoid collisions
		var role *Role
		var err error
		if userRole.ManagedService != "" {
			var sr *ServiceRole
			sr, err = GetExternalRoleByNameAndService(userRole.RoleName, userRole.ManagedService)
			if err == nil && sr != nil {
				role = &Role{
					ID:             sr.ID,
					ServiceKey:     sr.ServiceKey,
					Name:           sr.Name,
					Description:    sr.Description,
					Permissions:    sr.Permissions,
					RoleType:       sr.RoleType,
					ManagedService: sr.ManagedService,
				}
			}
		} else {
			role, err = GetRoleByServiceAndName("auth", userRole.RoleName)
		}
		if err != nil {
			log.Printf("DEBUG GetUserAuthPermissions: role not found: service=auth, name=%s: %v", userRole.RoleName, err)
			continue
		}

		// Add all permissions from this role
		for _, perm := range role.Permissions {
			permissionSet[perm] = true
		}

		log.Printf("DEBUG GetUserAuthPermissions: user=%s has role=%s with %d permissions", userID.Hex(), userRole.RoleName, len(role.Permissions))
	}

	// Convert set to slice
	permissions := make([]string, 0, len(permissionSet))
	for perm := range permissionSet {
		permissions = append(permissions, perm)
	}

	log.Printf("DEBUG GetUserAuthPermissions: user=%s has total %d unique permissions in auth-service", userID.Hex(), len(permissions))
	return permissions, nil
}

// HasAuthPermission checks if user has specific permission in auth-service
// Supports wildcard permissions (auth.*, auth.users.*)
func HasAuthPermission(userID primitive.ObjectID, permission string) bool {
	permissions, err := GetUserAuthPermissions(userID)
	if err != nil {
		log.Printf("ERROR HasAuthPermission: failed to get permissions: %v", err)
		return false
	}

	// Check exact match or wildcard
	for _, perm := range permissions {
		// Exact match
		if perm == permission {
			return true
		}

		// Wildcard match: auth.* matches anything starting with auth.
		if strings.HasSuffix(perm, ".*") {
			prefix := strings.TrimSuffix(perm, "*") // e.g., "auth." from "auth.*"
			if strings.HasPrefix(permission, prefix) {
				return true
			}
		}
	}

	return false
}

// HasAnyAuthPermission checks if user has at least one of the specified permissions
func HasAnyAuthPermission(userID primitive.ObjectID, permissions ...string) bool {
	for _, perm := range permissions {
		if HasAuthPermission(userID, perm) {
			return true
		}
	}
	return false
}

// IsSystemAdmin checks if user is a system admin via user_service_roles collection.
// A system admin is a user who has "admin" or "GOD" role in the auth service,
// or "admin" role in the legacy "system" service.
// NOTE: Must stay in sync with checkAdminInRoles() in routes/middleware.go.
func IsSystemAdmin(userID primitive.ObjectID) bool {
	// Check auth service roles
	roles, err := GetUserServiceRolesByUserIDAndService(userID, "auth")
	if err != nil {
		log.Printf("ERROR IsSystemAdmin: failed to get user service roles: %v", err)
		return false
	}

	adminRoles := map[string]bool{
		"admin": true,
		"GOD":   true,
	}

	for _, r := range roles {
		if r.IsActive && adminRoles[r.RoleName] {
			return true
		}
	}

	// Check legacy system/admin role
	systemRoles, err := GetUserServiceRolesByUserIDAndService(userID, "system")
	if err != nil {
		return false
	}
	for _, r := range systemRoles {
		if r.IsActive && r.RoleName == "admin" {
			return true
		}
	}

	return false
}

// GetUserServiceRolesByUserIDAndService returns all service roles for a user in a specific service
func GetUserServiceRolesByUserIDAndService(userID primitive.ObjectID, serviceKey string) ([]UserServiceRole, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Search by both "service_key" (new format) and "service" (legacy format)
	// to handle documents that haven't been migrated yet.
	filter := bson.M{
		"user_id": userID,
		"$or": []bson.M{
			{"service_key": serviceKey},
			{"service": serviceKey},
		},
	}

	cursor, err := userServiceRolesCol.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query user service roles: %v", err)
	}
	defer cursor.Close(ctx)

	var roles []UserServiceRole
	if err = cursor.All(ctx, &roles); err != nil {
		return nil, fmt.Errorf("failed to decode user service roles: %v", err)
	}

	return roles, nil
}
