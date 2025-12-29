package models

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
)

// RoleWithUsers represents a role with additional metadata
type RoleWithUsers struct {
	Role
	UserCount             int            `json:"user_count"`
	PermissionsByCategory map[string]int `json:"permissions_by_category"` // category -> count
}

// PermissionCategory represents a grouped set of permissions
type PermissionCategory struct {
	Name        string          `json:"name"`         // "users", "services", etc.
	DisplayName string          `json:"display_name"` // "Управление пользователями"
	Icon        string          `json:"icon"`         // emoji или icon class
	Permissions []PermissionDef `json:"permissions"`
	Count       int             `json:"count"`
	Category    string          `json:"category"` // Alias for Name for template compatibility
}

// SimplePermission represents a simplified permission for display
type SimplePermission struct {
	Code        string `json:"code"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

// ExternalPermissionCategory represents external permissions grouped by category
type ExternalPermissionCategory struct {
	Category    string             `json:"category"`
	Permissions []SimplePermission `json:"permissions"`
}

// GetRolesWithUserCount returns all roles for a service with user counts
func GetRolesWithUserCount(serviceKey string) ([]RoleWithUsers, error) {
	// Get all roles for the service
	roles, err := GetRolesByService(serviceKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %v", err)
	}

	result := make([]RoleWithUsers, 0, len(roles))

	for _, role := range roles {
		// Count users with this role
		userCount, err := countUsersWithRole(serviceKey, role.Name)
		if err != nil {
			log.Printf("Warning: failed to count users for role %s: %v", role.Name, err)
			userCount = 0
		}

		// Group permissions by category
		permsByCategory := groupPermissionsByCategory(role.Permissions)

		roleWithUsers := RoleWithUsers{
			Role:      role,
			UserCount: userCount,
		}

		// Convert category map to permission counts
		roleWithUsers.PermissionsByCategory = make(map[string]int)
		for category, perms := range permsByCategory {
			roleWithUsers.PermissionsByCategory[category] = len(perms)
		}

		result = append(result, roleWithUsers)
	}

	return result, nil
}

// countUsersWithRole counts users with a specific role for a service
func countUsersWithRole(serviceKey, roleName string) (int, error) {
	ctx := context.Background()

	// Count in user_service_roles collection
	count, err := userServiceRolesCol.CountDocuments(ctx, bson.M{
		"service_key": serviceKey,
		"role_name":   roleName,
		"is_active":   true,
	})

	return int(count), err
}

// groupPermissionsByCategory groups a list of permission names by their category
func groupPermissionsByCategory(permissionNames []string) map[string][]string {
	categories := make(map[string][]string)

	for _, permName := range permissionNames {
		// Wildcard permissions go into "all" category
		if strings.HasSuffix(permName, ".*") {
			categories["all"] = append(categories["all"], permName)
			continue
		}

		// Extract category from permission name (e.g., "auth.users.view" -> "users")
		parts := strings.Split(permName, ".")
		if len(parts) >= 2 {
			category := parts[1] // Second part after service prefix
			categories[category] = append(categories[category], permName)
		} else {
			categories["other"] = append(categories["other"], permName)
		}
	}

	return categories
}

// GetPermissionsByCategory returns permissions for a service grouped by category
func GetPermissionsByCategory(serviceKey string) ([]PermissionCategory, error) {
	// Get service permissions
	service, err := GetServiceByKey(serviceKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get service: %v", err)
	}

	// Group permissions by category (extracted from permission name)
	categoryMap := make(map[string][]PermissionDef)

	for _, perm := range service.AvailablePermissions {
		// Skip deleted permissions
		if !perm.DeletedAt.IsZero() {
			continue
		}

		// Extract category from permission name (auth.users.view -> users)
		parts := strings.Split(perm.Name, ".")
		if len(parts) >= 2 {
			category := parts[1]
			categoryMap[category] = append(categoryMap[category], perm)
		} else {
			categoryMap["other"] = append(categoryMap["other"], perm)
		}
	}

	// Convert to sorted slice
	categories := make([]PermissionCategory, 0, len(categoryMap))

	for catName, perms := range categoryMap {
		// Sort permissions within category
		sort.Slice(perms, func(i, j int) bool {
			return perms[i].Name < perms[j].Name
		})

		category := PermissionCategory{
			Name:        catName,
			DisplayName: getCategoryDisplayName(catName),
			Icon:        getCategoryIcon(catName),
			Permissions: perms,
			Count:       len(perms),
		}

		categories = append(categories, category)
	}

	// Sort categories by name
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Name < categories[j].Name
	})

	return categories, nil
}

// getCategoryDisplayName returns a human-readable name for a category
func getCategoryDisplayName(category string) string {
	displayNames := map[string]string{
		"users":          "Пользователи",
		"services":       "Сервисы",
		"roles":          "Роли",
		"permissions":    "Разрешения",
		"documents":      "Документы",
		"document_types": "Типы документов",
		"logs":           "Логи",
		"settings":       "Настройки",
		"notifications":  "Уведомления",
		"import_export":  "Импорт/Экспорт",
		"api":            "API",
		"system":         "Система",
		"dashboard":      "Дашборд",
		"all":            "Все разрешения",
		"other":          "Прочее",
	}

	if displayName, ok := displayNames[category]; ok {
		return displayName
	}
	return strings.Title(category)
}

// getCategoryIcon returns an icon class for a category (FontAwesome без эмодзи)
func getCategoryIcon(category string) string {
	icons := map[string]string{
		"users":          "users",
		"services":       "cogs",
		"roles":          "user-tag",
		"permissions":    "key",
		"documents":      "file-alt",
		"document_types": "folder",
		"logs":           "list",
		"settings":       "cog",
		"notifications":  "bell",
		"import_export":  "exchange-alt",
		"api":            "code",
		"system":         "server",
		"dashboard":      "tachometer-alt",
		"all":            "star",
		"other":          "ellipsis-h",
	}

	if icon, ok := icons[category]; ok {
		return icon
	}
	return "folder"
}

// GetExternalServiceRoles returns auth-service roles that manage a specific service
// These are roles that ONLY have external permissions (external=true)
// Excludes system roles like GOD, admin
func GetExternalServiceRoles(serviceKey string) ([]RoleWithUsers, error) {
	// Get all auth-service roles
	authRoles, err := GetRolesWithUserCount("auth")
	if err != nil {
		return nil, fmt.Errorf("failed to get auth roles: %v", err)
	}

	// Get external permissions for this service
	authService, err := GetServiceByKey("auth")
	if err != nil {
		return nil, fmt.Errorf("failed to get auth service: %v", err)
	}

	// Build set of external permission names for this service
	externalPermNames := make(map[string]bool)
	prefix := fmt.Sprintf("auth.%s.", serviceKey)
	for _, perm := range authService.AvailablePermissions {
		if perm.External && strings.HasPrefix(perm.Name, prefix) {
			externalPermNames[perm.Name] = true
		}
	}

	// System roles to exclude (they have auth.* wildcard or are general admin roles)
	systemRoleNames := map[string]bool{
		"GOD":   true,
		"god":   true,
		"admin": true,
		"Admin": true,
		"ADMIN": true,
	}

	// Filter roles that ONLY have external permissions for this service
	var externalRoles []RoleWithUsers
	for _, role := range authRoles {
		// Skip system roles
		if systemRoleNames[role.Name] {
			continue
		}

		// Check if role has wildcard auth.* permission (system role)
		hasWildcard := false
		for _, perm := range role.Permissions {
			if perm == "auth.*" {
				hasWildcard = true
				break
			}
		}
		if hasWildcard {
			continue
		}

		// Check if role has at least one external permission for this service
		hasExternalPerm := false
		for _, perm := range role.Permissions {
			if externalPermNames[perm] {
				hasExternalPerm = true
				break
			}
		}

		if hasExternalPerm {
			externalRoles = append(externalRoles, role)
		}
	}

	return externalRoles, nil
}

// GetExternalServicePermissions returns auth permissions for managing a service
// Only returns permissions where external=true
// These are permissions with format auth.<service-key>.<action>
// Example: For serviceKey="referal", returns auth.referal.users.view, auth.referal.users.manage, etc.
func GetExternalServicePermissions(serviceKey string) ([]PermissionCategory, error) {
	// Get auth service
	authService, err := GetServiceByKey("auth")
	if err != nil {
		return nil, fmt.Errorf("failed to get auth service: %v", err)
	}

	// Filter permissions that:
	// 1. Start with auth.<service-key>.
	// 2. Have external=true flag
	prefix := fmt.Sprintf("auth.%s.", serviceKey)
	var servicePermissions []PermissionDef

	for _, perm := range authService.AvailablePermissions {
		// Skip deleted permissions
		if !perm.DeletedAt.IsZero() {
			continue
		}

		// Only include external permissions for this service
		if perm.External && strings.HasPrefix(perm.Name, prefix) {
			servicePermissions = append(servicePermissions, perm)
		}
	}

	// Group by category (extract from auth.referal.users.manage -> users)
	categoryMap := make(map[string][]PermissionDef)

	for _, perm := range servicePermissions {
		// Extract category: auth.referal.users.manage -> users
		parts := strings.Split(perm.Name, ".")
		if len(parts) >= 3 {
			category := parts[2] // Third part is the category
			categoryMap[category] = append(categoryMap[category], perm)
		} else {
			categoryMap["other"] = append(categoryMap["other"], perm)
		}
	}

	// Convert to sorted slice
	categories := make([]PermissionCategory, 0, len(categoryMap))

	for catName, perms := range categoryMap {
		// Sort permissions within category
		sort.Slice(perms, func(i, j int) bool {
			return perms[i].Name < perms[j].Name
		})

		category := PermissionCategory{
			Name:        catName,
			DisplayName: getCategoryDisplayName(catName),
			Icon:        getCategoryIcon(catName),
			Permissions: perms,
			Count:       len(perms),
		}

		categories = append(categories, category)
	}

	// Sort categories by name
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Name < categories[j].Name
	})

	return categories, nil
}

// GetExternalRolesForService returns auth-service roles that grant access to the specified service
// These are roles in auth-service that have permissions matching auth.<serviceKey>.*
func GetExternalRolesForService(serviceKey string) ([]Role, error) {
	// Get all roles from auth-service (key is "auth", not "auth-service")
	authRoles, err := GetRolesByService("auth")
	if err != nil {
		log.Printf("ERROR: GetExternalRolesForService - failed to get auth roles: %v", err)
		return nil, fmt.Errorf("failed to get auth-service roles: %v", err)
	}
	log.Printf("DEBUG: GetExternalRolesForService - found %d roles in auth service", len(authRoles))

	prefix := fmt.Sprintf("auth.%s.", serviceKey)

	// System roles to exclude
	systemRoleNames := map[string]bool{
		"GOD":   true,
		"god":   true,
		"admin": true,
		"Admin": true,
		"ADMIN": true,
	}

	// Filter roles that have external permissions for this service
	var externalRoles []Role
	for _, role := range authRoles {
		// Skip system roles
		if systemRoleNames[role.Name] {
			continue
		}

		// Skip roles with wildcard auth.* permission (full admin)
		hasWildcard := false
		for _, perm := range role.Permissions {
			if perm == "auth.*" {
				hasWildcard = true
				break
			}
		}
		if hasWildcard {
			continue
		}

		// Check if role has at least one permission for this service
		hasExternalPerm := false
		for _, perm := range role.Permissions {
			if strings.HasPrefix(perm, prefix) {
				hasExternalPerm = true
				break
			}
		}

		if hasExternalPerm {
			externalRoles = append(externalRoles, role)
		}
	}

	return externalRoles, nil
}

// GetExternalPermissionsForService returns all external permissions defined for a service
// grouped by category. These are permissions in auth-service with names like auth.<serviceKey>.*
func GetExternalPermissionsForService(serviceKey string) ([]ExternalPermissionCategory, error) {
	log.Printf("DEBUG: GetExternalPermissionsForService called for serviceKey: %s", serviceKey)

	// Get auth service (key is "auth", not "auth-service")
	authService, err := GetServiceByKey("auth")
	if err != nil {
		log.Printf("ERROR: Failed to get auth service: %v", err)
		return nil, fmt.Errorf("failed to get auth-service: %v", err)
	}

	log.Printf("DEBUG: Auth service found, has %d available permissions", len(authService.AvailablePermissions))

	prefix := fmt.Sprintf("auth.%s.", serviceKey)
	log.Printf("DEBUG: Looking for permissions with prefix: %s", prefix)

	var permissions []PermissionDef
	for _, perm := range authService.AvailablePermissions {
		// Skip deleted permissions
		if !perm.DeletedAt.IsZero() {
			continue
		}

		// Include permissions that control access to this service
		if perm.External && strings.HasPrefix(perm.Name, prefix) {
			log.Printf("DEBUG: Found external permission: %s (external=%v)", perm.Name, perm.External)
			permissions = append(permissions, perm)
		}
	}

	log.Printf("DEBUG: Total external permissions found: %d", len(permissions))

	// Group permissions by category (extract from auth.referal.users.manage -> users)
	categoryMap := make(map[string][]PermissionDef)

	for _, perm := range permissions {
		// Extract category: auth.referal.users.manage -> users
		parts := strings.Split(perm.Name, ".")
		if len(parts) >= 3 {
			category := parts[2] // Third part is the category
			categoryMap[category] = append(categoryMap[category], perm)
		} else {
			categoryMap["other"] = append(categoryMap["other"], perm)
		}
	}

	// Convert to slice of ExternalPermissionCategory
	categories := make([]ExternalPermissionCategory, 0, len(categoryMap))

	for catName, perms := range categoryMap {
		// Sort permissions within category
		sort.Slice(perms, func(i, j int) bool {
			return perms[i].Name < perms[j].Name
		})

		category := ExternalPermissionCategory{
			Category:    catName,
			Permissions: convertToSimplePermissions(perms),
		}

		categories = append(categories, category)
	}

	// Sort categories by name
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Category < categories[j].Category
	})

	return categories, nil
}

// convertToSimplePermissions converts PermissionDef slice to SimplePermission slice
func convertToSimplePermissions(perms []PermissionDef) []SimplePermission {
	result := make([]SimplePermission, len(perms))
	for i, p := range perms {
		result[i] = SimplePermission{
			Code:        p.Name,
			DisplayName: p.DisplayName,
			Description: p.Description,
		}
	}
	return result
}
