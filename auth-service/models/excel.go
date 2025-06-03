package models

import (
	"strings"
)

// UserImportData represents user data imported from Excel
type UserImportData struct {
	Username string
	Email    string
	Password string
	Roles    []string
}

// ParseRolesString parses a comma-separated list of roles
func ParseRolesString(rolesStr string) []string {
	// Split by comma and trim whitespace
	roles := []string{}
	for _, role := range strings.Split(rolesStr, ",") {
		trimmedRole := strings.TrimSpace(role)
		if trimmedRole != "" {
			roles = append(roles, trimmedRole)
		}
	}
	return roles
}
