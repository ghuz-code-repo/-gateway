package models

import (
	"fmt"
	"log"
	"strings"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// UserRolesByCategory categorizes user's roles into different types
type UserRolesByCategory struct {
	AuthServiceRoles []UserServiceRoleWithDetails // Internal auth-service roles (system administration)
	ExternalRoles    map[string][]UserServiceRoleWithDetails // serviceKey -> external roles (service administration)
	InternalRoles    map[string][]UserServiceRoleWithDetails // serviceKey -> internal roles (end-user roles)
}

// UserServiceRoleWithDetails extends UserServiceRole with role details
type UserServiceRoleWithDetails struct {
	UserServiceRole
	RoleDetails *Role `json:"role_details,omitempty"`
}

// GetAuthServiceInternalRoles returns internal roles defined in auth-service
// These are roles for system administration (NOT external service management roles)
func GetAuthServiceInternalRoles() ([]RoleWithUsers, error) {
	// Get all auth-service roles
	authRoles, err := GetRolesWithUserCount("auth")
	if err != nil {
		return nil, fmt.Errorf("failed to get auth roles: %v", err)
	}

	// System roles that are for auth-service itself
	var internalRoles []RoleWithUsers
	
	for _, role := range authRoles {
		// Check if this is an external role (manages other services)
		isExternal := false
		
		// External roles have permissions like auth.<service>.* (not auth.users.*, auth.roles.*)
		for _, perm := range role.Permissions {
			// Skip auth.* wildcard
			if perm == "auth.*" {
				continue
			}
			
			// Check if permission is for managing another service
			// Format: auth.<service-key>.<resource>.<action>
			// Example: auth.referal.users.view (external)
			// vs: auth.users.view (internal)
			parts := strings.Split(perm, ".")
			if len(parts) >= 3 {
				// If second part is NOT a standard auth-service resource, it's external
				secondPart := parts[1]
				authResources := map[string]bool{
					"users": true, "roles": true, "services": true, 
					"permissions": true, "dashboard": true, "logs": true,
					"settings": true, "api": true, "system": true,
				}
				
				if !authResources[secondPart] {
					isExternal = true
					break
				}
			}
		}
		
		if !isExternal {
			internalRoles = append(internalRoles, role)
		}
	}
	
	return internalRoles, nil
}

// GetInternalServiceRoles returns internal roles defined within a service
// These are roles for end-users of the service (NOT for managing the service from auth)
func GetInternalServiceRoles(serviceKey string) ([]RoleWithUsers, error) {
	// For now, services don't have their own internal roles
	// They use auth-service roles
	// This function is a placeholder for future when services have their own role systems
	
	// Return empty for now
	return []RoleWithUsers{}, nil
}

// GetUserRolesByCategory categorizes a user's roles into auth-service, external, and internal
func GetUserRolesByCategory(userID primitive.ObjectID) (*UserRolesByCategory, error) {
	// Get all user's service roles
	allRoles, err := GetUserServiceRolesByUserID(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %v", err)
	}

	result := &UserRolesByCategory{
		AuthServiceRoles: []UserServiceRoleWithDetails{},
		ExternalRoles:    make(map[string][]UserServiceRoleWithDetails),
		InternalRoles:    make(map[string][]UserServiceRoleWithDetails),
	}

	// Get all services to check which ones exist
	services, err := GetAllServices()
	if err != nil {
		log.Printf("Warning: failed to get services: %v", err)
		services = []Service{}
	}
	
	serviceKeys := make(map[string]bool)
	for _, svc := range services {
		serviceKeys[svc.Key] = true
	}

	for _, userRole := range allRoles {
		// Get role details
		roleDetails, err := GetRoleByServiceAndName(userRole.ServiceKey, userRole.RoleName)
		if err != nil {
			log.Printf("Warning: failed to get role details for %s/%s: %v", userRole.ServiceKey, userRole.RoleName, err)
			roleDetails = nil
		}

		roleWithDetails := UserServiceRoleWithDetails{
			UserServiceRole: userRole,
			RoleDetails:     roleDetails,
		}

		if userRole.ServiceKey == "auth" {
			// Check if this is an external role or internal auth role
			if roleDetails != nil {
				isExternal := false
				managedService := ""
				
				// Check permissions to determine if external
				for _, perm := range roleDetails.Permissions {
					// Skip wildcard
					if perm == "auth.*" {
						continue
					}
					
					parts := strings.Split(perm, ".")
					if len(parts) >= 3 {
						secondPart := parts[1]
						authResources := map[string]bool{
							"users": true, "roles": true, "services": true,
							"permissions": true, "dashboard": true, "logs": true,
							"settings": true, "api": true, "system": true,
						}
						
						if !authResources[secondPart] && serviceKeys[secondPart] {
							isExternal = true
							managedService = secondPart
							break
						}
					}
				}
				
				if isExternal && managedService != "" {
					result.ExternalRoles[managedService] = append(result.ExternalRoles[managedService], roleWithDetails)
				} else {
					result.AuthServiceRoles = append(result.AuthServiceRoles, roleWithDetails)
				}
			} else {
				// If we can't get role details, assume internal
				result.AuthServiceRoles = append(result.AuthServiceRoles, roleWithDetails)
			}
		} else {
			// Internal service role
			result.InternalRoles[userRole.ServiceKey] = append(result.InternalRoles[userRole.ServiceKey], roleWithDetails)
		}
	}

	return result, nil
}

// GetAllServicesWithRolesCategorized returns all services with their external and internal roles
type ServiceWithRolesCategorized struct {
	Service       Service
	ExternalRoles []RoleWithUsers // Roles in auth-service for managing this service
	InternalRoles []RoleWithUsers // Roles within the service itself
}

func GetAllServicesWithRolesCategorized() ([]ServiceWithRolesCategorized, error) {
	services, err := GetAllServices()
	if err != nil {
		return nil, fmt.Errorf("failed to get services: %v", err)
	}

	var result []ServiceWithRolesCategorized
	
	for _, service := range services {
		// Skip auth service (it's handled separately)
		if service.Key == "auth" {
			continue
		}
		
		externalRoles, err := GetExternalServiceRoles(service.Key)
		if err != nil {
			log.Printf("Warning: failed to get external roles for %s: %v", service.Key, err)
			externalRoles = []RoleWithUsers{}
		}
		
		internalRoles, err := GetInternalServiceRoles(service.Key)
		if err != nil {
			log.Printf("Warning: failed to get internal roles for %s: %v", service.Key, err)
			internalRoles = []RoleWithUsers{}
		}
		
		result = append(result, ServiceWithRolesCategorized{
			Service:       service,
			ExternalRoles: externalRoles,
			InternalRoles: internalRoles,
		})
	}
	
	return result, nil
}

