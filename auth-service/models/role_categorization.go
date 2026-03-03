package models

import (
	"fmt"
	"log"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// UserRolesByCategory categorizes user's roles into different types
type UserRolesByCategory struct {
	AuthServiceRoles []UserServiceRoleWithDetails            // Internal auth-service roles (system administration)
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
// Uses the role_type field to filter — no hardcoded resource lists
func GetAuthServiceInternalRoles() ([]RoleWithUsers, error) {
	// Get all auth-service roles
	authRoles, err := GetRolesWithUserCount("auth")
	if err != nil {
		return nil, fmt.Errorf("failed to get auth roles: %v", err)
	}

	var internalRoles []RoleWithUsers
	for _, role := range authRoles {
		if role.IsInternal() {
			internalRoles = append(internalRoles, role)
		}
	}

	return internalRoles, nil
}

// GetInternalServiceRoles returns internal roles defined within a service
// These are roles for end-users of the service (NOT for managing the service from auth)
func GetInternalServiceRoles(serviceKey string) ([]RoleWithUsers, error) {
	// Get all roles for the service, then filter to internal only
	allRoles, err := GetRolesWithUserCount(serviceKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles for service %s: %v", serviceKey, err)
	}

	var internalRoles []RoleWithUsers
	for _, role := range allRoles {
		if role.IsInternal() {
			internalRoles = append(internalRoles, role)
		}
	}

	return internalRoles, nil
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
			// Use role_type field to determine if external or internal
			if roleDetails != nil && roleDetails.IsExternal() && roleDetails.ManagedService != "" {
				result.ExternalRoles[roleDetails.ManagedService] = append(result.ExternalRoles[roleDetails.ManagedService], roleWithDetails)
			} else {
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
