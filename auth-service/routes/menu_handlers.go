package routes

import (
	"auth-service/models"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// homeHandler handles the home page
func homeHandler(c *gin.Context) {
	c.Redirect(http.StatusFound, "/menu")
}

// healthHandler handles health check requests
func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "auth-service",
	})
}

// menuHandler shows the list of accessible services
func menuHandler(c *gin.Context) {
	// Get user from middleware
	user := c.MustGet("user").(*models.User)

	// Get user's accessible services based on their service roles
	accessibleServices := []string{}

	// Check if user is admin (has admin role in old system or system service)
	// NEW: Check if user has full admin access (auth.* wildcard)
	isAdmin := hasAnyAuthPermission(user, "auth.*")

	if isAdmin {
		fmt.Println("Пользователь является администратором. Добавление всех сервисов.")
		// Admin users can access all services
		services, err := models.GetAllServices()
		if err != nil {
			fmt.Printf("Ошибка получения сервисов для админа: %v\n", err)
		} else {
			for _, service := range services {
				accessibleServices = append(accessibleServices, service.Key)
			}
		}
	} else {
		// For regular users, get services where they have roles
		userAccessibleServices, err := models.GetUserAccessibleServices(user.ID)
		if err != nil {
			fmt.Printf("Ошибка получения доступных сервисов для пользователя %s: %v\n", user.Username, err)
		} else {
			accessibleServices = userAccessibleServices
		}

		// Also include services from old role system for backward compatibility
		roles, err := models.GetAllRoles()
		if err == nil {
			for _, userRole := range user.Roles {
				for _, role := range roles {
					if role.Name == userRole && role.ServiceKey != "" {
						if !contains(accessibleServices, role.ServiceKey) {
							accessibleServices = append(accessibleServices, role.ServiceKey)
						}
					}
				}
			}
		}
	}

	// Debug output
	fmt.Printf("Доступные сервисы для пользователя %s: %v\n", user.Username, accessibleServices)
	fmt.Printf("Пользователь %s является админом: %v\n", user.Username, isAdmin)

	// Create a slice of service infos with display names
	serviceInfos := []gin.H{}
	for _, serviceKey := range accessibleServices {
		// Skip 'auth' service - it's not a regular service card, but system settings
		if serviceKey == "auth" {
			continue
		}

		// Check user's role in this service
		hasServiceManager := hasServiceManagerRole(user, serviceKey)
		hasExternalRole := hasExternalRoleForService(user, serviceKey)
		hasAnyServiceRole := hasAnyRoleInService(user, serviceKey)

		serviceInfo := gin.H{
			"id":          serviceKey,
			"displayName": getServiceDisplayName(serviceKey),
			"icon":        getIconForService(serviceKey),
			"description": getServiceDescription(serviceKey),
		}

		// Can manage service if: system admin OR service manager OR has external role for this service
		canManageService := isAdmin || hasServiceManager || hasExternalRole
		serviceInfo["canManage"] = canManageService

		// Debug logging for access control
		fmt.Printf("[MENU DEBUG] Service=%s User=%s isAdmin=%v hasServiceManager=%v hasExternalRole=%v hasAnyRole=%v canManage=%v\n",
			serviceKey, user.Username, isAdmin, hasServiceManager, hasExternalRole, hasAnyServiceRole, canManageService) // Show service card if: system admin OR has any role in service (including admin) OR has external role
		showServiceCard := isAdmin || hasAnyServiceRole || hasExternalRole

		if showServiceCard {
			// Always get service info for health check (needed for all users)
			service, err := models.GetServiceByKey(serviceKey)
			if err == nil && service != nil {
				serviceInfo["serviceKey"] = service.Key
				fmt.Printf("Добавлен serviceKey для %s: %s (isSystemAdmin: %v, isServiceManager: %v, canManage: %v)\n",
					serviceKey, service.Key, isAdmin, hasServiceManager, canManageService)
			} else {
				fmt.Printf("Ошибка получения сервиса для %s: %v\n", serviceKey, err)
			}

			serviceInfos = append(serviceInfos, serviceInfo)
		}
	}

	// Check if user has permission to view system settings (must be system admin)
	// NEW: Check if user can view system settings - any role in auth service allows access
	canViewSystemSettings := hasAuthPermission(user, "auth.settings.view") ||
		hasAuthPermission(user, "auth.dashboard.view") ||
		hasAnyRoleInService(user, "auth")
	fmt.Printf("User %s can view system settings: %v\n", user.Username, canViewSystemSettings)

	c.HTML(http.StatusOK, "menu.html", gin.H{
		"username":              user.Username,
		"full_name":             user.GetFullName(),
		"short_name":            user.GetShortName(),
		"user":                  user,               // Add full user object for header template
		"services":              accessibleServices, // Keep for backward compatibility
		"serviceInfos":          serviceInfos,       // New structure with display names
		"isAdmin":               hasAnyAuthPermission(user, "auth.*"),
		"canViewSystemSettings": canViewSystemSettings,
		"role":                  user.Roles,
	})
}

// getServiceDisplayName returns a user-friendly name for a service
func getServiceDisplayName(serviceKey string) string {
	// Try to get the display name from services collection
	service, err := models.GetServiceByKey(serviceKey)
	if err == nil && service != nil && service.Name != "" {
		return service.Name
	}

	// Fallback to permissions collection for backward compatibility
	permission, err := models.GetPermissionByService(serviceKey)
	if err == nil && permission.DisplayName != "" {
		return permission.DisplayName
	}

	// Default to the original service key if not found
	return serviceKey
}

// getServiceDescription returns a description for a service
func getServiceDescription(serviceKey string) string {
	// Try to get the description from services collection
	service, err := models.GetServiceByKey(serviceKey)
	if err == nil && service != nil && service.Description != "" {
		return service.Description
	}

	// Default descriptions for known services
	switch serviceKey {
	case "client-service":
		return "Управление клиентами и их данными"
	case "referal":
		return "Система реферальных программ и бонусов"
	case "microservices-v2":
		return "Микросервисная архитектура версии 2.0"
	case "admin-service":
		return "Административные функции системы"
	case "AppartmentFinder":
		return "Поиск и анализ недвижимости"
	default:
		return "Сервис " + serviceKey
	}
}

// getIconForService returns an appropriate Font Awesome icon for each service
func getIconForService(service string) string {
	// Get icon from database if available
	permission, err := models.GetPermissionByService(service)
	if err == nil && permission.Icon != "" {
		return permission.Icon
	}

	// Default icon if no specific icon is defined
	return "link"
}

// systemSettingsHandler shows system settings page with admin functions
func systemSettingsHandler(c *gin.Context) {
	// Get user from middleware
	user := c.MustGet("user").(*models.User)

	// Check if user has any role in auth service or specific permissions
	hasAccess := hasAuthPermission(user, "auth.settings.view") ||
		hasAuthPermission(user, "auth.dashboard.view") ||
		hasAnyRoleInService(user, "auth")

	if !hasAccess {
		c.Redirect(http.StatusFound, "/access-denied")
		return
	}

	// Determine what user can do based on their permissions
	// User management - any users permission allows access to users page
	canManageUsers := hasAnyAuthPermission(user, "auth.users.view", "auth.users.create", "auth.users.edit", "auth.*")

	// Services management - requires edit/create permissions, not just view
	// View permission only allows seeing auth service roles, not all services management
	canManageServices := hasAnyAuthPermission(user, "auth.services.create", "auth.services.edit", "auth.services.delete", "auth.*")

	// Auth service roles - view permission is enough to see auth service settings
	canViewAuthRoles := hasAnyAuthPermission(user, "auth.roles.view", "auth.roles.create", "auth.roles.edit", "auth.*")

	// Logs - view permission is enough
	canViewLogs := hasAnyAuthPermission(user, "auth.logs.view", "auth.*")

	// Notifications - requires manage permission
	canManageNotifications := hasAnyAuthPermission(user, "auth.notifications.send", "auth.settings.edit", "auth.*")

	c.HTML(http.StatusOK, "settings.html", gin.H{
		"username":               user.Username,
		"full_name":              user.GetFullName(),
		"short_name":             user.GetShortName(),
		"user":                   user,
		"canManageUsers":         canManageUsers,
		"canManageServices":      canManageServices,
		"canManageRoles":         canViewAuthRoles,
		"canViewLogs":            canViewLogs,
		"canManageNotifications": canManageNotifications,
	})
}

// Helper function to check if a slice contains a string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}
