package routes

import (
	"auth-service/models"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// validateToken parses and validates a JWT token string
func validateToken(tokenString string) (*models.Claims, bool) {
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			jwtSecret = "default_jwt_secret_change_in_production"
		}
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		return nil, false
	}

	// SECURITY: Check if token is blacklisted
	if models.IsTokenBlacklisted(tokenString) {
		log.Printf("Security: Blocked blacklisted token for user %s", claims.UserID)
		return nil, false
	}

	return claims, true
}

// authRequired middleware checks if user is authenticated
func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie("token")
		if err != nil {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Parse and validate token
		claims, valid := validateToken(cookie)
		if !valid {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Get user info
		user, err := models.GetUserByID(claims.UserID)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"error": "Не удалось получить данные пользователя",
			})
			c.Abort()
			return
		}

		// Store user info for handlers
		c.Set("user", user)
		c.Set("username", user.Username)
		c.Set("full_name", user.GetFullName())
		c.Set("short_name", user.GetShortName())
		c.Next()
	}
}

// adminMiddleware checks if the user has admin role
func adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie("token")
		if err != nil {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Parse and validate token
		claims := &models.Claims{}
		token, err := jwt.ParseWithClaims(cookie, claims, func(token *jwt.Token) (interface{}, error) {
			jwtSecret := os.Getenv("JWT_SECRET")
			if jwtSecret == "" {
				jwtSecret = "default_jwt_secret_change_in_production"
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Get user info
		user, err := models.GetUserByID(claims.UserID)
		if err != nil {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Check if user has admin role
		if !hasAdminRole(user) {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"error": "Access denied. Admin role required.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// adminAuthRequired middleware for admin panel access
// NEW: Uses permission-based authorization - allows access to users with ANY auth permissions
func adminAuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get JWT token from cookie
		cookie, err := c.Cookie("token")
		if err != nil {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Parse and validate token
		claims, valid := validateToken(cookie)
		if !valid {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Get user info
		user, err := models.GetUserByID(claims.UserID)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"error": "Не удалось получить данные пользователя",
			})
			c.Abort()
			return
		}

		// Store user info for handlers
		c.Set("user", user)
		c.Set("username", user.Username)
		c.Set("full_name", user.GetFullName())
		c.Set("short_name", user.GetShortName())

		// NEW: Load all user's auth permissions into context
		permissions, _ := models.GetUserAuthPermissions(user.ID)
		c.Set("authPermissions", permissions)

		// NEW: Check if user has ANY auth permissions (including external permissions like auth.referal.*)
		// Users with external permissions should be able to access admin panel
		// Specific handlers will check for specific permissions
		if len(permissions) == 0 {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"error": "У вас нет прав для доступа к панели администратора",
			})
			c.Abort()
			return
		}

		// Set isSystemAdmin flag for backward compatibility
		// Users with auth.* wildcard are considered system admins
		isFullAdmin := models.HasAnyAuthPermission(user.ID, "auth.*")
		c.Set("isSystemAdmin", isFullAdmin)

		c.Next()
	}
}

// serviceAdminAuthRequired middleware ensures the user is a system admin or service admin for the specific service
func serviceAdminAuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get JWT token from cookie
		cookie, err := c.Cookie("token")
		if err != nil {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Parse and validate token
		claims, valid := validateToken(cookie)
		if !valid {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Get user info
		user, err := models.GetUserByID(claims.UserID)
		if err != nil || user == nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"error": "Не удалось получить данные пользователя",
			})
			c.Abort()
			return
		}

		// Store user info for handlers
		c.Set("user", user)
		c.Set("username", user.Username)
		c.Set("full_name", user.GetFullName())
		c.Set("short_name", user.GetShortName())

		// Check if user is system admin using new service_roles system
		isSystemAdmin := hasAdminRole(user)

		// If system admin, allow access to everything
		if isSystemAdmin {
			c.Set("isSystemAdmin", true)
			c.Next()
			return
		}

		// For service-specific routes, check if user is admin of that service
		serviceID := c.Param("id")
		serviceKey := c.Param("serviceKey")

		// If no serviceKey in URL params, check query params (for endpoints like /check-user-exists?serviceKey=xxx)
		if serviceKey == "" {
			serviceKey = c.Query("serviceKey")
		}

		fmt.Printf("DEBUG Middleware: serviceID='%s', serviceKey='%s', path='%s'\n", serviceID, serviceKey, c.Request.URL.Path)

		// If no serviceID in URL params, check query params
		if serviceID == "" {
			serviceID = c.Query("serviceId")
		}

		// Handle service routes by ID (existing services management routes)
		if serviceID != "" {
			// Get service by ID
			objID, err := primitive.ObjectIDFromHex(serviceID)
			if err != nil {
				c.HTML(http.StatusBadRequest, "error.html", gin.H{
					"error": "Неверный ID сервиса",
				})
				c.Abort()
				return
			}

			service, err := models.GetServiceByID(objID)
			if err != nil {
				c.HTML(http.StatusNotFound, "error.html", gin.H{
					"error": "Сервис не найден",
				})
				c.Abort()
				return
			}

			// Check if user is admin of this service
			if hasServiceAdminRole(user, service.Key) {
				c.Set("isSystemAdmin", false)
				c.Set("isServiceManager", false)
				c.Set("serviceKey", service.Key)
				c.Next()
				return
			}

			// Check if user is service-manager of this service
			if hasServiceManagerRole(user, service.Key) {
				c.Set("isSystemAdmin", false)
				c.Set("isServiceManager", true)
				c.Set("serviceKey", service.Key)
				c.Next()
				return
			}

			// Check if user has an external role that grants access to this service
			if hasExternalRoleForService(user, service.Key) {
				fmt.Printf("DEBUG Middleware: Access granted (external role by ID) for user='%s' in service='%s'\n", user.Username, service.Key)
				c.Set("isSystemAdmin", false)
				c.Set("isServiceManager", false)     // External role users have limited access based on permissions
				c.Set("hasExternalRoleAccess", true) // Mark as external role access
				c.Set("serviceKey", service.Key)
				c.Next()
				return
			}
		}

		// Handle service routes by key (new excel import/export routes)
		if serviceKey != "" {
			fmt.Printf("DEBUG Middleware: Processing serviceKey='%s'\n", serviceKey)
			// Get service by key
			service, err := models.GetServiceByKey(serviceKey)
			if err != nil {
				fmt.Printf("DEBUG Middleware: Service not found for key='%s': %v\n", serviceKey, err)
				c.HTML(http.StatusNotFound, "error.html", gin.H{
					"error": "Сервис не найден",
				})
				c.Abort()
				return
			}

			// Check if user is admin of this service
			fmt.Printf("DEBUG Middleware: Checking admin role for user='%s' in service='%s'\n", user.Username, service.Key)
			if hasServiceAdminRole(user, service.Key) {
				fmt.Printf("DEBUG Middleware: Access granted (admin) for user='%s' in service='%s'\n", user.Username, service.Key)
				c.Set("isSystemAdmin", false)
				c.Set("isServiceManager", false)
				c.Set("serviceKey", service.Key)
				c.Next()
				return
			}

			// Check if user is service-manager of this service
			if hasServiceManagerRole(user, service.Key) {
				fmt.Printf("DEBUG Middleware: Access granted (service-manager) for user='%s' in service='%s'\n", user.Username, service.Key)
				c.Set("isSystemAdmin", false)
				c.Set("isServiceManager", true)
				c.Set("serviceKey", service.Key)
				c.Next()
				return
			}

			// Check if user has an external role that grants access to this service
			if hasExternalRoleForService(user, service.Key) {
				fmt.Printf("DEBUG Middleware: Access granted (external role) for user='%s' in service='%s'\n", user.Username, service.Key)
				c.Set("isSystemAdmin", false)
				c.Set("isServiceManager", false)     // External role users have limited access based on permissions
				c.Set("hasExternalRoleAccess", true) // Mark as external role access
				c.Set("serviceKey", service.Key)
				c.Next()
				return
			}

			fmt.Printf("DEBUG Middleware: Access denied for user='%s' in service='%s'\n", user.Username, service.Key)
		}

		// No access
		fmt.Printf("DEBUG Middleware: Access denied - no valid service found for user='%s', serviceID='%s', serviceKey='%s', path='%s'\n", user.Username, serviceID, serviceKey, c.Request.URL.Path)
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "У вас нет прав для доступа к этому ресурсу",
		})
		c.Abort()
	}
}

// hasAdminRole checks if a user is a system administrator
func hasAdminRole(user *models.User) bool {
	// Check service_roles for system.admin or auth.GOD role
	userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
	if err != nil {
		fmt.Printf("Ошибка получения ролей для пользователя %s: %v\n", user.Username, err)
		return false
	}

	// Check if user has 'admin' role in 'system' service OR 'GOD' role in 'auth' service
	for _, serviceRole := range userServiceRoles {
		if !serviceRole.IsActive {
			continue
		}

		// Legacy system.admin role
		if serviceRole.ServiceKey == "system" && serviceRole.RoleName == "admin" {
			return true
		}

		// New auth.GOD role (supreme administrator)
		if serviceRole.ServiceKey == "auth" && serviceRole.RoleName == "GOD" {
			fmt.Printf("User %s has GOD role (supreme administrator)\n", user.Username)
			return true
		}

		// Also check for auth.admin role (system administrator)
		if serviceRole.ServiceKey == "auth" && serviceRole.RoleName == "admin" {
			fmt.Printf("User %s has auth.admin role (system administrator)\n", user.Username)
			return true
		}
	}
	return false
}

// hasServiceAdminRole checks if a user has admin role in a specific service
func hasServiceAdminRole(user *models.User, serviceKey string) bool {
	// Get user's service roles using ADR-001 system
	userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
	if err != nil {
		fmt.Printf("Ошибка получения ролей для пользователя %s: %v\n", user.Username, err)
		return false
	}

	// Check if user has 'admin' role in this specific service
	for _, role := range userServiceRoles {
		if role.ServiceKey == serviceKey && role.RoleName == "admin" && role.IsActive {
			fmt.Printf("Пользователь %s является админом сервиса %s\n", user.Username, serviceKey)
			return true
		}
	}

	fmt.Printf("Пользователь %s НЕ является админом сервиса %s\n", user.Username, serviceKey)
	return false
}

// hasServiceManagerRole checks if a user has service-manager role in a specific service
func hasServiceManagerRole(user *models.User, serviceKey string) bool {
	// Get user's service roles using ADR-001 system
	userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
	if err != nil {
		fmt.Printf("Ошибка получения ролей для пользователя %s: %v\n", user.Username, err)
		return false
	}

	// Check if user has 'service-manager' role in this specific service
	for _, role := range userServiceRoles {
		if role.ServiceKey == serviceKey && role.RoleName == "service-manager" && role.IsActive {
			fmt.Printf("Пользователь %s является service-manager сервиса %s\n", user.Username, serviceKey)
			return true
		}
	}

	// Also check if user has 'service-manager' role in auth service (global service manager)
	for _, role := range userServiceRoles {
		if role.ServiceKey == "auth" && role.RoleName == "service-manager" && role.IsActive {
			fmt.Printf("Пользователь %s является глобальным service-manager (auth.service-manager)\n", user.Username)
			return true
		}
	}

	fmt.Printf("Пользователь %s НЕ является service-manager сервиса %s\n", user.Username, serviceKey)
	return false
}

// hasExternalRoleForService checks if a user has any external role in auth service that grants access to a specific service
// External roles are roles in auth service with permissions like auth.<serviceKey>.*
func hasExternalRoleForService(user *models.User, serviceKey string) bool {
	// Get external roles defined for this service
	externalRoles, err := models.GetExternalRolesForService(serviceKey)
	if err != nil || len(externalRoles) == 0 {
		return false
	}

	// Build map of external role names
	externalRoleNames := make(map[string]bool)
	for _, role := range externalRoles {
		externalRoleNames[role.Name] = true
	}

	// Get user's roles
	userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
	if err != nil {
		return false
	}

	// Check if user has any external role in auth service for this service
	for _, role := range userServiceRoles {
		if role.ServiceKey == "auth" && role.IsActive {
			if externalRoleNames[role.RoleName] {
				fmt.Printf("Пользователь %s имеет внешнюю роль %s для доступа к сервису %s\n", user.Username, role.RoleName, serviceKey)
				return true
			}
		}
	}

	return false
}

// hasAnyRoleInService checks if a user has any active role in a specific service
func hasAnyRoleInService(user *models.User, serviceKey string) bool {
	// Get user's service roles using ADR-001 system
	userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
	if err != nil {
		fmt.Printf("Ошибка получения ролей для пользователя %s: %v\n", user.Username, err)
		return false
	}

	// Check if user has any active role in this specific service
	for _, role := range userServiceRoles {
		if role.ServiceKey == serviceKey && role.IsActive {
			fmt.Printf("Пользователь %s имеет роль %s в сервисе %s\n", user.Username, role.RoleName, serviceKey)
			return true
		}
	}

	// Also check old roles system for backward compatibility
	roles, err := models.GetAllRoles()
	if err == nil {
		for _, userRole := range user.Roles {
			for _, role := range roles {
				if role.Name == userRole && role.ServiceKey == serviceKey {
					fmt.Printf("Пользователь %s имеет старую роль %s в сервисе %s\n", user.Username, userRole, serviceKey)
					return true
				}
			}
		}
	}

	fmt.Printf("Пользователь %s НЕ имеет ролей в сервисе %s\n", user.Username, serviceKey)
	return false
}

// getUserContext extracts username and full name from gin context
func getUserContext(c *gin.Context) (string, string) {
	username := c.GetString("username")
	fullName := c.GetString("full_name")
	return username, fullName
}

// ============================================================================
// Permission-based authorization helpers
// ============================================================================

// hasAuthPermission checks if a user has a specific auth permission
// This uses the permission-based authorization system (ADR-001)
func hasAuthPermission(user *models.User, permission string) bool {
	return models.HasAuthPermission(user.ID, permission)
}

// hasAnyAuthPermission checks if a user has any of the specified auth permissions
func hasAnyAuthPermission(user *models.User, permissions ...string) bool {
	return models.HasAnyAuthPermission(user.ID, permissions...)
}

// requireAuthPermission checks if the current user (from context) has a specific permission
// Returns true if permission is granted, false otherwise
// This is a convenience function for handlers
func requireAuthPermission(c *gin.Context, permission string) bool {
	user, exists := c.Get("user")
	if !exists {
		return false
	}
	return hasAuthPermission(user.(*models.User), permission)
}

// requireServicePermission checks if the current user has a specific permission in a service
// Uses the service context from URL parameter :serviceKey
func requireServicePermission(c *gin.Context, permission string) bool {
	user, exists := c.Get("user")
	if !exists {
		return false
	}

	// System admins have all permissions
	if c.GetBool("isSystemAdmin") {
		return true
	}

	// Service managers have all permissions for their service
	if c.GetBool("isServiceManager") {
		return true
	}

	serviceKey := c.Param("serviceKey")
	if serviceKey == "" {
		return false
	}

	return models.HasServicePermission(user.(*models.User).ID, serviceKey, permission)
}
