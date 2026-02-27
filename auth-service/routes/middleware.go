package routes

import (
	"auth-service/models"
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
		return models.GetJWTSecret(), nil
	})

	if err != nil || !token.Valid {
		return nil, false
	}

	// SECURITY: Check if token is blacklisted
	if models.IsTokenBlacklisted(claims) {
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
		// Use validateToken for consistent blacklist checking
		claims, valid := validateToken(cookie)
		if !valid {
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

		// Fetch roles ONCE for all subsequent checks in this request
		roles := getUserRolesCached(c, user)

		// Check if user is system admin using new service_roles system
		isSystemAdmin := hasAdminRoleWithRoles(roles, user.Username)

		// If system admin, allow access to everything
		if isSystemAdmin {
			c.Set("isSystemAdmin", true)
			c.Next()
			return
		}

		// For service-specific routes, check if user is admin of that service
		serviceID := c.Param("id")
		serviceKey := c.Param("serviceKey")

		log.Printf("Middleware: serviceID='%s', serviceKey='%s', path='%s'", serviceID, serviceKey, c.Request.URL.Path)

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

			// Check if user is admin of this service (using cached roles)
			if checkServiceAdminInRoles(roles, service.Key) {
				c.Set("isSystemAdmin", false)
				c.Set("isServiceManager", false)
				c.Set("serviceKey", service.Key)
				c.Next()
				return
			}

			// Check if user is service-manager of this service (using cached roles)
			if checkServiceManagerInRoles(roles, service.Key) {
				c.Set("isSystemAdmin", false)
				c.Set("isServiceManager", true)
				c.Set("serviceKey", service.Key)
				c.Next()
				return
			}

			// Check if user has an external role that grants access to this service (using cached roles)
			if checkExternalRoleInRoles(roles, user.Username, service.Key) {
				c.Set("isSystemAdmin", false)
				c.Set("isServiceManager", false)
				c.Set("hasExternalRoleAccess", true)
				c.Set("serviceKey", service.Key)
				c.Next()
				return
			}
		}

		// Handle service routes by key (new excel import/export routes)
		if serviceKey != "" {
			// Get service by key
			service, err := models.GetServiceByKey(serviceKey)
			if err != nil {
				c.HTML(http.StatusNotFound, "error.html", gin.H{
					"error": "Сервис не найден",
				})
				c.Abort()
				return
			}

			// Check if user is admin of this service (using cached roles)
			if checkServiceAdminInRoles(roles, service.Key) {
				c.Set("isSystemAdmin", false)
				c.Set("isServiceManager", false)
				c.Set("serviceKey", service.Key)
				c.Next()
				return
			}

			// Check if user is service-manager of this service (using cached roles)
			if checkServiceManagerInRoles(roles, service.Key) {
				c.Set("isSystemAdmin", false)
				c.Set("isServiceManager", true)
				c.Set("serviceKey", service.Key)
				c.Next()
				return
			}

			// Check if user has an external role that grants access to this service (using cached roles)
			if checkExternalRoleInRoles(roles, user.Username, service.Key) {
				c.Set("isSystemAdmin", false)
				c.Set("isServiceManager", false)
				c.Set("hasExternalRoleAccess", true)
				c.Set("serviceKey", service.Key)
				c.Next()
				return
			}
		}

		// No access
		log.Printf("Middleware: Access denied for user='%s', path='%s'", user.Username, c.Request.URL.Path)
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "У вас нет прав для доступа к этому ресурсу",
		})
		c.Abort()
	}
}

// getUserRolesCached returns user's service roles, fetching once per request via gin.Context cache.
// This eliminates N+1 DB queries when multiple role checks happen in one request.
func getUserRolesCached(c *gin.Context, user *models.User) []models.UserServiceRole {
	if cached, exists := c.Get("_cachedUserRoles"); exists {
		return cached.([]models.UserServiceRole)
	}
	roles, err := models.GetUserServiceRolesByUserID(user.ID)
	if err != nil {
		log.Printf("Error fetching roles for user %s: %v", user.Username, err)
		roles = []models.UserServiceRole{}
	}
	c.Set("_cachedUserRoles", roles)
	return roles
}

// fetchUserRoles returns user's service roles from DB (for cases where gin.Context is unavailable).
func fetchUserRoles(user *models.User) []models.UserServiceRole {
	roles, err := models.GetUserServiceRolesByUserID(user.ID)
	if err != nil {
		log.Printf("Error fetching roles for user %s: %v", user.Username, err)
		return []models.UserServiceRole{}
	}
	return roles
}

// hasAdminRole checks if a user is a system administrator
func hasAdminRole(user *models.User) bool {
	return checkAdminInRoles(fetchUserRoles(user), user.Username)
}

// hasAdminRoleWithRoles checks admin role using pre-fetched roles
func hasAdminRoleWithRoles(roles []models.UserServiceRole, username string) bool {
	return checkAdminInRoles(roles, username)
}

// checkAdminInRoles checks if the given roles contain system admin.
// NOTE: Must stay in sync with IsSystemAdmin() in models/auth_permissions.go.
func checkAdminInRoles(userServiceRoles []models.UserServiceRole, username string) bool {
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
			log.Printf("User %s has GOD role (supreme administrator)", username)
			return true
		}

		// Also check for auth.admin role (system administrator)
		if serviceRole.ServiceKey == "auth" && serviceRole.RoleName == "admin" {
			log.Printf("User %s has auth.admin role (system administrator)", username)
			return true
		}
	}
	return false
}

// hasServiceAdminRole checks if a user has admin role in a specific service
func hasServiceAdminRole(user *models.User, serviceKey string) bool {
	return checkServiceAdminInRoles(fetchUserRoles(user), serviceKey)
}

func checkServiceAdminInRoles(roles []models.UserServiceRole, serviceKey string) bool {
	for _, role := range roles {
		if role.ServiceKey == serviceKey && role.RoleName == "admin" && role.IsActive {
			return true
		}
	}
	return false
}

// hasServiceManagerRole checks if a user has service-manager role in a specific service
func hasServiceManagerRole(user *models.User, serviceKey string) bool {
	return checkServiceManagerInRoles(fetchUserRoles(user), serviceKey)
}

func checkServiceManagerInRoles(roles []models.UserServiceRole, serviceKey string) bool {
	for _, role := range roles {
		if role.ServiceKey == serviceKey && role.RoleName == "service-manager" && role.IsActive {
			return true
		}
	}
	// Also check global service-manager role in auth service
	for _, role := range roles {
		if role.ServiceKey == "auth" && role.RoleName == "service-manager" && role.IsActive {
			return true
		}
	}
	return false
}

// hasExternalRoleForService checks if a user has any external role in auth service that grants access to a specific service
// External roles are roles in auth service with permissions like auth.<serviceKey>.*
func hasExternalRoleForService(user *models.User, serviceKey string) bool {
	return checkExternalRoleInRoles(fetchUserRoles(user), user.Username, serviceKey)
}

func checkExternalRoleInRoles(userServiceRoles []models.UserServiceRole, username string, serviceKey string) bool {
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

	// Check if user has any external role in auth service for this service
	for _, role := range userServiceRoles {
		if role.ServiceKey == "auth" && role.IsActive {
			if externalRoleNames[role.RoleName] {
				log.Printf("User %s has external role %s for service %s", username, role.RoleName, serviceKey)
				return true
			}
		}
	}

	return false
}

// hasAnyRoleInService checks if a user has any active role in a specific service
func hasAnyRoleInService(user *models.User, serviceKey string) bool {
	return checkAnyRoleInService(fetchUserRoles(user), serviceKey)
}

func checkAnyRoleInService(roles []models.UserServiceRole, serviceKey string) bool {
	for _, role := range roles {
		if role.ServiceKey == serviceKey && role.IsActive {
			return true
		}
	}
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

	serviceKey := c.Param("serviceKey")
	if serviceKey == "" {
		return false
	}

	return models.HasServicePermission(user.(*models.User).ID, serviceKey, permission)
}

// internalAPIKeyRequired is middleware that validates the X-API-Key header
// for service-to-service API calls. The key is configured via INTERNAL_API_KEY env var.
func internalAPIKeyRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := os.Getenv("INTERNAL_API_KEY")
		if apiKey == "" {
			log.Fatal("FATAL: INTERNAL_API_KEY environment variable is not set. " +
				"All /api/* endpoints would be unprotected. " +
				"Set INTERNAL_API_KEY in .env before starting the service.")
		}

		providedKey := c.GetHeader("X-API-Key")

		if providedKey != apiKey {
			log.Printf("WARNING: Invalid API key from %s for %s", c.ClientIP(), c.Request.URL.Path)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or missing API key",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
