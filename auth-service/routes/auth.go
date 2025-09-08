package routes

import (
	"auth-service/models"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// SetupAuthRoutes configures all the routes for authentication
func SetupAuthRoutes(router *gin.Engine) {
	// Auth routes
	router.GET("/", homeHandler)
	router.GET("/menu", menuHandler) // New menu handler
	router.GET("/login", loginPageHandler)
	router.POST("/login", loginHandler)
	router.GET("/logout", logoutHandler)
	router.GET("/verify", verifyHandler)

	// User management routes (protected by admin middleware)
	// Set up admin routes using the function from admin.go
	SetupAdminRoutes(router)

	// Add debug endpoint
	router.GET("/debug", debugHandler)
}

// homeHandler handles the home page
func homeHandler(c *gin.Context) {
	c.Redirect(http.StatusFound, "/menu")
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

// menuHandler shows the list of accessible services
func menuHandler(c *gin.Context) {
	// Check if user is authenticated
	cookie, err := c.Cookie("token")
	if err != nil {
		c.Redirect(http.StatusFound, "/auth/login?redirect=/menu")
		return
	}

	// Validate token
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(cookie, claims, func(token *jwt.Token) (interface{}, error) {
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			jwtSecret = "default_jwt_secret_change_in_production"
		}
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		c.Redirect(http.StatusFound, "/auth/login?redirect=/menu")
		return
	}

	// Get user info
	user, err := models.GetUserByID(claims.UserID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить данные пользователя",
		})
		return
	}

	// Get user's accessible services based on their service roles
	accessibleServices := []string{}

	// Check if user is admin (has admin role in old system or system service)
	isAdmin := hasAdminRole(user)
	
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

	// Create a slice of service infos with display names
	serviceInfos := []gin.H{}
	for _, service := range accessibleServices {
		serviceInfos = append(serviceInfos, gin.H{
			"id":          service,
			"displayName": getServiceDisplayName(service),
			"icon":        getIconForService(service),
		})
	}

	c.HTML(http.StatusOK, "menu.html", gin.H{
		"username":     user.Username,
		"full_name":    user.FullName,
		"services":     accessibleServices, // Keep for backward compatibility
		"serviceInfos": serviceInfos,       // New structure with display names
		"isAdmin":      hasAdminRole(user),
		"role":         user.Roles,
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

// loginPageHandler serves the login page
func loginPageHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"redirect": c.Query("redirect"),
	})
}

// loginHandler handles user login
func loginHandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	redirect := c.PostForm("redirect")

	user, valid := models.ValidateUser(username, password)
	if !valid {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"error":    "Invalid username or password",
			"redirect": redirect,
		})
		return
	}

	// Generate token
	tokenString, err := models.GenerateToken(user)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{
			"error":    "Failed to generate token",
			"redirect": redirect,
		})
		return
	}

	// Set token in cookie
	c.SetCookie("token", tokenString, 86400, "/", "", false, true) // 24 hours, http only

	// Redirect to requested page or menu
	if redirect == "" {
		redirect = "/menu"
	}
	c.Redirect(http.StatusFound, redirect)
}

// logoutHandler handles user logout
func logoutHandler(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "", false, true) // Delete cookie
	c.Redirect(http.StatusFound, "/auth/login")
}

// verifyHandler checks if a request is authenticated and has permission for the requested service
func verifyHandler(c *gin.Context) {
	cookie, err := c.Cookie("token")
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
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
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Extract service name from request path
	path := c.Request.Header.Get("X-Original-URI")
	if path == "" {
		path = c.Request.URL.Path
	}

	pathParts := strings.Split(path, "/")
	if len(pathParts) < 2 {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// Get the first non-empty part which is the service name
	var service string
	for _, part := range pathParts {
		if part != "" {
			service = part
			break
		}
	}

	// Get user info
	user, err := models.GetUserByID(claims.UserID)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Get user's roles and permissions for this service according to ADR-001
	serviceRoles, err := models.GetUserServiceRoles(claims.UserID, service)
	if err != nil {
		serviceRoles = []string{} // Default to empty if error
	}

	servicePermissions, err := models.GetUserServicePermissions(claims.UserID, service)
	if err != nil {
		servicePermissions = []string{} // Default to empty if error
	}

	// Check if user has any access to this service
	if len(serviceRoles) == 0 && len(servicePermissions) == 0 {
		// Admin role always has access to all services (legacy support)
		if hasAdminRole(user) {
			serviceRoles = []string{"admin"}
			// For admin, get all available permissions for the service
			adminPermissions, _ := models.GetUserServicePermissions(claims.UserID, service)
			servicePermissions = adminPermissions
		} else {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
	}

	// Set user information in response headers according to ADR-001
	c.Header("X-User-Name", user.Username)
	c.Header("X-User-ID", claims.UserID)

	// Base64 encode the full name to preserve non-ASCII characters
	encodedFullName := base64.StdEncoding.EncodeToString([]byte(user.FullName))
	c.Header("X-User-Full-Name", encodedFullName)
	c.Header("X-User-Full-Name-Encoding", "base64") // Add flag to indicate encoding

	// ADR-001: New service-scoped headers
	c.Header("X-User-Service-Roles", strings.Join(serviceRoles, ","))
	c.Header("X-User-Service-Permissions", strings.Join(servicePermissions, ","))

	// Legacy headers for backward compatibility
	c.Header("X-User-Roles", strings.Join(user.Roles, ","))
	if hasAdminRole(user) {
		c.Header("X-User-Admin", "true")
	}

	c.Status(http.StatusOK)
}

// adminMiddleware checks if the user has admin role
func adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie("token")
		if err != nil {
			c.Redirect(http.StatusFound, "/auth/login?redirect="+c.Request.URL.Path)
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
			c.Redirect(http.StatusFound, "/auth/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Get user info
		user, err := models.GetUserByID(claims.UserID)
		if err != nil {
			c.Redirect(http.StatusFound, "/auth/login?redirect="+c.Request.URL.Path)
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

// hasAdminRole checks if a user has the admin role
func hasAdminRole(user *models.User) bool {
	for _, roleName := range user.Roles {
		if roleName == "admin" {
			return true
		}
	}
	return false
}

// debugHandler shows detailed debug information
func debugHandler(c *gin.Context) {
	redirect := c.Query("redirect")

	// Try to get user info from token
	cookie, err := c.Cookie("token")
	if err != nil {
		c.HTML(http.StatusOK, "debug.html", gin.H{
			"error":    "No authentication token found",
			"redirect": redirect,
		})
		return
	}

	// Parse token
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(cookie, claims, func(token *jwt.Token) (interface{}, error) {
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			jwtSecret = "default_jwt_secret_change_in_production"
		}
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		c.HTML(http.StatusOK, "debug.html", gin.H{
			"error":    "Invalid token: " + err.Error(),
			"redirect": redirect,
		})
		return
	}

	// Get user
	user, err := models.GetUserByID(claims.UserID)
	if err != nil {
		c.HTML(http.StatusOK, "debug.html", gin.H{
			"error":    "Failed to get user: " + err.Error(),
			"redirect": redirect,
		})
		return
	}

	// Extract service name from redirect
	var serviceName string
	if redirect != "" {
		parts := strings.Split(redirect, "/")
		for _, part := range parts {
			if part != "" {
				serviceName = part
				break
			}
		}
	}

	// Get user's permissions
	permissions := []string{}
	roles, _ := models.GetAllRoles()
	for _, roleName := range user.Roles {
		for _, role := range roles {
			if role.Name == roleName {
				permissions = append(permissions, role.Permissions...)
			}
		}
	}

	c.HTML(http.StatusOK, "debug.html", gin.H{
		"user":          user,
		"roles":         user.Roles,
		"permissions":   permissions,
		"serviceName":   serviceName,
		"hasPermission": models.CheckPermission(claims.UserID, serviceName),
		"redirect":      redirect,
	})
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
