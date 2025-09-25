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

		// Check if user has admin role
		isAdmin := false
		for _, roleName := range user.Roles {
			if roleName == "admin" {
				isAdmin = true
				break
			}
		}

		if !isAdmin {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"error": "У вас нет прав для доступа к панели администратора",
			})
			c.Abort()
			return
		}

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

		// Check if user is system admin (by role, not username)
		isSystemAdmin := false
		for _, roleName := range user.Roles {
			if roleName == "admin" {
				isSystemAdmin = true
				break
			}
		}
		
		// If system admin, allow access to everything
		if isSystemAdmin {
			c.Set("isSystemAdmin", true)
			c.Next()
			return
		}

		// For service-specific routes, check if user is admin of that service
		serviceID := c.Param("id")
		serviceKey := c.Param("serviceKey")
		
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

			// Check if user is admin of this service
			if hasServiceAdminRole(user, service.Key) {
				c.Set("isSystemAdmin", false)
				c.Set("serviceKey", service.Key)
				c.Next()
				return
			}
		}

		// No access
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "У вас нет прав для доступа к этому ресурсу",
		})
		c.Abort()
	}
}

// hasAdminRole checks if a user is a system administrator
func hasAdminRole(user *models.User) bool {
	// Check if user has 'admin' role (not username)
	for _, roleName := range user.Roles {
		if roleName == "admin" {
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
