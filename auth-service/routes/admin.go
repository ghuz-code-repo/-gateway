package routes

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"auth-service/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// getUserContext extracts username and full name from gin context
func getUserContext(c *gin.Context) (string, string) {
	username := c.GetString("username")
	fullName := c.GetString("full_name")
	return username, fullName
}

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

	return claims, true
}

// SetupAdminRoutes sets up routes for the admin panel
func SetupAdminRoutes(router *gin.Engine) {
	// Admin menu
	router.GET("/admin-menu", adminAuthRequired(), adminDashboardHandler)

	// User management routes
	users := router.Group("/users")
	users.Use(adminAuthRequired())
	{
		users.GET("/", listUsersHandler)
		users.GET("/new", showUserFormHandler)
		users.POST("/", createUserHandler)
		users.GET("/:id", getUserHandler)
		users.POST("/:id", updateUserHandler)
		users.POST("/:id/delete", deleteUserHandler)
		users.GET("/import", showUserImportFormHandler)
		users.POST("/import", importUsersHandler)
	}

	// Role management
	roles := router.Group("/roles")
	roles.Use(adminAuthRequired())
	{
		roles.GET("/", listRolesHandler)
		roles.GET("/new", showRoleFormHandler)
		roles.POST("/", createRoleHandler)
		roles.GET("/:id", getRoleHandler)
		roles.POST("/:id", updateRoleHandler)
		roles.POST("/:id/delete", deleteRoleHandler)
	}

	// Permission management
	permissions := router.Group("/permissions")
	permissions.Use(adminAuthRequired())
	{
		permissions.GET("/", listPermissionsHandler)
		permissions.GET("/new", showPermissionFormHandler)
		permissions.POST("/", createPermissionHandler)
		permissions.GET("/:id", getPermissionHandler)
		permissions.POST("/:id", updatePermissionHandler)
		permissions.POST("/:id/delete", deletePermissionHandler)
	}

	// Service management
	services := router.Group("/services")
	services.Use(serviceAdminAuthRequired())
	{
		services.GET("/", listServicesHandlerWithAccess)
		services.GET("/new", showServiceFormHandler)
		services.POST("/", createServiceHandler)
		services.GET("/:id", getServiceHandlerWithAccess)
		services.POST("/:id", updateServiceHandlerWithAccess)
		services.POST("/:id/delete", deleteServiceHandler)
		services.POST("/:id/permissions", addServicePermissionHandler)
		services.PUT("/:id/permissions/:permName", updateServicePermissionHandler)
		services.POST("/:id/permissions/:permName/delete", deleteServicePermissionHandler)
		
		// Service roles management
		services.POST("/:id/roles", createServiceRoleHandler)
		services.GET("/:id/roles/:roleId", getServiceRoleHandler)
		services.POST("/:id/roles/:roleId", updateServiceRoleHandler)
		services.POST("/:id/roles/:roleId/delete", deleteServiceRoleHandler)
		services.POST("/:id/assign-role", assignUserToServiceRoleHandler)

		// User management for services
		services.GET("/:id/users", getServiceUsersHandler)
		services.POST("/:id/users", addUserToServiceHandler)
		services.PUT("/:id/users/:userId/roles", updateUserServiceRolesHandler)
	}

	// Migration management
	migration := router.Group("/migration")
	migration.Use(adminAuthRequired())
	{
		migration.GET("/", migrationStatusHandler)
		migration.POST("/run", runMigrationHandler)
		migration.POST("/validate", validateMigrationHandler)
		migration.POST("/rollback", rollbackMigrationHandler)
	}

	// API endpoint for checking user existence
	router.GET("/check-user-exists", serviceAdminAuthRequired(), checkUserExistsHandler)
}

// SetupServiceAdminRoutes sets up routes accessible by service admins and system admins
func SetupServiceAdminRoutes(router *gin.Engine) {
	// Service management routes (accessible by service admins and system admins)
	services := router.Group("/services")
	services.Use(serviceAdminAuthRequired())
	{
		services.GET("/:id", getServiceHandlerForServiceAdmin)
		services.POST("/:id", updateServiceHandlerForServiceAdmin)
		
		// Service roles management (allowed for service admins)
		services.POST("/:id/roles", createServiceRoleHandler)
		services.GET("/:id/roles/:roleId", getServiceRoleHandler)
		services.POST("/:id/roles/:roleId", updateServiceRoleHandler)
		services.POST("/:id/roles/:roleId/delete", deleteServiceRoleHandler)
		services.POST("/:id/assign-role", assignUserToServiceRoleHandler)

		// User management for services (allowed for service admins)
		services.GET("/:id/users", getServiceUsersHandler)
		services.POST("/:id/users", addUserToServiceHandler)
		services.PUT("/:id/users/:userId/roles", updateUserServiceRolesHandler)
	}
	
	// User management routes (accessible by service admins and system admins)
	users := router.Group("/users")
	users.Use(serviceAdminAuthRequired())
	{
		users.GET("/", listUsersHandlerForServiceAdmin)
		users.GET("/new", showUserFormHandlerForServiceAdmin)
		users.POST("/", createUserHandlerForServiceAdmin)
		users.GET("/:id", getUserHandlerForServiceAdmin)
		users.POST("/:id", updateUserHandlerForServiceAdmin)
		users.POST("/:id/delete", deleteUserHandlerForServiceAdmin)
	}
}

// adminAuthRequired middleware ensures the user is an admin
func adminAuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get JWT token from cookie
		cookie, err := c.Cookie("token")
		if err != nil {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path) // Preserve original redirect
			c.Abort()
			return
		}

		// Parse and validate token
		claims, valid := validateToken(cookie)
		if !valid {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path) // Preserve original redirect
			c.Abort()
			return
		}

		// Get user info
		user, err := models.GetUserByID(claims.UserID)
		if err != nil {
			// error.html does not use the shared header, so no username/full_name needed here
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"error": "Не удалось получить данные пользователя",
			})
			c.Abort()
			return
		}

		// Store user info for handlers
		c.Set("username", user.Username)
		c.Set("full_name", user.FullName)

		// Check if user has admin role
		isAdmin := false
		for _, roleName := range user.Roles { // Iterate over role names
			if roleName == "admin" {
				isAdmin = true
				break
			}
		}

		if !isAdmin {
			// error.html does not use the shared header
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
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"error": "Не удалось получить данные пользователя",
			})
			c.Abort()
			return
		}

		// Store user info for handlers
		c.Set("username", user.Username)
		c.Set("full_name", user.FullName)

		// Check if user is system admin
		isSystemAdmin := user.Username == "administrator"
		
		// If system admin, allow access to everything
		if isSystemAdmin {
			c.Set("isSystemAdmin", true)
			c.Next()
			return
		}

		// For service-specific routes, check if user is admin of that service
		serviceID := c.Param("id")
		
		// If no serviceID in URL params, check query params
		if serviceID == "" {
			serviceID = c.Query("serviceId")
		}
		
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

		// No access
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "У вас нет прав для доступа к этому ресурсу",
		})
		c.Abort()
	}
}

// adminDashboardHandler handles the admin dashboard page
func adminDashboardHandler(c *gin.Context) {
	username := c.GetString("username")
	fullName := c.GetString("full_name")
	c.HTML(http.StatusOK, "admin.html", gin.H{
		"title":     "Панель администратора",
		"username":  username,
		"full_name": fullName,
	})
}

// User management handlers
func listUsersHandler(c *gin.Context) {
	username := c.GetString("username")
	fullName := c.GetString("full_name")
	users, err := models.GetAllUsers()
	if err != nil {
		// error.html does not use the shared header
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить пользователей",
		})
		return
	}

	// Prepare users with their service roles
	type UserWithServiceRoles struct {
		User         models.User
		ServiceRoles []models.UserServiceRole
	}

	var usersWithRoles []UserWithServiceRoles
	for _, user := range users {
		serviceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
		if err != nil {
			log.Printf("Warning: Failed to get service roles for user %s: %v", user.ID.Hex(), err)
			serviceRoles = []models.UserServiceRole{} // Empty slice if error
		}
		
		usersWithRoles = append(usersWithRoles, UserWithServiceRoles{
			User:         user,
			ServiceRoles: serviceRoles,
		})
	}

	// Get 'imported' query parameter
	importedCount := c.Query("imported")

	c.HTML(http.StatusOK, "users_list.html", gin.H{
		"title":           "Управление пользователями",
		"usersWithRoles":  usersWithRoles,
		"username":        username,
		"full_name":       fullName,
		"imported":        importedCount, // Pass imported count to template
	})
}

// showUserFormHandler shows the form to create a new user
func showUserFormHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")
	roles, err := models.GetSystemRoles() // Changed from GetAllRoles to GetSystemRoles
	if err != nil {
		// error.html does not use the shared header
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить роли",
		})
		return
	}

	// Get all services with their roles
	services, err := models.GetAllServicesWithRolesForTemplate()
	if err != nil {
		// error.html does not use the shared header
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить сервисы и их роли",
		})
		return
	}

	c.HTML(http.StatusOK, "user_form.html", gin.H{
		"title":     "Создать пользователя",
		"roles":     roles,
		"services":  services,
		"username":  usernameCtx, // For header
		"full_name": fullNameCtx, // For header
	})
}

func createUserHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")

	if c.Request.Method == "GET" { // Should be POST, but if GET, show form
		roles, _ := models.GetSystemRoles()
		c.HTML(http.StatusOK, "user_form.html", gin.H{
			"title":     "Создать пользователя",
			"roles":     roles,
			"username":  usernameCtx,
			"full_name": fullNameCtx,
		})
		return
	}

	// Handle POST
	username := c.PostForm("username")
	email := c.PostForm("email")
	password := c.PostForm("password")
	formFullName := c.PostForm("full_name") // Renamed to avoid conflict with fullNameCtx
	roleNames := c.PostFormArray("roles")
	serviceRoles := c.PostFormArray("service_roles") // Format: "serviceKey:roleName"

	if username == "" || email == "" || password == "" || formFullName == "" {
		roles, _ := models.GetSystemRoles() // Fetch roles again for the form
		services, _ := models.GetAllServicesWithRolesForTemplate()
		c.HTML(http.StatusBadRequest, "user_form.html", gin.H{
			"title":          "Создать пользователя",
			"error":          "Все поля обязательны для заполнения",
			"username_val":   username, // Pass back form values
			"email_val":      email,
			"full_name_val":  formFullName,
			"selected_roles": roleNames,
			"roles":          roles,
			"services":       services,
			"username":       usernameCtx, // For header
			"full_name":      fullNameCtx, // For header
		})
		return
	}

	user, err := models.CreateUser(username, email, password, formFullName, roleNames)
	if err != nil {
		// error.html does not use the shared header
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось создать пользователя: " + err.Error(),
		})
		return
	}

	// Assign service roles
	for _, serviceRole := range serviceRoles {
		parts := strings.Split(serviceRole, ":")
		if len(parts) == 2 {
			serviceKey := parts[0]
			roleName := parts[1]
			
			userServiceRole := models.UserServiceRole{
				UserID:     user, // user is primitive.ObjectID
				ServiceKey: serviceKey,
				RoleName:   roleName,
				AssignedAt: time.Now(),
				AssignedBy: user, // Self-assigned during creation
				IsActive:   true,
			}
			
			// Don't fail user creation if service role assignment fails
			if err := models.CreateUserServiceRole(userServiceRole); err != nil {
				log.Printf("Warning: Failed to assign service role %s:%s to user %s: %v", 
					serviceKey, roleName, user.Hex(), err)
			}
		}
	}

	c.Redirect(http.StatusFound, "/users")
}

// getUserHandler shows the form to edit an existing user
func getUserHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		// error.html
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный формат ID пользователя"})
		return
	}

	user, err := models.GetUserByObjectID(objectID)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить пользователя: " + err.Error()})
		return
	}

	roles, err := models.GetSystemRoles()
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить роли: " + err.Error()})
		return
	}

	// Get all services with their roles
	services, err := models.GetAllServicesWithRolesForTemplate()
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить сервисы и их роли: " + err.Error()})
		return
	}

	// Get user's current service roles
	userServiceRoles, err := models.GetUserServiceRolesByUserID(objectID)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить роли пользователя в сервисах: " + err.Error()})
		return
	}

	c.HTML(http.StatusOK, "user_form.html", gin.H{
		"title":            "Редактировать пользователя",
		"user":             user,
		"roles":            roles,
		"services":         services,
		"userServiceRoles": userServiceRoles,
		"username":         usernameCtx,
		"full_name":        fullNameCtx,
	})
}

// updateUserHandler processes the form submission to update a user
func updateUserHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		// error.html
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный формат ID пользователя"})
		return
	}

	existingUser, err := models.GetUserByObjectID(objectID)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить пользователя: " + err.Error()})
		return
	}

	usernameForm := c.PostForm("username")
	emailForm := c.PostForm("email")
	passwordForm := c.PostForm("password")
	fullNameForm := c.PostForm("full_name")
	roleNamesForm := c.PostFormArray("roles")
	serviceRoles := c.PostFormArray("service_roles") // Format: "serviceKey:roleName"

	// Use existing values if fields are empty (this logic is in models.UpdateUser, but good to be aware)
	// For rendering the form back on error, we need to decide what to show.
	// Let's assume the model handles using existing if empty for the actual update.

	err = models.UpdateUser(objectID, usernameForm, emailForm, passwordForm, fullNameForm, roleNamesForm)
	if err != nil {
		roles, _ := models.GetSystemRoles()
		services, _ := models.GetAllServicesWithRolesForTemplate()
		userServiceRoles, _ := models.GetUserServiceRolesByUserID(objectID)
		// user_form.html needs header data
		c.HTML(http.StatusInternalServerError, "user_form.html", gin.H{
			"title":            "Редактировать пользователя",
			"error":            "Не удалось обновить пользователя: " + err.Error(),
			"user":             existingUser, // Show existing user data in form
			"roles":            roles,
			"services":         services,
			"userServiceRoles": userServiceRoles,
			"username":         usernameCtx,
			"full_name":        fullNameCtx,
		})
		return
	}

	// Update service roles
	// First, remove all existing service roles for this user
	err = models.RemoveAllUserServiceRoles(objectID)
	if err != nil {
		log.Printf("Warning: Failed to remove existing service roles for user %s: %v", objectID.Hex(), err)
	}

	// Then assign new service roles
	for _, serviceRole := range serviceRoles {
		parts := strings.Split(serviceRole, ":")
		if len(parts) == 2 {
			serviceKey := parts[0]
			roleName := parts[1]
			
			userServiceRole := models.UserServiceRole{
				UserID:     objectID,
				ServiceKey: serviceKey,
				RoleName:   roleName,
				AssignedAt: time.Now(),
				AssignedBy: objectID, // Self-assigned during update
				IsActive:   true,
			}
			
			// Don't fail user update if service role assignment fails
			if err := models.CreateUserServiceRole(userServiceRole); err != nil {
				log.Printf("Warning: Failed to assign service role %s:%s to user %s: %v", 
					serviceKey, roleName, objectID.Hex(), err)
			}
		}
	}

	c.Redirect(http.StatusFound, "/users")
}

// Role management handlers
func listRolesHandler(c *gin.Context) {
	username := c.GetString("username")
	fullName := c.GetString("full_name")
	roles, err := models.GetAllRoles()
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить роли: " + err.Error()})
		return
	}

	c.HTML(http.StatusOK, "roles_list.html", gin.H{
		"title":     "Управление ролями",
		"roles":     roles,
		"username":  username,
		"full_name": fullName,
	})
}

// showRoleFormHandler shows the form to create a new role
func showRoleFormHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")
	permissions, err := models.GetAllPermissions()
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить разрешения"})
		return
	}

	c.HTML(http.StatusOK, "role_form.html", gin.H{
		"title":       "Создать роль",
		"permissions": permissions,
		"username":    usernameCtx,
		"full_name":   fullNameCtx,
	})
}

func createRoleHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")

	if c.Request.Method == "GET" { // Should be POST
		permissions, _ := models.GetAllPermissions()
		c.HTML(http.StatusOK, "role_form.html", gin.H{
			"title":       "Создать роль",
			"permissions": permissions,
			"username":    usernameCtx,
			"full_name":   fullNameCtx,
		})
		return
	}

	name := c.PostForm("name")
	description := c.PostForm("description")
	serviceKey := c.PostForm("service") // ADR-001: Service is required for roles
	permissionNames := c.PostFormArray("permissions")

	if name == "" || description == "" || serviceKey == "" {
		permissions, _ := models.GetAllPermissions()
		services, _ := models.GetAllServices() // ADR-001: Get services for dropdown
		c.HTML(http.StatusBadRequest, "role_form.html", gin.H{
			"title":           "Создать роль",
			"error":           "Имя, описание и сервис обязательны для заполнения",
			"name_val":        name,
			"description_val": description,
			"service_val":     serviceKey,
			"permissions":     permissions, // For repopulating checkboxes
			"services":        services,    // ADR-001: For service dropdown
			"selected_perms":  permissionNames,
			"username":        usernameCtx,
			"full_name":       fullNameCtx,
		})
		return
	}

	_, err := models.CreateRole(serviceKey, name, description, permissionNames)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось создать роль: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/roles")
}

// getRoleHandler shows the form to edit an existing role
func getRoleHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")
	roleID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		// error.html
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный формат ID роли"})
		return
	}

	role, err := models.GetRoleByID(objectID)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить роль: " + err.Error()})
		return
	}

	permissions, err := models.GetAllPermissions()
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить разрешения: " + err.Error()})
		return
	}

	c.HTML(http.StatusOK, "role_form.html", gin.H{
		"title":       "Редактировать роль",
		"role":        role,
		"permissions": permissions,
		"username":    usernameCtx,
		"full_name":   fullNameCtx,
	})
}

// updateRoleHandler processes the form submission to update a role
func updateRoleHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")
	roleID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		// error.html
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный формат ID роли"})
		return
	}

	nameForm := c.PostForm("name")
	descriptionForm := c.PostForm("description")
	permissionNamesForm := c.PostFormArray("permissions")

	role, err := models.GetRoleByID(objectID) // Fetch role for validation and form repopulation
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить роль: " + err.Error()})
		return
	}

	if nameForm == "" || descriptionForm == "" {
		permissions, _ := models.GetAllPermissions()
		c.HTML(http.StatusBadRequest, "role_form.html", gin.H{
			"title":          "Редактировать роль",
			"error":          "Имя и описание обязательны для заполнения",
			"role":           role, // Pass existing role data back
			"permissions":    permissions,
			"selected_perms": permissionNamesForm, // Pass submitted permissions
			"username":       usernameCtx,
			"full_name":      fullNameCtx,
		})
		return
	}

	if role.Name == "admin" && nameForm != "admin" {
		// error.html
		c.HTML(http.StatusForbidden, "error.html", gin.H{"error": "Нельзя менять имя роли admin"})
		return
	}

	serviceKeyForm := c.PostForm("service") // ADR-001: Get service key
	if serviceKeyForm == "" {
		serviceKeyForm = role.ServiceKey // Use existing service if not provided
	}

	err = models.UpdateRole(objectID, serviceKeyForm, nameForm, descriptionForm, permissionNamesForm)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось обновить роль: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/roles")
}

// deleteUserHandler handles the deletion of a user
func deleteUserHandler(c *gin.Context) {
	// usernameCtx := c.GetString("username") // Not needed if only redirecting or error.html
	// fullNameCtx := c.GetString("full_name")
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		// error.html
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный формат ID пользователя"})
		return
	}

	user, err := models.GetUserByObjectID(objectID)
	if err == nil && user.Username == "admin" {
		// error.html
		c.HTML(http.StatusForbidden, "error.html", gin.H{"error": "Невозможно удалить пользователя admin"})
		return
	}

	err = models.DeleteUser(objectID)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось удалить пользователя: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/users")
}

// deleteRoleHandler handles the deletion of a role
func deleteRoleHandler(c *gin.Context) {
	// usernameCtx := c.GetString("username") // Not needed
	// fullNameCtx := c.GetString("full_name")
	roleID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		// error.html
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный формат ID роли"})
		return
	}

	role, err := models.GetRoleByID(objectID)
	if err == nil && role.Name == "admin" {
		// error.html
		c.HTML(http.StatusForbidden, "error.html", gin.H{"error": "Невозможно удалить роль admin"})
		return
	}

	usersWithRole, err := models.GetUsersWithRole(role.Name)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось проверить назначение ролей: " + err.Error()})
		return
	}

	if len(usersWithRole) > 0 {
		// error.html
		c.HTML(http.StatusForbidden, "error.html", gin.H{"error": "Невозможно удалить роль, которая назначена пользователям"})
		return
	}

	err = models.DeleteRole(objectID)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось удалить роль: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/roles")
}

// Permission management handlers
func listPermissionsHandler(c *gin.Context) {
	username := c.GetString("username")
	fullName := c.GetString("full_name")
	permissions, err := models.GetAllPermissions()
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить разрешения: " + err.Error()})
		return
	}

	c.HTML(http.StatusOK, "permissions_list.html", gin.H{
		"title":       "Управление сервисами",
		"permissions": permissions,
		"username":    username,
		"full_name":   fullName,
	})
}

// showPermissionFormHandler shows the form to create a new permission
func showPermissionFormHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")
	c.HTML(http.StatusOK, "permission_form.html", gin.H{
		"title":     "Добавить сервис",
		"username":  usernameCtx,
		"full_name": fullNameCtx,
	})
}

// createPermissionHandler creates a new service permission
func createPermissionHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")

	if c.Request.Method == "GET" { // Should be POST
		c.HTML(http.StatusOK, "permission_form.html", gin.H{
			"title":     "Добавить сервис",
			"username":  usernameCtx,
			"full_name": fullNameCtx,
		})
		return
	}

	service := c.PostForm("service")
	displayName := c.PostForm("display_name")

	if service == "" {
		c.HTML(http.StatusBadRequest, "permission_form.html", gin.H{
			"title":            "Добавить сервис",
			"error":            "Имя сервиса обязательно для заполнения",
			"service_val":      service,
			"display_name_val": displayName,
			"username":         usernameCtx,
			"full_name":        fullNameCtx,
		})
		return
	}

	if displayName == "" {
		displayName = service
	}

	err := models.CreatePermission(service, displayName)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось создать разрешение: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/permissions")
}

// getPermissionHandler shows the form to edit an existing permission
func getPermissionHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")
	permissionID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(permissionID)
	if err != nil {
		// error.html
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный формат ID разрешения"})
		return
	}

	permission, err := models.GetPermissionByID(objectID)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить разрешение: " + err.Error()})
		return
	}

	c.HTML(http.StatusOK, "permission_form.html", gin.H{
		"title":      "Редактировать сервис",
		"permission": permission,
		"username":   usernameCtx,
		"full_name":  fullNameCtx,
	})
}

// updatePermissionHandler processes the form submission to update a permission
func updatePermissionHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")
	permissionID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(permissionID)
	if err != nil {
		// error.html
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный формат ID разрешения"})
		return
	}

	displayNameForm := c.PostForm("display_name")
	permission, _ := models.GetPermissionByID(objectID) // Fetch for form repopulation

	if displayNameForm == "" {
		c.HTML(http.StatusBadRequest, "permission_form.html", gin.H{
			"title":      "Редактировать сервис",
			"error":      "Отображаемое имя обязательно для заполнения",
			"permission": permission, // Pass existing permission data
			"username":   usernameCtx,
			"full_name":  fullNameCtx,
		})
		return
	}

	err = models.UpdatePermissionDisplayName(objectID, displayNameForm)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось обновить разрешение: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/permissions")
}

// deletePermissionHandler handles the deletion of a permission
func deletePermissionHandler(c *gin.Context) {
	// usernameCtx := c.GetString("username") // Not needed
	// fullNameCtx := c.GetString("full_name")
	permissionID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(permissionID)
	if err != nil {
		// error.html
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный формат ID разрешения"})
		return
	}

	permission, err := models.GetPermissionByID(objectID)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить информацию о разрешении: " + err.Error()})
		return
	}

	rolesWithPermission, err := models.GetRolesWithPermission(permission.Service)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось проверить использование разрешений: " + err.Error()})
		return
	}

	if len(rolesWithPermission) > 0 {
		// error.html
		c.HTML(http.StatusForbidden, "error.html", gin.H{"error": "Невозможно удалить разрешение, которое используется ролями"})
		return
	}

	err = models.DeletePermission(objectID)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось удалить разрешение: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/permissions")
}

// showUserImportFormHandler shows the form to import users from Excel
func showUserImportFormHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")
	c.HTML(http.StatusOK, "user_import.html", gin.H{
		"title":     "Импорт пользователей из Excel",
		"username":  usernameCtx,
		"full_name": fullNameCtx,
	})
}

// importUsersHandler processes the Excel file upload and imports users
func importUsersHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")

	file, err := c.FormFile("excelFile")
	if err != nil {
		// error.html
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Нет файла для загрузки: " + err.Error()})
		return
	}

	ext := filepath.Ext(file.Filename)
	if ext != ".xlsx" && ext != ".xls" {
		// error.html
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный тип файла. Разрешены только файлы Excel (.xlsx, .xls)."})
		return
	}

	tempFilePath := filepath.Join(os.TempDir(), "user_import"+time.Now().Format("20060102150405")+ext)
	if err := c.SaveUploadedFile(file, tempFilePath); err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось сохранить файл: " + err.Error()})
		return
	}
	defer os.Remove(tempFilePath) // Ensure temp file is deleted

	usersCreated, err := models.ImportUsersFromExcel(tempFilePath) // Modified to return warnings

	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось импортировать пользователей: " + err.Error()})
		return
	}

	// import_result.html uses the header
	if usersCreated == 0 {
		c.HTML(http.StatusOK, "import_result.html", gin.H{
			"title":     "Результаты импорта",
			"success":   "Новых пользователей не создано (возможно, все уже существуют или файл пуст).",
			"username":  usernameCtx,
			"full_name": fullNameCtx,
		})
	} else {
		c.HTML(http.StatusOK, "import_result.html", gin.H{
			"title":     "Результаты импорта",
			"success":   fmt.Sprintf("Успешно создано %d пользователей!", usersCreated),
			"username":  usernameCtx,
			"full_name": fullNameCtx,
		})
	}
}

// ADR-001: Service Management Handlers

// listServicesHandler displays all services
func listServicesHandler(c *gin.Context) {
	usernameCtx, fullNameCtx := getUserContext(c)

	services, err := models.GetAllServices()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить список сервисов: " + err.Error(),
		})
		return
	}

	c.HTML(http.StatusOK, "admin_services.html", gin.H{
		"title":     "Управление сервисами",
		"services":  services,
		"username":  usernameCtx,
		"full_name": fullNameCtx,
	})
}

// showServiceFormHandler displays the service creation form
func showServiceFormHandler(c *gin.Context) {
	usernameCtx, fullNameCtx := getUserContext(c)

	c.HTML(http.StatusOK, "admin_service_form.html", gin.H{
		"title":     "Создать сервис",
		"username":  usernameCtx,
		"full_name": fullNameCtx,
	})
}

// createServiceHandler creates a new service
func createServiceHandler(c *gin.Context) {
	usernameCtx, fullNameCtx := getUserContext(c)

	key := c.PostForm("key")
	name := c.PostForm("name")
	description := c.PostForm("description")

	if key == "" || name == "" {
		c.HTML(http.StatusBadRequest, "admin_service_form.html", gin.H{
			"title":     "Создать сервис",
			"error":     "Ключ и название сервиса обязательны",
			"username":  usernameCtx,
			"full_name": fullNameCtx,
		})
		return
	}

	// Create service with empty permissions list initially
	_, err := models.CreateService(key, name, description, []models.PermissionDef{})
	if err != nil {
		c.HTML(http.StatusInternalServerError, "admin_service_form.html", gin.H{
			"title":     "Создать сервис",
			"error":     "Не удалось создать сервис: " + err.Error(),
			"username":  usernameCtx,
			"full_name": fullNameCtx,
		})
		return
	}

	c.Redirect(http.StatusFound, "/services")
}

// getServiceHandler displays service details for editing
func getServiceHandler(c *gin.Context) {
	usernameCtx, fullNameCtx := getUserContext(c)

	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный ID сервиса",
		})
		return
	}

	service, err := models.GetServiceByID(id)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Сервис не найден",
		})
		return
	}

	// Debug: log available permissions
	log.Printf("Service %s has %d available permissions", service.Name, len(service.AvailablePermissions))
	for i, perm := range service.AvailablePermissions {
		log.Printf("Permission %d: %s (%s) - %s", i, perm.Name, perm.DisplayName, perm.Description)
	}

	// Get roles for this service
	serviceRoles, err := models.GetRolesByService(service.Key)
	if err != nil {
		log.Printf("Warning: Failed to get roles for service %s: %v", service.Key, err)
		serviceRoles = []models.Role{} // Set empty slice if error
	}

	// Get all users for the dropdown
	allUsers, err := models.GetAllUsers()
	if err != nil {
		log.Printf("Warning: Failed to get all users: %v", err)
		allUsers = []models.User{} // Set empty slice if error
	}

	// Get users with roles in this service using new ADR-001 approach
	serviceUsersWithRoles, err := models.GetUsersWithServiceRolesNew(service.Key)
	if err != nil {
		log.Printf("Warning: Failed to get users with service roles for %s: %v", service.Key, err)
		// Fallback to old approach for backward compatibility
		oldUsers, oldErr := models.GetUsersWithServiceRoles(service.Key)
		if oldErr != nil {
			log.Printf("Warning: Failed to get users with old approach: %v", oldErr)
			serviceUsersWithRoles = []models.UserWithServiceRoles{}
		} else {
			// Convert old users to new format
			serviceUsersWithRoles = make([]models.UserWithServiceRoles, len(oldUsers))
			for i, user := range oldUsers {
				serviceUsersWithRoles[i] = models.UserWithServiceRoles{
					User:         user,
					ServiceRoles: []string{}, // No specific service roles in old format
				}
			}
		}
	}

	c.HTML(http.StatusOK, "admin_service_form.html", gin.H{
		"title":        "Редактировать сервис",
		"service":      service,
		"serviceRoles": serviceRoles,
		"allUsers":     allUsers,
		"serviceUsers": serviceUsersWithRoles, // Now contains users with their service roles
		"username":     usernameCtx,
		"full_name":    fullNameCtx,
	})
}

// updateServiceHandler updates an existing service
func updateServiceHandler(c *gin.Context) {
	usernameCtx, fullNameCtx := getUserContext(c)

	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный ID сервиса",
		})
		return
	}

	key := c.PostForm("key")
	name := c.PostForm("name")
	description := c.PostForm("description")

	if key == "" || name == "" {
		service, _ := models.GetServiceByID(id)
		c.HTML(http.StatusBadRequest, "admin_service_form.html", gin.H{
			"title":     "Редактировать сервис",
			"service":   service,
			"error":     "Ключ и название сервиса обязательны",
			"username":  usernameCtx,
			"full_name": fullNameCtx,
		})
		return
	}

	// Get current service to preserve permissions
	service, err := models.GetServiceByID(id)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Сервис не найден",
		})
		return
	}

	err = models.UpdateService(id, key, name, description, service.AvailablePermissions)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "admin_service_form.html", gin.H{
			"title":     "Редактировать сервис",
			"service":   service,
			"error":     "Не удалось обновить сервис: " + err.Error(),
			"username":  usernameCtx,
			"full_name": fullNameCtx,
		})
		return
	}

	c.Redirect(http.StatusFound, "/services")
}

// deleteServiceHandler deletes a service (soft delete)
func deleteServiceHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID сервиса"})
		return
	}

	// For now, implement as status change to "deleted"
	service, err := models.GetServiceByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Сервис не найден"})
		return
	}

	err = models.UpdateService(id, service.Key, service.Name, service.Description, service.AvailablePermissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось удалить сервис"})
		return
	}

	c.Redirect(http.StatusFound, "/services")
}

// addServicePermissionHandler adds a permission to a service
func addServicePermissionHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный ID сервиса",
		})
		return
	}

	permName := c.PostForm("name")
	permDisplayName := c.PostForm("displayName")
	permDescription := c.PostForm("description")

	service, err := models.GetServiceByID(id)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Сервис не найден",
		})
		return
	}

	if permName == "" {
		// Get service data for re-rendering the form with error
		serviceRoles, _ := models.GetRolesByService(service.Key)
		allUsers, _ := models.GetAllUsers()
		serviceUsers, _ := models.GetUsersWithServiceRoles(service.Key)

		c.HTML(http.StatusBadRequest, "admin_service_form.html", gin.H{
			"title":        "Редактировать сервис",
			"service":      service,
			"serviceRoles": serviceRoles,
			"allUsers":     allUsers,
			"serviceUsers": serviceUsers,
			"error":        "Название разрешения обязательно",
		})
		return
	}

	permissionDef := models.PermissionDef{
		Name:        permName,
		DisplayName: permDisplayName,
		Description: permDescription,
	}

	err = models.AddPermissionToService(service.Key, permissionDef)
	if err != nil {
		// Get service data for re-rendering the form with error
		serviceRoles, _ := models.GetRolesByService(service.Key)
		allUsers, _ := models.GetAllUsers()
		serviceUsers, _ := models.GetUsersWithServiceRoles(service.Key)

		c.HTML(http.StatusInternalServerError, "admin_service_form.html", gin.H{
			"title":        "Редактировать сервис",
			"service":      service,
			"serviceRoles": serviceRoles,
			"allUsers":     allUsers,
			"serviceUsers": serviceUsers,
			"error":        "Ошибка добавления разрешения: " + err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, "/services/"+idStr)
}

// updateServicePermissionHandler updates a permission in a service
func updateServicePermissionHandler(c *gin.Context) {
	idStr := c.Param("id")
	originalPermName := c.Param("permName")
	
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID сервиса"})
		return
	}

	newPermName := c.PostForm("name")
	permDisplayName := c.PostForm("displayName")
	permDescription := c.PostForm("description")

	service, err := models.GetServiceByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Сервис не найден"})
		return
	}

	if newPermName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Название разрешения обязательно"})
		return
	}

	permissionDef := models.PermissionDef{
		Name:        newPermName,
		DisplayName: permDisplayName,
		Description: permDescription,
	}

	err = models.UpdateServicePermission(service.Key, originalPermName, permissionDef)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления разрешения: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Разрешение успешно обновлено"})
}

// deleteServicePermissionHandler removes a permission from a service
func deleteServicePermissionHandler(c *gin.Context) {
	idStr := c.Param("id")
	permName := c.Param("permName")

	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID сервиса"})
		return
	}

	service, err := models.GetServiceByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Сервис не найден"})
		return
	}

	err = models.RemovePermissionFromService(service.Key, permName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось удалить разрешение"})
		return
	}

	c.Redirect(http.StatusFound, "/services/"+idStr)
}

// ADR-001: Migration Management Handlers

// migrationStatusHandler shows migration status
func migrationStatusHandler(c *gin.Context) {
	usernameCtx, fullNameCtx := getUserContext(c)

	err := models.ValidateMigration()
	migrationStatus := map[string]interface{}{
		"completed": err == nil,
		"error":     "",
	}

	if err != nil {
		migrationStatus["error"] = err.Error()
	}

	c.HTML(http.StatusOK, "admin_migration.html", gin.H{
		"title":           "Миграция ADR-001",
		"migrationStatus": migrationStatus,
		"username":        usernameCtx,
		"full_name":       fullNameCtx,
	})
}

// runMigrationHandler executes the migration
func runMigrationHandler(c *gin.Context) {
	result, err := models.MigrateToADR001Schema()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  "Ошибка миграции: " + err.Error(),
			"result": result,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Миграция завершена успешно",
		"result":  result,
	})
}

// validateMigrationHandler validates the migration
func validateMigrationHandler(c *gin.Context) {
	err := models.ValidateMigration()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Валидация миграции не пройдена: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Валидация миграции пройдена успешно",
	})
}

// rollbackMigrationHandler rolls back the migration
func rollbackMigrationHandler(c *gin.Context) {
	err := models.RollbackMigration()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Ошибка отката миграции: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Откат миграции завершен успешно",
	})
}

// createServiceRoleHandler creates a new role for a specific service
func createServiceRoleHandler(c *gin.Context) {
	serviceID := c.Param("id")
	id, err := primitive.ObjectIDFromHex(serviceID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный ID сервиса",
		})
		return
	}

	service, err := models.GetServiceByID(id)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Сервис не найден",
		})
		return
	}

	name := c.PostForm("name")
	description := c.PostForm("description")
	permissions := c.PostFormArray("permissions")

	if name == "" {
		usernameCtx, fullNameCtx := getUserContext(c)
		serviceRoles, _ := models.GetRolesByService(service.Key)
		allUsers, _ := models.GetAllUsers()
		serviceUsersWithRoles, _ := models.GetUsersWithServiceRolesNew(service.Key)
		
		c.HTML(http.StatusBadRequest, "admin_service_form.html", gin.H{
			"title":        "Редактировать сервис",
			"service":      service,
			"serviceRoles": serviceRoles,
			"allUsers":     allUsers,
			"serviceUsers": serviceUsersWithRoles,
			"username":     usernameCtx,
			"full_name":    fullNameCtx,
			"error":        "Название роли обязательно",
		})
		return
	}

	_, err = models.CreateRole(service.Key, name, description, permissions)
	if err != nil {
		usernameCtx, fullNameCtx := getUserContext(c)
		serviceRoles, _ := models.GetRolesByService(service.Key)
		allUsers, _ := models.GetAllUsers()
		serviceUsersWithRoles, _ := models.GetUsersWithServiceRolesNew(service.Key)
		
		c.HTML(http.StatusInternalServerError, "admin_service_form.html", gin.H{
			"title":        "Редактировать сервис",
			"service":      service,
			"serviceRoles": serviceRoles,
			"allUsers":     allUsers,
			"serviceUsers": serviceUsersWithRoles,
			"username":     usernameCtx,
			"full_name":    fullNameCtx,
			"error":        "Ошибка создания роли: " + err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, "/services/"+serviceID)
}

// getServiceRoleHandler displays role details for editing
func getServiceRoleHandler(c *gin.Context) {
	serviceID := c.Param("id")
	roleIDStr := c.Param("roleId")

	serviceOID, err := primitive.ObjectIDFromHex(serviceID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный ID сервиса",
		})
		return
	}

	roleOID, err := primitive.ObjectIDFromHex(roleIDStr)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный ID роли",
		})
		return
	}

	_, err = models.GetServiceByID(serviceOID)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Сервис не найден",
		})
		return
	}

	_, err = models.GetRoleByID(roleOID)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Роль не найдена",
		})
		return
	}

	// TODO: Create service_role_form.html template or redirect for now
	c.Redirect(http.StatusFound, "/services/"+serviceID)
}

// updateServiceRoleHandler updates an existing role for a service
func updateServiceRoleHandler(c *gin.Context) {
	serviceID := c.Param("id")
	roleIDStr := c.Param("roleId")

	serviceOID, err := primitive.ObjectIDFromHex(serviceID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный ID сервиса",
		})
		return
	}

	roleOID, err := primitive.ObjectIDFromHex(roleIDStr)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный ID роли",
		})
		return
	}

	service, err := models.GetServiceByID(serviceOID)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Сервис не найден",
		})
		return
	}

	name := c.PostForm("name")
	description := c.PostForm("description")
	permissions := c.PostFormArray("permissions")

	if name == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Название роли обязательно",
		})
		return
	}

	err = models.UpdateRole(roleOID, service.Key, name, description, permissions)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Ошибка обновления роли: " + err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, "/services/"+serviceID)
}

// deleteServiceRoleHandler removes a role from a service
func deleteServiceRoleHandler(c *gin.Context) {
	serviceID := c.Param("id")
	roleIDStr := c.Param("roleId")

	roleOID, err := primitive.ObjectIDFromHex(roleIDStr)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный ID роли",
		})
		return
	}

	err = models.DeleteRole(roleOID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Ошибка удаления роли: " + err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, "/services/"+serviceID)
}

// assignUserToServiceRoleHandler assigns a role to a user within a service
func assignUserToServiceRoleHandler(c *gin.Context) {
	serviceID := c.Param("id")
	userIDStr := c.PostForm("userId")
	roleName := c.PostForm("roleName")

	serviceOID, err := primitive.ObjectIDFromHex(serviceID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный ID сервиса",
		})
		return
	}

	userOID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный ID пользователя",
		})
		return
	}

	service, err := models.GetServiceByID(serviceOID)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Сервис не найден",
		})
		return
	}

	// Check if role exists for this service
	roles, err := models.GetRolesByService(service.Key)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Ошибка получения ролей сервиса: " + err.Error(),
		})
		return
	}

	roleExists := false
	for _, role := range roles {
		if role.Name == roleName {
			roleExists = true
			break
		}
	}

	if !roleExists {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Роль не найдена в данном сервисе",
		})
		return
	}

	// Add role to user
	err = models.AssignRoleToUser(userOID, roleName)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Ошибка назначения роли: " + err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, "/services/"+serviceID)
}

// getServiceUsersHandler returns users with their roles for a specific service via API
func getServiceUsersHandler(c *gin.Context) {
	serviceID := c.Param("id")
	
	// Convert serviceID to ObjectID
	serviceObjectID, err := primitive.ObjectIDFromHex(serviceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID"})
		return
	}
	
	// Get service to validate it exists
	service, err := models.GetServiceByID(serviceObjectID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		return
	}

	// Get users with roles in this service
	log.Printf("Getting users with roles for service: %s", service.Key)
	serviceUsers, err := models.GetUsersWithServiceRolesNew(service.Key)
	if err != nil {
		log.Printf("Error getting users with service roles: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get service users"})
		return
	}
	
	log.Printf("Found %d users with roles in service %s", len(serviceUsers), service.Key)
	for i, user := range serviceUsers {
		log.Printf("User %d: %s (%s) with roles: %v", i+1, user.Username, user.Email, user.ServiceRoles)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"users":   serviceUsers,
	})
}

// addUserToServiceHandler handles adding users to services via API
func addUserToServiceHandler(c *gin.Context) {
	serviceID := c.Param("id")
	
	// Convert serviceID to ObjectID
	serviceObjectID, err := primitive.ObjectIDFromHex(serviceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID"})
		return
	}
	
	var request struct {
		Identifier string   `json:"identifier" binding:"required"` // Can be email or username
		ServiceKey string   `json:"service_key" binding:"required"`
		Roles      []string `json:"roles" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		log.Printf("Binding error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Check if user exists by email or username
	existingUser, err := models.GetUserByEmailOrUsername(request.Identifier)
	if err != nil {
		log.Printf("Error checking user existence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check user existence"})
		return
	}

	var userID primitive.ObjectID
	var userEmail string

	if existingUser == nil {
		// User doesn't exist, create new user
		// Validate email format if creating new user
		if !strings.Contains(request.Identifier, "@") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "User not found. To create new user, provide a valid email address"})
			return
		}
		
		password := models.GenerateSecurePassword()
		
		// Use email as username if no username provided
		username := strings.Split(request.Identifier, "@")[0]
		userEmail = request.Identifier
		
		newUserID, err := models.CreateUser(username, userEmail, password, userEmail, []string{})
		if err != nil {
			log.Printf("Error creating user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user: " + err.Error()})
			return
		}

		userID = newUserID
		log.Printf("Created new user: %s with password: %s", userEmail, password)
		
		// TODO: Here you would typically send an email with the password
		// For now, we'll just log it
		
	} else {
		// User exists, use existing user ID
		userID = existingUser.ID
		userEmail = existingUser.Email
		log.Printf("Using existing user: %s (found by identifier: %s)", userEmail, request.Identifier)
	}

	// Get current admin user ID (in real app, this would come from JWT token)
	// For now, we'll use a placeholder admin ID
	adminID := primitive.NewObjectID() // This should be the ID of the current admin user
	
	// Get service to validate it exists
	service, err := models.GetServiceByID(serviceObjectID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		return
	}

	// Add user to service with specified roles
	log.Printf("Adding user %s (%s) to service %s with %d roles: %v", userEmail, userID.Hex(), service.Key, len(request.Roles), request.Roles)
	
	addedRoles := 0
	for _, roleName := range request.Roles {
		// Create user service role assignment
		userServiceRole := models.UserServiceRole{
			UserID:     userID,
			ServiceKey: service.Key,
			RoleName:   roleName,
			AssignedAt: time.Now(),
			AssignedBy: adminID,
			IsActive:   true,
		}
		
		log.Printf("Attempting to add role %s to user %s in service %s", roleName, userID.Hex(), service.Key)
		err = models.CreateUserServiceRole(userServiceRole)
		if err != nil {
			log.Printf("Error adding role %s to user %s: %v", roleName, userID.Hex(), err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to add role %s to user", roleName)})
			return
		} else {
			log.Printf("Successfully added role %s to user %s", roleName, userID.Hex())
			addedRoles++
		}
	}
	
	log.Printf("Successfully added %d/%d roles to user %s in service %s", addedRoles, len(request.Roles), userID.Hex(), service.Key)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("User %s successfully added to service %s", userEmail, service.Name),
		"user_id": userID.Hex(),
	})
}

// updateUserServiceRolesHandler handles updating user roles in services via API  
func updateUserServiceRolesHandler(c *gin.Context) {
	serviceID := c.Param("id")
	userID := c.Param("userId")
	
	// Convert serviceID to ObjectID
	serviceObjectID, err := primitive.ObjectIDFromHex(serviceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID"})
		return
	}
	
	var request struct {
		Roles []string `json:"roles" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		log.Printf("Binding error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Convert user ID to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	// Check if user exists
	user, err := models.GetUserByObjectID(userObjectID)
	if err != nil {
		log.Printf("Error checking user existence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check user existence"})
		return
	}

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Get service to validate it exists
	service, err := models.GetServiceByID(serviceObjectID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		return
	}

	// Get current admin user ID (in real app, this would come from JWT token)
	adminID := primitive.NewObjectID() // This should be the ID of the current admin user

	// Remove existing roles for this user in this service
	log.Printf("Removing existing roles for user %s in service %s", userID, service.Key)
	err = models.RemoveUserFromServiceRoles(userObjectID, service.Key)
	if err != nil {
		log.Printf("Error removing existing roles: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove existing roles"})
		return
	}

	// Add new roles
	log.Printf("Adding %d new roles for user %s in service %s: %v", len(request.Roles), userID, service.Key, request.Roles)
	for _, roleName := range request.Roles {
		userServiceRole := models.UserServiceRole{
			UserID:     userObjectID,
			ServiceKey: service.Key,
			RoleName:   roleName,
			AssignedAt: time.Now(),
			AssignedBy: adminID,
			IsActive:   true,
		}
		
		err = models.CreateUserServiceRole(userServiceRole)
		if err != nil {
			log.Printf("Error adding role %s to user %s: %v", roleName, userID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to add role %s", roleName)})
			return
		} else {
			log.Printf("Successfully added role %s to user %s", roleName, userID)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("User roles updated successfully for service %s", service.Name),
	})
}

// Service admin handlers - specialized versions for service admins

// getServiceHandlerForServiceAdmin displays service details with limited tabs for service admins
func getServiceHandlerForServiceAdmin(c *gin.Context) {
	usernameCtx, fullNameCtx := getUserContext(c)
	isSystemAdmin := c.GetBool("isSystemAdmin")

	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный ID сервиса",
		})
		return
	}

	service, err := models.GetServiceByID(id)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"error": "Сервис не найден",
		})
		return
	}

	// Get roles for this service
	serviceRoles, err := models.GetRolesByService(service.Key)
	if err != nil {
		log.Printf("Warning: Failed to get roles for service %s: %v", service.Key, err)
		serviceRoles = []models.Role{}
	}

	// Get all users for the dropdown
	allUsers, err := models.GetAllUsers()
	if err != nil {
		log.Printf("Warning: Failed to get all users: %v", err)
		allUsers = []models.User{}
	}

	// Get users with roles in this service
	serviceUsersWithRoles, err := models.GetUsersWithServiceRolesNew(service.Key)
	if err != nil {
		log.Printf("Warning: Failed to get users with service roles for %s: %v", service.Key, err)
		serviceUsersWithRoles = []models.UserWithServiceRoles{}
	}

	// Use the same template as admin but with manageMode for service admins
	c.HTML(http.StatusOK, "admin_service_form.html", gin.H{
		"title":        "Управление сервисом",
		"service":      service,
		"serviceRoles": serviceRoles,
		"allUsers":     allUsers,
		"serviceUsers": serviceUsersWithRoles,
		"username":     usernameCtx,
		"full_name":    fullNameCtx,
		"manageMode":   !isSystemAdmin, // Service admins use manage mode, system admins don't
	})
}

// updateServiceHandlerForServiceAdmin - service admins cannot update basic service info
func updateServiceHandlerForServiceAdmin(c *gin.Context) {
	c.HTML(http.StatusForbidden, "error.html", gin.H{
		"error": "У вас нет прав для изменения основной информации о сервисе",
	})
}

// User management handlers for service admins

// listUsersHandlerForServiceAdmin shows users relevant to service admin's services
func listUsersHandlerForServiceAdmin(c *gin.Context) {
	isSystemAdmin := c.GetBool("isSystemAdmin")

	if isSystemAdmin {
		// System admin sees all users
		listUsersHandler(c)
		return
	}

	// Service admin sees only users from their services
	c.HTML(http.StatusForbidden, "error.html", gin.H{
		"error": "Управление пользователями доступно только через интерфейс конкретного сервиса",
	})
}

// Stub handlers for service admin user management (redirect to forbidden for now)
func showUserFormHandlerForServiceAdmin(c *gin.Context) {
	c.HTML(http.StatusForbidden, "error.html", gin.H{
		"error": "Создание пользователей доступно только через интерфейс конкретного сервиса",
	})
}

func createUserHandlerForServiceAdmin(c *gin.Context) {
	c.HTML(http.StatusForbidden, "error.html", gin.H{
		"error": "Создание пользователей доступно только через интерфейс конкретного сервиса",
	})
}

func getUserHandlerForServiceAdmin(c *gin.Context) {
	c.HTML(http.StatusForbidden, "error.html", gin.H{
		"error": "Редактирование пользователей доступно только через интерфейс конкретного сервиса",
	})
}

func updateUserHandlerForServiceAdmin(c *gin.Context) {
	c.HTML(http.StatusForbidden, "error.html", gin.H{
		"error": "Редактирование пользователей доступно только через интерфейс конкретного сервиса",
	})
}

func deleteUserHandlerForServiceAdmin(c *gin.Context) {
	c.HTML(http.StatusForbidden, "error.html", gin.H{
		"error": "Удаление пользователей доступно только через интерфейс конкретного сервиса",
	})
}

// Handlers with access control for services and users

// listServicesHandlerWithAccess shows services based on user access level
func listServicesHandlerWithAccess(c *gin.Context) {
	isSystemAdmin := c.GetBool("isSystemAdmin")
	
	if isSystemAdmin {
		// System admin sees all services
		listServicesHandler(c)
		return
	}
	
	// Service admin sees only their services
	c.HTML(http.StatusForbidden, "error.html", gin.H{
		"error": "У вас нет прав для просмотра всех сервисов",
	})
}

// getServiceHandlerWithAccess shows service details based on user access level
func getServiceHandlerWithAccess(c *gin.Context) {
	isSystemAdmin := c.GetBool("isSystemAdmin")
	
	if isSystemAdmin {
		// System admin sees full service management
		getServiceHandler(c)
	} else {
		// Service admin sees limited management
		getServiceHandlerForServiceAdmin(c)
	}
}

// updateServiceHandlerWithAccess updates service based on user access level
func updateServiceHandlerWithAccess(c *gin.Context) {
	isSystemAdmin := c.GetBool("isSystemAdmin")
	
	if isSystemAdmin {
		// System admin can update service
		updateServiceHandler(c)
	} else {
		// Service admin cannot update basic service info
		updateServiceHandlerForServiceAdmin(c)
	}
}

// checkUserExistsHandler checks if a user exists by email or username
func checkUserExistsHandler(c *gin.Context) {
	identifier := c.Query("identifier")
	serviceID := c.Query("serviceId")
	
	if identifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "identifier parameter is required",
		})
		return
	}

	if serviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "serviceId parameter is required",
		})
		return
	}

	// Check if user exists by email or username
	user, err := models.GetUserByEmailOrUsername(identifier)
	if err != nil {
		log.Printf("Error checking user existence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to check user existence",
		})
		return
	}

	if user == nil {
		// User not found
		c.JSON(http.StatusOK, gin.H{
			"exists": false,
		})
		return
	}

	// User exists, now check if they have roles in this service
	objID, err := primitive.ObjectIDFromHex(serviceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid service ID",
		})
		return
	}

	service, err := models.GetServiceByID(objID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get service",
		})
		return
	}

	// Get user's roles in this service
	userRoles, err := models.GetUserServiceRolesFromCollection(user.ID.Hex(), service.Key)
	if err != nil {
		log.Printf("Error getting user service roles: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to check user service roles",
		})
		return
	}

	log.Printf("User %s roles in service %s: %v", user.Username, service.Key, userRoles)

	// User exists
	response := gin.H{
		"exists": true,
		"user": gin.H{
			"id":       user.ID.Hex(),
			"username": user.Username,
			"email":    user.Email,
			"fullName": user.FullName,
		},
	}

	// If user has roles in this service, add them to response
	if len(userRoles) > 0 {
		response["hasServiceAccess"] = true
		response["serviceRoles"] = userRoles
		log.Printf("User %s has service access: %v", user.Username, userRoles)
	} else {
		response["hasServiceAccess"] = false
		log.Printf("User %s has NO service access", user.Username)
	}

	c.JSON(http.StatusOK, response)
}
