package routes

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"auth-service/models"

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

	return claims, true
}

// SetupAdminRoutes sets up routes for the admin panel
func SetupAdminRoutes(router *gin.Engine) {
	// Admin dashboard and CRUD operations
	admin := router.Group("/admin")
	admin.Use(adminAuthRequired())
	{
		admin.GET("/", adminDashboardHandler)

		// User management
		admin.GET("/users", listUsersHandler)
		admin.GET("/users/new", showUserFormHandler)
		admin.POST("/users", createUserHandler)
		admin.GET("/users/:id", getUserHandler)
		admin.POST("/users/:id", updateUserHandler)
		admin.POST("/users/:id/delete", deleteUserHandler)
		admin.GET("/users/import", showUserImportFormHandler)
		admin.POST("/users/import", importUsersHandler)

		// Role management
		admin.GET("/roles", listRolesHandler)
		admin.GET("/roles/new", showRoleFormHandler)
		admin.POST("/roles", createRoleHandler)
		admin.GET("/roles/:id", getRoleHandler)
		admin.POST("/roles/:id", updateRoleHandler)
		admin.POST("/roles/:id/delete", deleteRoleHandler)

		// Permission management
		admin.GET("/permissions", listPermissionsHandler)
		admin.GET("/permissions/new", showPermissionFormHandler)
		admin.POST("/permissions", createPermissionHandler)
		admin.GET("/permissions/:id", getPermissionHandler)
		admin.POST("/permissions/:id", updatePermissionHandler)
		admin.POST("/permissions/:id/delete", deletePermissionHandler)
	}
}

// adminAuthRequired middleware ensures the user is an admin
func adminAuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get JWT token from cookie
		cookie, err := c.Cookie("token")
		if err != nil {
			c.Redirect(http.StatusFound, "/auth/login?redirect="+c.Request.URL.Path) // Preserve original redirect
			c.Abort()
			return
		}

		// Parse and validate token
		claims, valid := validateToken(cookie)
		if !valid {
			c.Redirect(http.StatusFound, "/auth/login?redirect="+c.Request.URL.Path) // Preserve original redirect
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

	// Get 'imported' query parameter
	importedCount := c.Query("imported")

	c.HTML(http.StatusOK, "users_list.html", gin.H{
		"title":     "Управление пользователями",
		"users":     users,
		"username":  username,
		"full_name": fullName,
		"imported":  importedCount, // Pass imported count to template
	})
}

// showUserFormHandler shows the form to create a new user
func showUserFormHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")
	roles, err := models.GetAllRoles()
	if err != nil {
		// error.html does not use the shared header
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить роли",
		})
		return
	}

	c.HTML(http.StatusOK, "user_form.html", gin.H{
		"title":     "Создать пользователя",
		"roles":     roles,
		"username":  usernameCtx, // For header
		"full_name": fullNameCtx, // For header
	})
}

func createUserHandler(c *gin.Context) {
	usernameCtx := c.GetString("username")
	fullNameCtx := c.GetString("full_name")

	if c.Request.Method == "GET" { // Should be POST, but if GET, show form
		roles, _ := models.GetAllRoles()
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

	if username == "" || email == "" || password == "" || formFullName == "" {
		roles, _ := models.GetAllRoles() // Fetch roles again for the form
		c.HTML(http.StatusBadRequest, "user_form.html", gin.H{
			"title":          "Создать пользователя",
			"error":          "Все поля обязательны для заполнения",
			"username_val":   username, // Pass back form values
			"email_val":      email,
			"full_name_val":  formFullName,
			"selected_roles": roleNames,
			"roles":          roles,
			"username":       usernameCtx, // For header
			"full_name":      fullNameCtx, // For header
		})
		return
	}

	_, err := models.CreateUser(username, email, password, formFullName, roleNames)
	if err != nil {
		// error.html does not use the shared header
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось создать пользователя: " + err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, "/admin/users")
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

	roles, err := models.GetAllRoles()
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить роли: " + err.Error()})
		return
	}

	c.HTML(http.StatusOK, "user_form.html", gin.H{
		"title":     "Редактировать пользователя",
		"user":      user,
		"roles":     roles,
		"username":  usernameCtx,
		"full_name": fullNameCtx,
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

	// Use existing values if fields are empty (this logic is in models.UpdateUser, but good to be aware)
	// For rendering the form back on error, we need to decide what to show.
	// Let's assume the model handles using existing if empty for the actual update.

	err = models.UpdateUser(objectID, usernameForm, emailForm, passwordForm, fullNameForm, roleNamesForm)
	if err != nil {
		roles, _ := models.GetAllRoles()
		// user_form.html needs header data
		c.HTML(http.StatusInternalServerError, "user_form.html", gin.H{
			"title":     "Редактировать пользователя",
			"error":     "Не удалось обновить пользователя: " + err.Error(),
			"user":      existingUser, // Show existing user data in form
			"roles":     roles,
			"username":  usernameCtx,
			"full_name": fullNameCtx,
		})
		return
	}

	c.Redirect(http.StatusFound, "/admin/users")
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
	permissionNames := c.PostFormArray("permissions")

	if name == "" || description == "" {
		permissions, _ := models.GetAllPermissions()
		c.HTML(http.StatusBadRequest, "role_form.html", gin.H{
			"title":           "Создать роль",
			"error":           "Имя и описание обязательны для заполнения",
			"name_val":        name,
			"description_val": description,
			"permissions":     permissions, // For repopulating checkboxes
			"selected_perms":  permissionNames,
			"username":        usernameCtx,
			"full_name":       fullNameCtx,
		})
		return
	}

	_, err := models.CreateRole(name, description, permissionNames)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось создать роль: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/admin/roles")
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

	err = models.UpdateRole(objectID, nameForm, descriptionForm, permissionNamesForm)
	if err != nil {
		// error.html
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось обновить роль: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/admin/roles")
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

	c.Redirect(http.StatusFound, "/admin/users")
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

	c.Redirect(http.StatusFound, "/admin/roles")
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

	c.Redirect(http.StatusFound, "/admin/permissions")
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

	c.Redirect(http.StatusFound, "/admin/permissions")
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

	c.Redirect(http.StatusFound, "/admin/permissions")
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
		return
	}

	successMessage := fmt.Sprintf("Успешно создано %d пользователей.", usersCreated)
	if usersCreated == 0 {
		successMessage = "Новых пользователей не создано."
	}

	c.HTML(http.StatusOK, "import_result.html", gin.H{
		"title":     "Результаты импорта",
		"success":   successMessage,
		"username":  usernameCtx,
		"full_name": fullNameCtx,
	})
}
