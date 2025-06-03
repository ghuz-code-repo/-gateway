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

// showUserFormHandler shows the form to create a new user
func showUserFormHandler(c *gin.Context) {
	roles, err := models.GetAllRoles()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить роли",
		})
		return
	}

	c.HTML(http.StatusOK, "user_form.html", gin.H{
		"title": "Создать пользователя",
		"roles": roles,
	})
}

// showRoleFormHandler shows the form to create a new role
func showRoleFormHandler(c *gin.Context) {
	permissions, err := models.GetAllPermissions()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить разрешения",
		})
		return
	}

	c.HTML(http.StatusOK, "role_form.html", gin.H{
		"title":       "Создать роль",
		"permissions": permissions,
	})
}

// showPermissionFormHandler shows the form to create a new permission
func showPermissionFormHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "permission_form.html", gin.H{
		"title": "Добавить сервис",
	})
}

// adminAuthRequired middleware ensures the user is an admin
func adminAuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get JWT token from cookie
		cookie, err := c.Cookie("token")
		if err != nil {
			c.Redirect(http.StatusFound, "/auth/login?redirect=/admin")
			c.Abort()
			return
		}

		// Parse and validate token
		claims, valid := validateToken(cookie)
		if !valid {
			c.Redirect(http.StatusFound, "/auth/login?redirect=/admin")
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

		// Check if user has admin role
		isAdmin := false
		for _, role := range user.Roles {
			if role == "admin" {
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

// adminDashboardHandler handles the admin dashboard page
func adminDashboardHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "admin.html", gin.H{
		"title": "Панель администратора",
	})
}

// User management handlers
func listUsersHandler(c *gin.Context) {
	users, err := models.GetAllUsers()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить пользователей",
		})
		return
	}

	c.HTML(http.StatusOK, "users_list.html", gin.H{
		"title": "Управление пользователями",
		"users": users,
	})
}

func createUserHandler(c *gin.Context) {
	if c.Request.Method == "GET" {
		roles, _ := models.GetAllRoles()
		c.HTML(http.StatusOK, "user_form.html", gin.H{
			"title": "Создать пользователя",
			"roles": roles,
		})
		return
	}

	// Handle POST
	username := c.PostForm("username")
	email := c.PostForm("email")
	password := c.PostForm("password")
	fullName := c.PostForm("full_name")
	roleNames := c.PostFormArray("roles")

	if username == "" || email == "" || password == "" || fullName == "" {
		c.HTML(http.StatusBadRequest, "user_form.html", gin.H{
			"title":     "Создать пользователя",
			"error":     "Все поля обязательны для заполнения",
			"username":  username,
			"email":     email,
			"full_name": fullName,
		})
		return
	}

	_, err := models.CreateUser(username, email, password, fullName, roleNames)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось создать пользователя: " + err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, "/admin/users")
}

// getUserHandler shows the form to edit an existing user
func getUserHandler(c *gin.Context) {
	// Get user ID from URL parameter
	userID := c.Param("id")

	// Convert string ID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный формат ID пользователя",
		})
		return
	}

	// Get user from database
	user, err := models.GetUserByObjectID(objectID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить пользователя: " + err.Error(),
		})
		return
	}

	// Get all roles for role selection
	roles, err := models.GetAllRoles()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить роли: " + err.Error(),
		})
		return
	}

	// Render edit form with user data
	c.HTML(http.StatusOK, "user_form.html", gin.H{
		"title": "Редактировать пользователя",
		"user":  user,
		"roles": roles,
	})
}

// updateUserHandler processes the form submission to update a user
func updateUserHandler(c *gin.Context) {
	// Get user ID from URL parameter
	userID := c.Param("id")

	// Convert string ID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный формат ID пользователя",
		})
		return
	}

	// Get existing user first
	existingUser, err := models.GetUserByObjectID(objectID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить пользователя: " + err.Error(),
		})
		return
	}

	// Get form data
	username := c.PostForm("username")
	email := c.PostForm("email")
	password := c.PostForm("password")
	fullName := c.PostForm("full_name")
	roleNames := c.PostFormArray("roles")

	// Use existing values if fields are empty
	if username == "" {
		username = existingUser.Username
	}
	if email == "" {
		email = existingUser.Email
	}
	if fullName == "" {
		fullName = existingUser.FullName
	}

	// Update user in database with validated data
	err = models.UpdateUser(objectID, username, email, password, fullName, roleNames)
	if err != nil {
		// Get all roles for re-rendering the form
		roles, _ := models.GetAllRoles()

		c.HTML(http.StatusInternalServerError, "user_form.html", gin.H{
			"title": "Редактировать пользователя",
			"error": "Не удалось обновить пользователя: " + err.Error(),
			"user":  existingUser,
			"roles": roles,
		})
		return
	}

	// Redirect to user list page
	c.Redirect(http.StatusFound, "/admin/users")
}

// Role management handlers
func listRolesHandler(c *gin.Context) {
	roles, err := models.GetAllRoles()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить роли: " + err.Error(),
		})
		return
	}

	c.HTML(http.StatusOK, "roles_list.html", gin.H{
		"title": "Управление ролями",
		"roles": roles,
	})
}

func createRoleHandler(c *gin.Context) {
	if c.Request.Method == "GET" {
		permissions, _ := models.GetAllPermissions()
		c.HTML(http.StatusOK, "role_form.html", gin.H{
			"title":       "Создать роль",
			"permissions": permissions,
		})
		return
	}

	// Handle POST
	name := c.PostForm("name")
	description := c.PostForm("description")
	permissionNames := c.PostFormArray("permissions")

	if name == "" || description == "" {
		c.HTML(http.StatusBadRequest, "role_form.html", gin.H{
			"title": "Создать роль",
			"error": "Имя и описание обязательны для заполнения",
		})
		return
	}

	_, err := models.CreateRole(name, description, permissionNames)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось создать роль: " + err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, "/admin/roles")
}

// getRoleHandler shows the form to edit an existing role
func getRoleHandler(c *gin.Context) {
	// Get role ID from URL parameter
	roleID := c.Param("id")

	// Convert string ID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный формат ID роли",
		})
		return
	}

	// Get role from database
	role, err := models.GetRoleByID(objectID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить роль: " + err.Error(),
		})
		return
	}

	// Get all permissions for permission selection
	permissions, err := models.GetAllPermissions()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить разрешения: " + err.Error(),
		})
		return
	}

	// Render edit form with role data
	c.HTML(http.StatusOK, "role_form.html", gin.H{
		"title":       "Редактировать роль",
		"role":        role,
		"permissions": permissions,
	})
}

// updateRoleHandler processes the form submission to update a role
func updateRoleHandler(c *gin.Context) {
	// Get role ID from URL parameter
	roleID := c.Param("id")

	// Convert string ID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный формат ID роли",
		})
		return
	}

	// Get form data
	name := c.PostForm("name")
	description := c.PostForm("description")
	permissionNames := c.PostFormArray("permissions")

	// Remove special protection for admin role's services
	// We only maintain the admin role name

	// Basic validation
	if name == "" || description == "" {
		// Get role and permissions for re-rendering the form with error
		role, _ := models.GetRoleByID(objectID)
		permissions, _ := models.GetAllPermissions()

		c.HTML(http.StatusBadRequest, "role_form.html", gin.H{
			"title":       "Редактировать роль",
			"error":       "Имя и описание обязательны для заполнения",
			"role":        role,
			"permissions": permissions,
		})
		return
	}

	// Get the role from the database
	role, err := models.GetRoleByID(objectID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить роль: " + err.Error(),
		})
		return
	}

	// For admin role, ensure we're not removing the admin status
	if role.Name == "admin" && name != "admin" {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "Нельзя менять имя роли admin",
		})
		return
	}

	// Update role in database
	err = models.UpdateRole(objectID, name, description, permissionNames)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось обновить роль: " + err.Error(),
		})
		return
	}

	// Redirect to role list page
	c.Redirect(http.StatusFound, "/admin/roles")
}

// deleteUserHandler handles the deletion of a user
func deleteUserHandler(c *gin.Context) {
	// Get user ID from URL parameter
	userID := c.Param("id")

	// Convert string ID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный формат ID пользователя",
		})
		return
	}

	// Don't allow deleting the admin user
	user, err := models.GetUserByObjectID(objectID)
	if err == nil && user.Username == "admin" {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "Невозможно удалить пользователя admin",
		})
		return
	}

	// Store who performed the deletion for audit purposes
	// adminUserID := getAdminUserID(c) // You'll need to implement this function

	// Delete the user - this will now send an email notification
	err = models.DeleteUser(objectID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось удалить пользователя: " + err.Error(),
		})
		return
	}

	// Redirect to user list page
	c.Redirect(http.StatusFound, "/admin/users")
}

// Helper function to get the admin user ID from the context
func getAdminUserID(c *gin.Context) string {
	cookie, err := c.Cookie("token")
	if err != nil {
		return "unknown"
	}

	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(cookie, claims, func(token *jwt.Token) (interface{}, error) {
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			jwtSecret = "default_jwt_secret_change_in_production"
		}
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		return "unknown"
	}

	return claims.UserID
}

// deleteRoleHandler handles the deletion of a role
func deleteRoleHandler(c *gin.Context) {
	// Get role ID from URL parameter
	roleID := c.Param("id")

	// Convert string ID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный формат ID роли",
		})
		return
	}

	// Don't allow deleting the admin role
	role, err := models.GetRoleByID(objectID)
	if err == nil && role.Name == "admin" {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "Невозможно удалить роль admin",
		})
		return
	}

	// Check if role is assigned to any user
	usersWithRole, err := models.GetUsersWithRole(role.Name)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось проверить назначение ролей: " + err.Error(),
		})
		return
	}

	if len(usersWithRole) > 0 {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "Невозможно удалить роль, которая назначена пользователям",
		})
		return
	}

	// Delete the role
	err = models.DeleteRole(objectID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось удалить роль: " + err.Error(),
		})
		return
	}

	// Redirect to role list page
	c.Redirect(http.StatusFound, "/admin/roles")
}

// Permission management handlers
func listPermissionsHandler(c *gin.Context) {
	permissions, err := models.GetAllPermissions()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить разрешения: " + err.Error(),
		})
		return
	}

	c.HTML(http.StatusOK, "permissions_list.html", gin.H{
		"title":       "Управление сервисами",
		"permissions": permissions,
	})
}

// createPermissionHandler creates a new service permission
func createPermissionHandler(c *gin.Context) {
	if c.Request.Method == "GET" {
		c.HTML(http.StatusOK, "permission_form.html", gin.H{
			"title": "Добавить сервис",
		})
		return
	}

	// Handle POST
	service := c.PostForm("service")
	displayName := c.PostForm("display_name")

	if service == "" {
		c.HTML(http.StatusBadRequest, "permission_form.html", gin.H{
			"title": "Добавить сервис",
			"error": "Имя сервиса обязательно для заполнения",
		})
		return
	}

	if displayName == "" {
		displayName = service // Default to service name if no display name provided
	}

	// Create permission in database
	err := models.CreatePermission(service, displayName)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось создать разрешение: " + err.Error(),
		})
		return
	}

	// Redirect to permissions list page
	c.Redirect(http.StatusFound, "/admin/permissions")
}

// getPermissionHandler shows the form to edit an existing permission
func getPermissionHandler(c *gin.Context) {
	// Get permission ID from URL parameter
	permissionID := c.Param("id")

	// Convert string ID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(permissionID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный формат ID разрешения",
		})
		return
	}

	// Get permission from database
	permission, err := models.GetPermissionByID(objectID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить разрешение: " + err.Error(),
		})
		return
	}

	// Render edit form with permission data
	c.HTML(http.StatusOK, "permission_form.html", gin.H{
		"title":      "Редактировать сервис",
		"permission": permission,
	})
}

// updatePermissionHandler processes the form submission to update a permission
func updatePermissionHandler(c *gin.Context) {
	// Get permission ID from URL parameter
	permissionID := c.Param("id")

	// Convert string ID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(permissionID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный формат ID разрешения",
		})
		return
	}

	// Get form data
	displayName := c.PostForm("display_name")

	if displayName == "" {
		permission, _ := models.GetPermissionByID(objectID)
		c.HTML(http.StatusBadRequest, "permission_form.html", gin.H{
			"title":      "Редактировать сервис",
			"error":      "Отображаемое имя обязательно для заполнения",
			"permission": permission,
		})
		return
	}

	// Update permission in database
	err = models.UpdatePermissionDisplayName(objectID, displayName)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось обновить разрешение: " + err.Error(),
		})
		return
	}

	// Redirect to permissions list page
	c.Redirect(http.StatusFound, "/admin/permissions")
}

// deletePermissionHandler handles the deletion of a permission
func deletePermissionHandler(c *gin.Context) {
	// Get permission ID from URL parameter
	permissionID := c.Param("id")

	// Convert string ID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(permissionID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный формат ID разрешения",
		})
		return
	}

	// Получение информации о разрешении
	permission, err := models.GetPermissionByID(objectID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить информацию о разрешении: " + err.Error(),
		})
		return
	}

	// Удаляем эту проверку, чтобы разрешить удаление любых сервисов
	// if err == nil && (permission.Service == "referal" || permission.Service == "sample") {
	//     c.HTML(http.StatusForbidden, "error.html", gin.H{
	//         "error": "Невозможно удалить системные разрешения",
	//     })
	//     return
	// }

	// Check if permission is used by any roles
	rolesWithPermission, err := models.GetRolesWithPermission(permission.Service)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось проверить использование разрешений: " + err.Error(),
		})
		return
	}

	if len(rolesWithPermission) > 0 {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "Невозможно удалить разрешение, которое используется ролями",
		})
		return
	}

	// Delete the permission
	err = models.DeletePermission(objectID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось удалить разрешение: " + err.Error(),
		})
		return
	}

	// Redirect to permission list page
	c.Redirect(http.StatusFound, "/admin/permissions")
}

// showUserImportFormHandler shows the form to import users from Excel
func showUserImportFormHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "user_import.html", gin.H{
		"title": "Импорт пользователей из Excel",
	})
}

// importUsersHandler processes the Excel file upload and imports users
func importUsersHandler(c *gin.Context) {
	// Get uploaded file
	file, err := c.FormFile("excelFile")
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Нет файла для загрузки: " + err.Error(),
		})
		return
	}

	// Validate file extension
	ext := filepath.Ext(file.Filename)
	if ext != ".xlsx" && ext != ".xls" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"error": "Неверный тип файла. Разрешены только файлы Excel (.xlsx, .xls).",
		})
		return
	}

	// Create temp file path
	tempFilePath := filepath.Join(os.TempDir(), "user_import"+time.Now().Format("20060102150405")+ext)

	// Save file to temp directory
	if err := c.SaveUploadedFile(file, tempFilePath); err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось сохранить файл: " + err.Error(),
		})
		return
	}

	// Import users
	usersCreated, err := models.ImportUsersFromExcel(tempFilePath)

	// Delete temp file
	os.Remove(tempFilePath)

	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось импортировать пользователей: " + err.Error(),
		})
		return
	}

	// If no users were created, show a warning
	if usersCreated == 0 {
		c.HTML(http.StatusOK, "import_result.html", gin.H{
			"title":   "Результаты импорта",
			"warning": "Не удалось создать новых пользователей.",
		})
		return
	}

	// Redirect to user list with success message
	c.Redirect(http.StatusFound, "/admin/users?imported="+fmt.Sprintf("%d", usersCreated))
}
