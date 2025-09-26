package routes

import (
	"auth-service/models"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// listServicesHandlerWithAccess shows services based on user access level
func listServicesHandlerWithAccess(c *gin.Context) {
	// Check if user is system admin
	isSystemAdmin := c.GetBool("isSystemAdmin")
	
	if isSystemAdmin {
		listServicesHandler(c)
		return
	}

	// For service admins, show only services they can manage
	user := c.MustGet("user").(*models.User)
	// TODO: Implement GetUserManagedServices in models
	userServices := []models.Service{} // Placeholder

	c.HTML(http.StatusOK, "admin_services.html", gin.H{
		"title":        "Управление сервисами",
		"services":     userServices,
		"username":     user.Username,
		"full_name":    user.GetFullName(),
		"short_name":   user.GetShortName(),
		"user":         user,
		"isSystemAdmin": isSystemAdmin,
	})
}

// listServicesHandler displays all services (system admin only)
func listServicesHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	services, err := models.GetAllServices()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить сервисы",
		})
		return
	}

	c.HTML(http.StatusOK, "admin_services.html", gin.H{
		"title":        "Управление сервисами",
		"services":     services,
		"username":     user.Username,
		"full_name":    user.GetFullName(),
		"short_name":   user.GetShortName(),
		"user":         user,
		"isSystemAdmin": true,
	})
}

// showServiceFormHandler shows the form to create a new service
func showServiceFormHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	
	c.HTML(http.StatusOK, "service_form.html", gin.H{
		"title":      "Создать сервис",
		"username":   user.Username,
		"full_name":  user.GetFullName(),
		"short_name": user.GetShortName(),
		"user":       user,
	})
}

// createServiceHandler creates a new service
func createServiceHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	if c.Request.Method == "GET" {
		c.HTML(http.StatusOK, "service_form.html", gin.H{
			"title":      "Создать сервис",
			"username":   user.Username,
			"full_name":  user.GetFullName(),
			"short_name": user.GetShortName(),
			"user":       user,
		})
		return
	}

	// Handle POST
	key := c.PostForm("key")
	name := c.PostForm("name")
	description := c.PostForm("description")

	if key == "" || name == "" {
		c.HTML(http.StatusBadRequest, "service_form.html", gin.H{
			"title":       "Создать сервис",
			"error":       "Ключ и название сервиса обязательны",
			"key_val":     key,
			"name_val":    name,
			"desc_val":    description,
			"username":    user.Username,
			"full_name":   user.GetFullName(),
			"short_name":  user.GetShortName(),
			"user":        user,
		})
		return
	}

	// Create service with empty permissions list
	_, err := models.CreateService(key, name, description, []models.PermissionDef{})
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось создать сервис: " + err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, "/services")
}

// getServiceHandlerWithAccess shows service details with access control
func getServiceHandlerWithAccess(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	serviceKey := c.Param("serviceKey")
	
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "Сервис не найден"})
		return
	}

	// Check access
	isSystemAdmin := c.GetBool("isSystemAdmin")
	if !isSystemAdmin && !hasServiceAdminRole(user, service.Key) {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "У вас нет прав для доступа к этому сервису",
		})
		return
	}

	// Get service roles
	serviceRoles, err := models.GetRolesByService(service.Key)
	if err != nil {
		// Log error but don't fail the request
		serviceRoles = []models.Role{}
	}

	// Get users with roles in this service
	serviceUsers, err := models.GetUsersWithServiceRolesNew(service.Key)
	if err != nil {
		// Log error but don't fail the request
		serviceUsers = []models.UserWithServiceRoles{}
	}

	// Determine manage mode - true if user is service admin but not system admin
	manageMode := !isSystemAdmin && hasServiceAdminRole(user, service.Key)
	
	// Check for import success message
	importSuccess := c.Query("import_success")
	
	templateData := gin.H{
		"title":         "Детали сервиса",
		"service":       service,
		"serviceRoles":  serviceRoles,
		"serviceUsers":  serviceUsers,
		"username":      user.Username,
		"full_name":     user.GetFullName(),
		"short_name":    user.GetShortName(),
		"user":          user,
		"isSystemAdmin": isSystemAdmin,
		"manageMode":    manageMode,
	}
	
	// Add import success message if present
	if importSuccess != "" {
		templateData["importSuccessMessage"] = importSuccess
	}
	
	c.HTML(http.StatusOK, "admin_service_form.html", templateData)
}

// updateServiceHandlerWithAccess updates service with access control
func updateServiceHandlerWithAccess(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	serviceKey := c.Param("serviceKey")
	
	// Get service first to check access
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "Сервис не найден"})
		return
	}

	// Check access
	isSystemAdmin := c.GetBool("isSystemAdmin")
	if !isSystemAdmin && !hasServiceAdminRole(user, service.Key) {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "У вас нет прав для изменения этого сервиса",
		})
		return
	}

	// Get form data
	name := c.PostForm("name")
	description := c.PostForm("description")
	newKey := c.PostForm("key")
	confirmKeyChange := c.PostForm("confirmKeyChange")
	
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Название сервиса обязательно"})
		return
	}
	
	if newKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ключ сервиса обязателен"})
		return
	}
	
	// Check if key is being changed
	keyChanged := newKey != service.Key
	if keyChanged {
		// Require confirmation for key changes
		if confirmKeyChange != "true" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Изменение ключа сервиса требует подтверждения. Это может повлиять на интеграции.",
				"message": "Изменение ключа сервиса требует подтверждения. Это может повлиять на интеграции.",
				"requires_confirmation": true,
				"key_change": true,
			})
			return
		}
		
		// Check if new key already exists
		existingService, err := models.GetServiceByKey(newKey)
		if err == nil && existingService.ID != service.ID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Сервис с таким ключом уже существует"})
			return
		}
	}
	
	// Update service with new key and permissions
	err = models.UpdateService(service.ID, newKey, name, description, service.AvailablePermissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при обновлении сервиса: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/services/"+newKey)
}

// deleteServiceHandler deletes a service (system admin only)
func deleteServiceHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "Сервис не найден"})
		return
	}
	objectID := service.ID

	err = models.DeleteService(objectID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось удалить сервис: " + err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, "/services")
}

// addServicePermissionHandler adds a permission to a service
func addServicePermissionHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	permissionName := c.PostForm("name")
	permissionDisplayName := c.PostForm("displayName")
	permissionDescription := c.PostForm("description")
	
	if permissionName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Имя разрешения обязательно"})
		return
	}
	
	// Validate service exists
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Сервис не найден"})
		return
	}
	
	// Create permission definition
	permissionDef := models.PermissionDef{
		Name:        permissionName,
		DisplayName: permissionDisplayName,
		Description: permissionDescription,
	}
	
	// Add permission to service
	err = models.AddPermissionToService(service.Key, permissionDef)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при добавлении разрешения: " + err.Error()})
		return
	}
	
	c.Redirect(http.StatusFound, "/services/"+service.Key)
}

func updateServicePermissionHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Service permission update not implemented yet"})
}

func deleteServicePermissionHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	permissionName := c.Param("permName")
	
	if permissionName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Имя разрешения обязательно"})
		return
	}
	
	// Validate service exists
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Сервис не найден"})
		return
	}
	
	// Remove permission from service (soft delete)
	err = models.RemovePermissionFromService(service.Key, permissionName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при удалении разрешения: " + err.Error()})
		return
	}
	
	c.Redirect(http.StatusFound, "/services/"+service.Key)
}

func createServiceRoleHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	roleName := c.PostForm("role_name")
	roleDescription := c.PostForm("role_description")
	
	if roleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Имя роли обязательно"})
		return
	}
	
	// Validate service exists
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Сервис не найден"})
		return
	}
	
	// Get permissions from form (checkboxes)
	var permissions []string
	c.Request.ParseForm()
	for key, values := range c.Request.PostForm {
		if len(key) > 5 && key[:5] == "perm_" && len(values) > 0 && values[0] == "on" {
			permName := key[5:] // Remove "perm_" prefix
			permissions = append(permissions, permName)
		}
	}
	
	// Create the role
	_, err = models.CreateRole(service.Key, roleName, roleDescription, permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать роль: " + err.Error()})
		return
	}
	
	// Redirect back to service page with roles tab active
	c.Redirect(http.StatusFound, "/services/"+service.Key)
}

func getServiceRoleHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Service role retrieval not implemented yet"})
}

func updateServiceRoleHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Service role update not implemented yet"})
}

func deleteServiceRoleHandler(c *gin.Context) {
	serviceID := c.Param("id")
	roleID := c.Param("roleId")
	
	if roleID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID роли обязателен"})
		return
	}
	
	// Validate service exists
	serviceObjectID, err := primitive.ObjectIDFromHex(serviceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID сервиса"})
		return
	}
	
	_, err = models.GetServiceByID(serviceObjectID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Сервис не найден"})
		return
	}
	
	// Validate role ID and convert to ObjectID
	roleObjectID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID роли"})
		return
	}
	
	// Delete the role
	err = models.DeleteRole(roleObjectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при удалении роли: " + err.Error()})
		return
	}
	
	c.Redirect(http.StatusFound, "/services/"+serviceID)
}

func assignUserToServiceRoleHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "User role assignment not implemented yet"})
}

func getServiceUsersHandler(c *gin.Context) {
	serviceID := c.Param("id")
	
	// Validate service exists
	serviceObjectID, err := primitive.ObjectIDFromHex(serviceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID сервиса"})
		return
	}
	
	service, err := models.GetServiceByID(serviceObjectID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Сервис не найден"})
		return
	}
	
	// Get users with roles in this service
	users, err := models.GetUsersWithServiceRoles(service.Key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения пользователей"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"service": service.Name,
	})
}

func addUserToServiceHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")

	var req struct {
		Identifier string   `json:"identifier"`
		FullName   string   `json:"full_name"`
		ServiceKey string   `json:"service_key"`
		Roles      []string `json:"roles"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if req.Identifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Identifier is required"})
		return
	}

	if len(req.Roles) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one role must be specified"})
		return
	}

	// Get service by key
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil || service == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		return
	}

	// Find user by identifier or create new one
	user, err := models.GetUserByEmailOrUsername(req.Identifier)
	if err != nil || user == nil {
		// If user not found and we have full name, create new user
		if req.FullName != "" {
			// Check if identifier is email format
			isEmail := len(req.Identifier) > 0 && req.Identifier[0] != '@' && 
			         len(req.Identifier) > 3 && 
			         strings.Contains(req.Identifier, "@") && 
			         strings.Contains(req.Identifier, ".")
			
			var username, email string
			if isEmail {
				email = req.Identifier
				username = strings.Split(req.Identifier, "@")[0]
			} else {
				username = req.Identifier
				email = ""
			}
			
			// Create new user with temporary password
			userID, err := models.CreateUser(username, email, "temporary123", req.FullName, []string{})
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create new user: " + err.Error()})
				return
			}
			
			// Get the created user
			user, err = models.GetUserByObjectID(userID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve created user"})
				return
			}
		} else {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
	}

	// Get current user for assignedBy
	currentUser := c.MustGet("user").(*models.User)
	if currentUser == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Assign roles to user
	for _, roleName := range req.Roles {
		err := models.AssignUserToServiceRole(user.ID, service.Key, roleName, currentUser.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign role: " + roleName})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User added to service successfully",
		"user": gin.H{
			"id":       user.ID.Hex(),
			"username": user.Username,
			"email":    user.Email,
			"fullName": user.FullName,
		},
		"assignedRoles": req.Roles,
	})
}

func updateUserServiceRolesHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	userID := c.Param("userId")

	var req struct {
		RoleNames []string `json:"roleNames"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Convert userID to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Get service by key
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil || service == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		return
	}

	// Get current user for assignedBy
	currentUser := c.MustGet("user").(*models.User)

	// Get current roles for the user in this service
	currentAssignments, err := models.GetUserServiceRoleAssignments(userObjectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get current roles"})
		return
	}

	// Build map of current active roles for this service
	currentRoles := make(map[string]bool)
	if currentAssignments != nil {
		for _, assignment := range currentAssignments {
			if assignment.ServiceKey == service.Key && assignment.IsActive {
				currentRoles[assignment.RoleName] = true
			}
		}
	}

	// Build map of new roles
	newRoles := make(map[string]bool)
	for _, roleName := range req.RoleNames {
		newRoles[roleName] = true
	}

	// Remove roles that are no longer needed
	for roleName := range currentRoles {
		if !newRoles[roleName] {
			log.Printf("Removing role '%s' from user %s in service %s", roleName, userObjectID.Hex(), service.Key)
			err := models.RemoveUserFromServiceRole(userObjectID, service.Key, roleName)
			if err != nil {
				log.Printf("Failed to remove role '%s': %v", roleName, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove role: " + roleName})
				return
			}
		}
	}

	// Add new roles that user doesn't have yet
	for roleName := range newRoles {
		if !currentRoles[roleName] {
			log.Printf("Adding role '%s' to user %s in service %s", roleName, userObjectID.Hex(), service.Key)
			err := models.AssignUserToServiceRole(userObjectID, service.Key, roleName, currentUser.ID)
			if err != nil {
				log.Printf("Failed to assign role '%s': %v", roleName, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign role: " + roleName})
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "User roles updated successfully"})
}

// checkUserExistsHandler checks if a user exists by username or email
func checkUserExistsHandler(c *gin.Context) {
	identifier := c.Query("identifier")
	serviceKey := c.Query("serviceKey")

	if identifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Identifier is required"})
		return
	}

	// Check if user exists
	targetUser, err := models.GetUserByEmailOrUsername(identifier)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found", "exists": false})
		return
	}

	if targetUser == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found", "exists": false})
		return
	}

	// Get service roles if serviceKey is provided
	var serviceRoles []string
	if serviceKey != "" {
		service, err := models.GetServiceByKey(serviceKey)
		if err == nil && service != nil {
			// Get target user's roles for this service
			assignments, err := models.GetUserServiceRoleAssignments(targetUser.ID)
			if err == nil && assignments != nil {
				for _, assignment := range assignments {
					if assignment.ServiceKey == service.Key {
						serviceRoles = append(serviceRoles, assignment.RoleName)
					}
				}
			}
		}
	}

	// Определяем, есть ли у пользователя доступ к сервису
	hasServiceAccess := len(serviceRoles) > 0

	c.JSON(http.StatusOK, gin.H{
		"exists":          true,
		"hasServiceAccess": hasServiceAccess,
		"user": gin.H{
			"id":        targetUser.ID.Hex(),
			"username":  targetUser.Username,
			"email":     targetUser.Email,
			"fullName":  targetUser.GetFullName(),
			"shortName": targetUser.GetShortName(),
			"avatarPath": targetUser.AvatarPath,
		},
		"serviceRoles": serviceRoles,
	})
}
