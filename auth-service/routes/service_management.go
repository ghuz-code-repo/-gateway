package routes

import (
	"auth-service/models"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// listServicesHandlerWithAccess shows services based on user access level
func listServicesHandlerWithAccess(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	// Check if user is system admin
	isSystemAdmin := c.GetBool("isSystemAdmin")

	// System admins can see all services
	if isSystemAdmin {
		listServicesHandler(c)
		return
	}

	// For non-admin users, show only services they have access to
	// This includes users with any active role in the service (not just service-manager)
	allServices, err := models.GetAllServicesWithOptions(false) // Don't include deleted
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить сервисы",
		})
		return
	}

	// Filter services where user has ANY active role
	var accessibleServices []models.Service
	userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
	if err == nil {
		// Build a set of service keys where user has active roles
		serviceAccess := make(map[string]bool)
		for _, role := range userServiceRoles {
			if role.IsActive {
				serviceAccess[role.ServiceKey] = true
			}
		}

		// Filter services user has access to
		for _, service := range allServices {
			if serviceAccess[service.Key] {
				accessibleServices = append(accessibleServices, service)
			}
		}
	}

	c.HTML(http.StatusOK, "admin_services.html", gin.H{
		"title":            "Управление сервисами",
		"services":         accessibleServices,
		"username":         user.Username,
		"full_name":        user.GetFullName(),
		"short_name":       user.GetShortName(),
		"user":             user,
		"isSystemAdmin":    false,
		"isServiceManager": true, // They are managing specific services
	})
}

// listServicesHandler displays all services including deleted ones (system admin only)
func listServicesHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	isSystemAdmin := c.GetBool("isSystemAdmin")

	// System admins can see deleted services
	services, err := models.GetAllServicesWithOptions(true) // Include deleted services
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить сервисы",
		})
		return
	}

	c.HTML(http.StatusOK, "admin_services.html", gin.H{
		"title":            "Управление сервисами",
		"services":         services,
		"username":         user.Username,
		"full_name":        user.GetFullName(),
		"short_name":       user.GetShortName(),
		"user":             user,
		"isSystemAdmin":    isSystemAdmin,
		"isServiceManager": false, // System admin is not a service manager
	})
}

// showServiceFormHandler shows the form to create a new service
func showServiceFormHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	c.HTML(http.StatusOK, "admin_service_form.html", gin.H{
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
		c.HTML(http.StatusOK, "admin_service_form.html", gin.H{
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
		c.HTML(http.StatusBadRequest, "admin_service_form.html", gin.H{
			"title":      "Создать сервис",
			"error":      "Ключ и название сервиса обязательны",
			"key_val":    key,
			"name_val":   name,
			"desc_val":   description,
			"username":   user.Username,
			"full_name":  user.GetFullName(),
			"short_name": user.GetShortName(),
			"user":       user,
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

	// Register external permissions in auth-service for managing this service
	// These permissions allow control of this service from auth-service UI
	err = models.RegisterExternalServicePermissions(key, name)
	if err != nil {
		log.Printf("WARNING: Failed to register external permissions for service %s: %v", key, err)
		// Don't fail service creation if external permissions fail
		// Admin can add them manually later
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

	// Check access - allow system admin, service admin, or service manager
	isSystemAdmin := c.GetBool("isSystemAdmin")
	isServiceManager := c.GetBool("isServiceManager")
	hasExternalRoleAccess := c.GetBool("hasExternalRoleAccess")

	// If middleware passed (user has admin or service-manager role), allow access
	// isServiceManager is true for service-manager role, false for admin role
	// But both should have access since middleware already validated
	hasAccess := isSystemAdmin || isServiceManager || hasExternalRoleAccess || c.GetString("serviceKey") == service.Key

	if !hasAccess {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "У вас нет прав для доступа к этому сервису.",
		})
		return
	}

	// Get service roles (for auth service, exclude external roles)
	serviceRoles, err := models.GetInternalRolesByService(service.Key)
	if err != nil {
		// Log error but don't fail the request
		log.Printf("Warning: Failed to get roles for service %s: %v", service.Key, err)
		serviceRoles = []models.Role{}
	}
	log.Printf("DEBUG: Found %d internal roles for service %s", len(serviceRoles), service.Key)
	if len(serviceRoles) > 0 {
		log.Printf("DEBUG: First role: %+v", serviceRoles[0])
	}

	// Build role display names map for template
	roleDisplayNames := make(map[string]string)
	for _, role := range serviceRoles {
		if role.DisplayName != "" {
			roleDisplayNames[role.Name] = role.DisplayName
		} else {
			roleDisplayNames[role.Name] = role.Name
		}
	}

	// Get users with roles in this service
	serviceUsers, err := models.GetUsersWithServiceRolesNew(service.Key)
	if err != nil {
		// Log error but don't fail the request
		log.Printf("Warning: Failed to get users for service %s: %v", service.Key, err)
		serviceUsers = []models.UserWithServiceRoles{}
	}

	// Get external roles - roles from auth-service that grant access TO this service
	externalRoles, err := models.GetExternalRolesForService(service.Key)
	if err != nil {
		log.Printf("Warning: Failed to get external roles for service %s: %v", service.Key, err)
		externalRoles = []models.Role{}
	}

	// Add external roles to roleDisplayNames map
	for _, role := range externalRoles {
		if role.DisplayName != "" {
			roleDisplayNames[role.Name] = role.DisplayName
		} else {
			roleDisplayNames[role.Name] = role.Name
		}
	}
	log.Printf("DEBUG: Found %d external roles for service %s", len(externalRoles), service.Key)

	// Get available external permissions for this service (permissions with auth.<serviceKey>.* pattern)
	externalPermissions, err := models.GetExternalPermissionsForService(service.Key)
	if err != nil {
		log.Printf("Warning: Failed to get external permissions for service %s: %v", service.Key, err)
		externalPermissions = []models.ExternalPermissionCategory{}
	}
	log.Printf("DEBUG: Found %d external permission categories for service %s", len(externalPermissions), service.Key)

	// Build permission display names map for template
	permissionDisplayNames := make(map[string]string)
	for _, category := range externalPermissions {
		for _, perm := range category.Permissions {
			if perm.DisplayName != "" {
				permissionDisplayNames[perm.Code] = perm.DisplayName
			} else {
				permissionDisplayNames[perm.Code] = perm.Code
			}
		}
	}

	// Also add internal permissions display names
	for _, permDef := range service.AvailablePermissions {
		if permDef.DisplayName != "" {
			permissionDisplayNames[permDef.Name] = permDef.DisplayName
		} else {
			permissionDisplayNames[permDef.Name] = permDef.Name
		}
	}

	// Determine manage mode - true if user is service manager but not system admin
	manageMode := !isSystemAdmin && isServiceManager

	// Check permissions for this specific service (external permissions like auth.referal.*)
	// These permissions control what user can do when accessing service settings via external role
	servicePermPrefix := fmt.Sprintf("auth.%s.", service.Key)

	// For auth-service, external roles are not allowed (it's a system service)
	isAuthService := service.Key == "auth"

	// Check external roles permissions for the current user
	// Can be granted via global auth.external_roles.* OR service-specific auth.<service>.roles.*
	// But NOT for auth-service - it cannot have external roles
	canViewExternalRoles := !isAuthService && (isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, "auth.external_roles.view") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.view") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*"))
	canCreateExternalRoles := !isAuthService && (isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, "auth.external_roles.create") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.create") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*"))
	canEditExternalRoles := !isAuthService && (isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, "auth.external_roles.edit") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.edit") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*"))
	canDeleteExternalRoles := !isAuthService && (isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, "auth.external_roles.delete") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.delete") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*"))
	canAssignExternalRoles := !isAuthService && (isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, "auth.external_roles.assign") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.assign") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*"))

	// Internal roles management permissions
	// Can be managed by system admins, service managers, OR users with auth.<service>.service_roles.* permissions
	canViewInternalRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.view") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.*")
	canCreateInternalRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.create") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.*")
	canEditInternalRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.edit") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.*")
	canDeleteInternalRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.delete") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.*")
	canAssignInternalRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.assign") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.*")

	// Keep old variable names for backward compatibility in template
	canViewRoles := canViewInternalRoles
	canCreateRoles := canCreateInternalRoles
	canEditRoles := canEditInternalRoles
	canDeleteRoles := canDeleteInternalRoles

	// Users management permissions
	canViewUsers := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.view") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.*")
	canAddUsers := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.add") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.*")
	canEditUsers := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.edit") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.*")
	canDeleteUsers := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.delete") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.*")
	// canAssignRoles is true if user can assign either internal or external roles
	canAssignRoles := canAssignInternalRoles || canAssignExternalRoles ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.assign") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*")
	canImportUsers := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.import") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.*")
	canExportUsers := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.export") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.*")

	// Settings permissions
	canViewSettings := isSystemAdmin ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"settings.view") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"settings.*")
	canEditSettings := isSystemAdmin ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"settings.edit") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"settings.*")

	// Logs permissions
	canViewLogs := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"logs.view") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"logs.*")

	// Check if user can manage internal roles (has access to service management)
	// Now based on actual permissions
	canManageInternalRoles := canCreateRoles || canEditRoles || canDeleteRoles

	// Check for import success message
	importSuccess := c.Query("import_success")

	// Get permissions grouped by category for internal roles
	permissionCategories := service.GetPermissionsByCategory()

	templateData := gin.H{
		"title":                  "Детали сервиса",
		"service":                service,
		"serviceRoles":           serviceRoles,
		"serviceUsers":           serviceUsers,
		"externalRoles":          externalRoles,
		"externalPermissions":    externalPermissions,
		"permissionCategories":   permissionCategories,
		"roleDisplayNames":       roleDisplayNames,
		"permissionDisplayNames": permissionDisplayNames,
		"username":               user.Username,
		"full_name":              user.GetFullName(),
		"short_name":             user.GetShortName(),
		"user":                   user,
		"isSystemAdmin":          isSystemAdmin,
		"isServiceManager":       isServiceManager,
		"manageMode":             manageMode,
		"canViewExternalRoles":   canViewExternalRoles,
		"canCreateExternalRoles": canCreateExternalRoles,
		"canEditExternalRoles":   canEditExternalRoles,
		"canDeleteExternalRoles": canDeleteExternalRoles,
		"canAssignExternalRoles": canAssignExternalRoles,
		"canAssignInternalRoles": canAssignInternalRoles,
		"canManageInternalRoles": canManageInternalRoles,
		// Service-specific permissions
		"canViewRoles":    canViewRoles,
		"canCreateRoles":  canCreateRoles,
		"canEditRoles":    canEditRoles,
		"canDeleteRoles":  canDeleteRoles,
		"canViewUsers":    canViewUsers,
		"canAddUsers":     canAddUsers,
		"canEditUsers":    canEditUsers,
		"canDeleteUsers":  canDeleteUsers,
		"canAssignRoles":  canAssignRoles,
		"canImportUsers":  canImportUsers,
		"canExportUsers":  canExportUsers,
		"canViewSettings": canViewSettings,
		"canEditSettings": canEditSettings,
		"canViewLogs":     canViewLogs,
	}
	log.Printf("DEBUG: Template data for service %s - serviceRoles count: %d, externalRoles count: %d", service.Key, len(serviceRoles), len(externalRoles))
	log.Printf("DEBUG: Permissions check - isSystemAdmin: %v, isServiceManager: %v, hasExternalRoleAccess: %v", isSystemAdmin, isServiceManager, hasExternalRoleAccess)
	log.Printf("DEBUG: Role permissions - canCreateRoles: %v, canEditRoles: %v, canDeleteRoles: %v", canCreateRoles, canEditRoles, canDeleteRoles)
	log.Printf("DEBUG: User permissions - canViewUsers: %v, canAddUsers: %v, canEditUsers: %v, canDeleteUsers: %v", canViewUsers, canAddUsers, canEditUsers, canDeleteUsers)
	log.Printf("DEBUG: External roles permissions - canViewExternalRoles: %v, canAssignExternalRoles: %v, canAssignRoles: %v", canViewExternalRoles, canAssignExternalRoles, canAssignRoles)

	// Add import success message if present
	if importSuccess != "" {
		templateData["importSuccessMessage"] = importSuccess
	}

	c.HTML(http.StatusOK, "admin_service_form.html", templateData)
}

// updateServiceHandlerWithAccess updates service with access control
func updateServiceHandlerWithAccess(c *gin.Context) {
	serviceKey := c.Param("serviceKey")

	// Get service first to check access
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "Сервис не найден"})
		return
	}

	// Check access - allow system admin, service admin, or service manager
	isSystemAdmin := c.GetBool("isSystemAdmin")
	isServiceManager := c.GetBool("isServiceManager")
	hasAccess := isSystemAdmin || isServiceManager || c.GetString("serviceKey") == service.Key

	if !hasAccess {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "У вас нет прав для изменения этого сервиса.",
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
				"error":                 "Изменение ключа сервиса требует подтверждения. Это может повлиять на интеграции.",
				"message":               "Изменение ключа сервиса требует подтверждения. Это может повлиять на интеграции.",
				"requires_confirmation": true,
				"key_change":            true,
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

// deleteServiceHandler performs soft delete of a service (system admin only)
// The service is marked as deleted but can be restored
func deleteServiceHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")

	// Verify service exists
	_, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "Сервис не найден"})
		return
	}

	// Perform soft delete
	err = models.SoftDeleteService(serviceKey)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось удалить сервис: " + err.Error(),
		})
		return
	}

	// Regenerate nginx config to remove deleted service
	if err := regenerateNginxConfig(); err != nil {
		log.Printf("Warning: Failed to regenerate nginx config after service deletion: %v", err)
	}

	c.Redirect(http.StatusFound, "/services")
}

// restoreServiceHandler restores a soft-deleted service (system admin only)
func restoreServiceHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")

	// Perform restore
	err := models.RestoreService(serviceKey)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось восстановить сервис: " + err.Error(),
		})
		return
	}

	// Regenerate nginx config (service might have active instance)
	if err := regenerateNginxConfig(); err != nil {
		log.Printf("Warning: Failed to regenerate nginx config after service restore: %v", err)
	}

	c.Redirect(http.StatusFound, "/services/"+serviceKey)
}

// hardDeleteServiceHandler permanently deletes a service (system admin only)
// WARNING: This action cannot be undone!
func hardDeleteServiceHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")

	// Verify service exists (including deleted ones)
	_, err := models.GetServiceByKeyWithOptions(serviceKey, true)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "Сервис не найден"})
		return
	}

	// Perform hard delete
	err = models.HardDeleteService(serviceKey)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось окончательно удалить сервис: " + err.Error(),
		})
		return
	}

	// Regenerate nginx config to remove deleted service
	if err := regenerateNginxConfig(); err != nil {
		log.Printf("Warning: Failed to regenerate nginx config after hard delete: %v", err)
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
	serviceKey := c.Param("serviceKey")
	permissionName := c.Param("permName")

	if permissionName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Имя разрешения обязательно"})
		return
	}

	// Try to parse from form data first (from HTML form)
	displayName := c.PostForm("displayName")
	if displayName == "" {
		displayName = c.PostForm("display_name") // fallback for legacy forms
	}
	description := c.PostForm("description")

	// If form data is empty, try JSON
	if displayName == "" && description == "" {
		var input struct {
			DisplayName string `json:"displayName"`
			Description string `json:"description"`
		}
		if err := c.ShouldBindJSON(&input); err == nil {
			displayName = input.DisplayName
			description = input.Description
		}
	}

	// Validate service exists
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Сервис не найден"})
		return
	}

	// Find and update permission
	found := false
	for i, perm := range service.AvailablePermissions {
		if perm.Name == permissionName {
			service.AvailablePermissions[i].DisplayName = displayName
			service.AvailablePermissions[i].Description = description
			found = true
			break
		}
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Разрешение не найдено"})
		return
	}

	// Save updated service
	err = models.UpdateServicePermissions(service.Key, service.AvailablePermissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при обновлении разрешения: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Разрешение успешно обновлено"})
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
	roleDisplayName := c.PostForm("role_display_name")
	roleDescription := c.PostForm("role_description")

	log.Printf("DEBUG createServiceRoleHandler: serviceKey=%s, roleName=%s, displayName=%s, roleDescription=%s", serviceKey, roleName, roleDisplayName, roleDescription)

	if roleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Имя роли обязательно"})
		return
	}

	// Validate service exists
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		log.Printf("ERROR createServiceRoleHandler: Service not found: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Сервис не найден"})
		return
	}

	// Get permissions from form (checkboxes)
	var permissions []string
	c.Request.ParseForm()
	log.Printf("DEBUG createServiceRoleHandler: PostForm data: %+v", c.Request.PostForm)

	// Get permissions from checkbox array (modern form uses name="permissions")
	permissions = c.Request.Form["permissions"]
	log.Printf("DEBUG createServiceRoleHandler: Permissions from form array: %v", permissions)

	// Fallback: check for old format with perm_ prefix (if any legacy forms exist)
	if len(permissions) == 0 {
		for key, values := range c.Request.PostForm {
			if len(key) > 5 && key[:5] == "perm_" && len(values) > 0 && values[0] == "on" {
				permName := key[5:] // Remove "perm_" prefix
				permissions = append(permissions, permName)
				log.Printf("DEBUG createServiceRoleHandler: Added permission from perm_ format: %s", permName)
			}
		}
	}

	log.Printf("DEBUG createServiceRoleHandler: Final permissions list: %v", permissions)

	// Create the role
	log.Printf("DEBUG createServiceRoleHandler: Creating role with permissions: %v", permissions)
	_, err = models.CreateRole(service.Key, roleName, roleDisplayName, roleDescription, permissions)
	if err != nil {
		log.Printf("ERROR createServiceRoleHandler: Failed to create role: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать роль: " + err.Error()})
		return
	}

	log.Printf("SUCCESS createServiceRoleHandler: Role created successfully")
	// Redirect back to service page with roles tab active
	c.Redirect(http.StatusFound, "/services/"+service.Key)
}

func getServiceRoleHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Service role retrieval not implemented yet"})
}

func updateServiceRoleHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	roleName := c.Param("roleId") // actually role name now

	log.Printf("updateServiceRoleHandler: serviceKey=%s, roleName=%s", serviceKey, roleName)

	if roleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Имя роли обязательно"})
		return
	}

	if serviceKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ключ сервиса обязателен"})
		return
	}

	// Get form data
	newRoleName := c.PostForm("name")
	roleDisplayName := c.PostForm("display_name")
	roleDescription := c.PostForm("description")

	log.Printf("updateServiceRoleHandler: newRoleName=%s, displayName=%s, roleDescription=%s", newRoleName, roleDisplayName, roleDescription)

	if newRoleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Новое имя роли обязательно"})
		return
	}

	// Validate service exists
	_, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Сервис не найден"})
		return
	}

	// Find role by service and name
	role, err := models.GetRoleByServiceAndName(serviceKey, roleName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Роль не найдена"})
		return
	}

	// Get permissions from form (checkboxes)
	permissions := c.PostFormArray("permissions")

	// Update the role
	err = models.UpdateRole(role.ID, serviceKey, newRoleName, roleDisplayName, roleDescription, permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить роль: " + err.Error()})
		return
	}

	// Redirect back to service page with roles tab active
	c.Redirect(http.StatusFound, "/services/"+serviceKey)
}

func deleteServiceRoleHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	roleName := c.Param("roleId") // actually role name now

	if roleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Имя роли обязательно"})
		return
	}

	if serviceKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ключ сервиса обязателен"})
		return
	}

	// Validate service exists
	_, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Сервис не найден"})
		return
	}

	// Find role by service and name
	role, err := models.GetRoleByServiceAndName(serviceKey, roleName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Роль не найдена"})
		return
	}

	// Delete role
	err = models.DeleteRole(role.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при удалении роли: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/services/"+serviceKey)
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
		"users":   users,
		"service": service.Name,
	})
}

func addUserToServiceHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")

	// Check permission
	if !requireServicePermission(c, models.PermServiceUsersAdd) {
		c.JSON(http.StatusForbidden, gin.H{"error": "У вас нет прав на добавление пользователей в этот сервис"})
		return
	}

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
		RoleNames         []string `json:"roleNames"`
		ExternalRoleNames []string `json:"externalRoleNames"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("updateUserServiceRolesHandler: Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	log.Printf("updateUserServiceRolesHandler: serviceKey=%s, userId=%s, roleNames=%v, externalRoleNames=%v",
		serviceKey, userID, req.RoleNames, req.ExternalRoleNames)

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

	// Handle external roles (roles in auth-service that grant access to this service)
	if len(req.ExternalRoleNames) > 0 || len(currentAssignments) > 0 {
		// Get current external roles for this user in auth service
		currentExternalRoles := make(map[string]bool)
		if currentAssignments != nil {
			for _, assignment := range currentAssignments {
				if assignment.ServiceKey == "auth" && assignment.IsActive {
					// Check if this is an external role for our service
					externalRoles, _ := models.GetExternalRolesForService(service.Key)
					for _, extRole := range externalRoles {
						if extRole.Name == assignment.RoleName {
							currentExternalRoles[assignment.RoleName] = true
							break
						}
					}
				}
			}
		}

		// Build map of new external roles
		newExternalRoles := make(map[string]bool)
		for _, roleName := range req.ExternalRoleNames {
			newExternalRoles[roleName] = true
		}

		// Remove external roles that are no longer needed
		for roleName := range currentExternalRoles {
			if !newExternalRoles[roleName] {
				log.Printf("Removing external role '%s' from user %s in auth service", roleName, userObjectID.Hex())
				err := models.RemoveUserFromServiceRole(userObjectID, "auth", roleName)
				if err != nil {
					log.Printf("Failed to remove external role '%s': %v", roleName, err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove external role: " + roleName})
					return
				}
			}
		}

		// Add new external roles that user doesn't have yet
		for roleName := range newExternalRoles {
			if !currentExternalRoles[roleName] {
				log.Printf("Adding external role '%s' to user %s in auth service", roleName, userObjectID.Hex())
				err := models.AssignUserToServiceRole(userObjectID, "auth", roleName, currentUser.ID)
				if err != nil {
					log.Printf("Failed to assign external role '%s': %v", roleName, err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign external role: " + roleName})
					return
				}
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
		"exists":           true,
		"hasServiceAccess": hasServiceAccess,
		"user": gin.H{
			"id":         targetUser.ID.Hex(),
			"username":   targetUser.Username,
			"email":      targetUser.Email,
			"fullName":   targetUser.GetFullName(),
			"shortName":  targetUser.GetShortName(),
			"avatarPath": targetUser.AvatarPath,
		},
		"serviceRoles": serviceRoles,
	})
}

// syncServicePermissionsHandler syncs permissions from external service
func syncServicePermissionsHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")

	// Validate service exists
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		return
	}

	// Get service URL from environment or config
	// For now, assume services are reachable via docker network
	serviceURL := getServiceURL(serviceKey)
	if serviceURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service URL not configured"})
		return
	}

	// Fetch permissions from service
	permissions, err := fetchServicePermissions(serviceURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to fetch permissions from service: " + err.Error(),
		})
		return
	}

	// Update service permissions
	err = models.UpdateServicePermissions(service.Key, permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update service permissions: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":            "Permissions synced successfully",
		"service_key":        service.Key,
		"synced_permissions": len(permissions),
		"permissions":        permissions,
	})
}

// getServiceURL returns the URL for a service based on service key
func getServiceURL(serviceKey string) string {
	// Special case for auth-service: use localhost since we're calling ourselves
	if serviceKey == "auth" {
		return "http://localhost:80"
	}

	// First, try to get URL from Service Discovery (highest priority)
	instances, err := models.GetServiceInstancesByKey(serviceKey)
	if err == nil && len(instances) > 0 {
		// Return the URL of the first healthy instance
		for _, instance := range instances {
			if instance.Status == "healthy" || instance.Status == "active" {
				log.Printf("Using Service Discovery URL for '%s': %s", serviceKey, instance.InternalURL)
				return instance.InternalURL
			}
		}
		// If no healthy instances, use the first one anyway
		if instances[0].InternalURL != "" {
			log.Printf("Using Service Discovery URL (not healthy) for '%s': %s", serviceKey, instances[0].InternalURL)
			return instances[0].InternalURL
		}
	}

	// Fallback to hardcoded URLs
	serviceURLs := map[string]string{
		"referal":        "http://referal:80",
		"client-service": "http://client-service-service:80",
		// Add more services as needed
	}

	if url, exists := serviceURLs[serviceKey]; exists {
		log.Printf("Using hardcoded URL for '%s': %s", serviceKey, url)
		return url
	}

	// Default pattern: http://service-key:80
	defaultURL := fmt.Sprintf("http://%s:80", serviceKey)
	log.Printf("Using default URL pattern for '%s': %s", serviceKey, defaultURL)
	return defaultURL
}

// fetchServicePermissions fetches permissions from external service
func fetchServicePermissions(serviceURL string) ([]models.PermissionDef, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Make request to service permissions endpoint
	url := fmt.Sprintf("%s/api/sync/permissions", serviceURL)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("service returned error %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var response struct {
		Success     bool `json:"success"`
		Permissions []struct {
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
			Description string `json:"description"`
			Category    string `json:"category"`
		} `json:"permissions"`
		Error string `json:"error"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("service error: %s", response.Error)
	}

	// Convert to PermissionDef structs
	var permissions []models.PermissionDef
	for _, perm := range response.Permissions {
		permissions = append(permissions, models.PermissionDef{
			Name:        perm.Name,
			DisplayName: perm.DisplayName,
			Description: perm.Description,
		})
	}

	return permissions, nil
}

// getAuthServicePermissionsHandler returns auth-service's own permissions
// This endpoint allows auth-service to be synced like other services
func getAuthServicePermissionsHandler(c *gin.Context) {
	// Get auth service from database using raw BSON to preserve category field
	ctx := c.Request.Context()
	var result struct {
		AvailablePermissions []struct {
			Name        string `bson:"name" json:"name"`
			DisplayName string `bson:"displayName" json:"displayName"`
			Description string `bson:"description" json:"description"`
			Category    string `bson:"category" json:"category"`
		} `bson:"availablePermissions" json:"availablePermissions"`
	}

	collection := models.GetDatabase().Collection("services")
	err := collection.FindOne(ctx, map[string]interface{}{"key": "auth"}).Decode(&result)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Auth service not found in database",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"permissions": result.AvailablePermissions,
		"service_key": "auth",
		"note":        "Auth service permissions are managed internally",
	})
}

// ========== EXTERNAL ROLES HANDLERS ==========
// External roles are roles in auth-service that control access to external services

// createExternalRoleHandler creates a new external role for a service
func createExternalRoleHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	serviceKey := c.Param("serviceKey")

	// Auth-service cannot have external roles (it's a system service)
	if serviceKey == "auth" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Auth-service не может иметь внешние роли"})
		return
	}

	// Check permission - need auth.external_roles.create or system admin
	isSystemAdmin := c.GetBool("isSystemAdmin")
	if !isSystemAdmin && !models.HasAuthPermission(user.ID, "auth.external_roles.create") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Нет разрешения на создание внешних ролей"})
		return
	}

	var input struct {
		Name        string   `json:"name" binding:"required"`
		DisplayName string   `json:"display_name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		log.Printf("ERROR: createExternalRoleHandler - invalid input: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}

	log.Printf("INFO: createExternalRoleHandler - creating role '%s' for service '%s' with %d permissions", input.Name, serviceKey, len(input.Permissions))

	// Validate permissions - they should be auth.<serviceKey>.* format
	for _, perm := range input.Permissions {
		expectedPrefix := fmt.Sprintf("auth.%s.", serviceKey)
		if !strings.HasPrefix(perm, expectedPrefix) {
			log.Printf("ERROR: createExternalRoleHandler - invalid permission '%s', expected prefix '%s'", perm, expectedPrefix)
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid permission '%s'. External role permissions must start with '%s'", perm, expectedPrefix),
			})
			return
		}
	}

	// Create the role in auth-service (service_key = "auth")
	role := models.ServiceRole{
		ID:          primitive.NewObjectID(),
		ServiceKey:  "auth", // Role lives in auth-service
		Name:        input.Name,
		DisplayName: input.DisplayName,
		Description: input.Description,
		Permissions: input.Permissions,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := models.CreateServiceRole(&role); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			log.Printf("ERROR: createExternalRoleHandler - role '%s' already exists", input.Name)
			c.JSON(http.StatusConflict, gin.H{"error": "Role with this name already exists"})
			return
		}
		log.Printf("ERROR: createExternalRoleHandler - failed to create role: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create role"})
		return
	}

	log.Printf("SUCCESS: Created external role '%s' for service '%s' with %d permissions", input.Name, serviceKey, len(input.Permissions))
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "External role created successfully",
		"role":    role,
	})
}

// getExternalRoleHandler returns an external role by name
func getExternalRoleHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	serviceKey := c.Param("serviceKey")
	roleName := c.Param("roleName")

	// Check permission
	isSystemAdmin := c.GetBool("isSystemAdmin")
	if !isSystemAdmin && !models.HasAuthPermission(user.ID, "auth.external_roles.read") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Нет разрешения на просмотр внешних ролей"})
		return
	}

	// External roles are stored in auth-service with service_key="auth"
	role, err := models.GetServiceRoleByName("auth", roleName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		return
	}

	// Verify that this is an external role for the requested service
	expectedPrefix := fmt.Sprintf("auth.%s.", serviceKey)
	isExternalRole := false
	for _, perm := range role.Permissions {
		if strings.HasPrefix(perm, expectedPrefix) {
			isExternalRole = true
			break
		}
	}

	if !isExternalRole && len(role.Permissions) > 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found for this service"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"name":         role.Name,
		"display_name": role.DisplayName,
		"description":  role.Description,
		"permissions":  role.Permissions,
	})
}

// updateExternalRoleHandler updates an existing external role
func updateExternalRoleHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	serviceKey := c.Param("serviceKey")
	roleName := c.Param("roleName")

	// Check permission - need auth.external_roles.edit or system admin
	isSystemAdmin := c.GetBool("isSystemAdmin")
	if !isSystemAdmin && !models.HasAuthPermission(user.ID, "auth.external_roles.edit") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Нет разрешения на редактирование внешних ролей"})
		return
	}

	var input struct {
		Name        string   `json:"name"`
		DisplayName string   `json:"display_name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}

	// Get existing role
	existingRole, err := models.GetServiceRoleByName("auth", roleName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		return
	}

	// Validate permissions
	for _, perm := range input.Permissions {
		expectedPrefix := fmt.Sprintf("auth.%s.", serviceKey)
		if !strings.HasPrefix(perm, expectedPrefix) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Invalid permission '%s'. External role permissions must start with '%s'", perm, expectedPrefix),
			})
			return
		}
	}

	// Update fields
	if input.Name != "" {
		existingRole.Name = input.Name
	}
	existingRole.DisplayName = input.DisplayName
	existingRole.Description = input.Description
	existingRole.Permissions = input.Permissions
	existingRole.UpdatedAt = time.Now()

	if err := models.UpdateServiceRole(existingRole); err != nil {
		log.Printf("Error updating external role: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role"})
		return
	}

	log.Printf("Updated external role '%s' for service '%s'", roleName, serviceKey)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "External role updated successfully",
		"role":    existingRole,
	})
}

// deleteExternalRoleHandler deletes an external role
func deleteExternalRoleHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	roleName := c.Param("roleName")

	// Check permission - need auth.external_roles.delete or system admin
	isSystemAdmin := c.GetBool("isSystemAdmin")
	if !isSystemAdmin && !models.HasAuthPermission(user.ID, "auth.external_roles.delete") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Нет разрешения на удаление внешних ролей"})
		return
	}

	// Get existing role first
	existingRole, err := models.GetServiceRoleByName("auth", roleName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		return
	}

	// Delete the role
	if err := models.DeleteServiceRole(existingRole.ID); err != nil {
		log.Printf("Error deleting external role: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete role"})
		return
	}

	// Also remove role assignments from users
	if err := models.RemoveRoleFromAllUsers("auth", roleName); err != nil {
		log.Printf("Warning: Failed to remove role assignments: %v", err)
	}

	log.Printf("Deleted external role '%s'", roleName)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "External role deleted successfully",
	})
}

// ========== AUTH ROLES API HANDLERS ==========

// getAuthRoleByNameHandler returns a role from auth-service by name
func getAuthRoleByNameHandler(c *gin.Context) {
	roleName := c.Param("roleName")
	log.Printf("DEBUG: getAuthRoleByNameHandler called for roleName: '%s'", roleName)

	role, err := models.GetServiceRoleByName("auth", roleName)
	if err != nil {
		log.Printf("ERROR: getAuthRoleByNameHandler - role '%s' not found: %v", roleName, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		return
	}

	log.Printf("DEBUG: getAuthRoleByNameHandler - found role: %s with %d permissions", role.Name, len(role.Permissions))
	c.JSON(http.StatusOK, gin.H{
		"id":          role.ID.Hex(),
		"name":        role.Name,
		"description": role.Description,
		"permissions": role.Permissions,
		"created_at":  role.CreatedAt,
		"updated_at":  role.UpdatedAt,
	})
}

// getAuthRoleUsersHandler returns users who have a specific role in auth-service
func getAuthRoleUsersHandler(c *gin.Context) {
	roleName := c.Param("roleName")

	users, err := models.GetUsersByServiceRole("auth", roleName)
	if err != nil {
		log.Printf("Error getting users for role %s: %v", roleName, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get users"})
		return
	}

	// Convert to simpler format for API response
	var result []gin.H
	for _, user := range users {
		result = append(result, gin.H{
			"id":        user.ID.Hex(),
			"username":  user.Username,
			"email":     user.Email,
			"full_name": user.GetFullName(),
		})
	}

	c.JSON(http.StatusOK, result)
}
