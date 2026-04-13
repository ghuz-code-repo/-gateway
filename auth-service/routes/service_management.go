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

	// For non-admin users, show only services they manage (service-manager role ONLY)
	allServices, err := models.GetAllServicesWithOptions(false) // Don't include deleted
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "РќРµ СѓРґР°Р»РѕСЃСЊ РїРѕР»СѓС‡РёС‚СЊ СЃРµСЂРІРёСЃС‹",
		})
		return
	}

	// Filter services where user has service-manager role OR external role managing that service
	var managedServices []models.Service
	userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
	if err == nil {
		// Collect managed service keys from external auth roles
		externalManagedKeys := make(map[string]bool)
		for _, role := range userServiceRoles {
			if role.ServiceKey == "auth" && role.IsActive {
				// If assignment has managed_service, use it directly
				if role.ManagedService != "" {
					externalManagedKeys[role.ManagedService] = true
					continue
				}
				// Fallback for old assignments without managed_service:
				// look up role definitions to find managed_service
				externalRoles, err := models.GetAllExternalRolesByName(role.RoleName)
				if err == nil {
					for _, sr := range externalRoles {
						if sr.ManagedService != "" {
							externalManagedKeys[sr.ManagedService] = true
						}
					}
				}
			}
		}

		for _, service := range allServices {
			// Check direct service-manager role
			for _, role := range userServiceRoles {
				if role.ServiceKey == service.Key &&
					role.RoleName == "service-manager" &&
					role.IsActive {
					managedServices = append(managedServices, service)
					goto nextService
				}
			}
			// Check external role managing this service
			if externalManagedKeys[service.Key] {
				managedServices = append(managedServices, service)
			}
		nextService:
		}
	}

	c.HTML(http.StatusOK, "admin_services.html", gin.H{
		"title":            "РЈРїСЂР°РІР»РµРЅРёРµ СЃРµСЂРІРёСЃР°РјРё",
		"services":         managedServices,
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
			"error": "РќРµ СѓРґР°Р»РѕСЃСЊ РїРѕР»СѓС‡РёС‚СЊ СЃРµСЂРІРёСЃС‹",
		})
		return
	}

	c.HTML(http.StatusOK, "admin_services.html", gin.H{
		"title":            "РЈРїСЂР°РІР»РµРЅРёРµ СЃРµСЂРІРёСЃР°РјРё",
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
		"title":      "РЎРѕР·РґР°С‚СЊ СЃРµСЂРІРёСЃ",
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
			"title":      "РЎРѕР·РґР°С‚СЊ СЃРµСЂРІРёСЃ",
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
			"title":      "РЎРѕР·РґР°С‚СЊ СЃРµСЂРІРёСЃ",
			"error":      "РљР»СЋС‡ Рё РЅР°Р·РІР°РЅРёРµ СЃРµСЂРІРёСЃР° РѕР±СЏР·Р°С‚РµР»СЊРЅС‹",
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
			"error": "РќРµ СѓРґР°Р»РѕСЃСЊ СЃРѕР·РґР°С‚СЊ СЃРµСЂРІРёСЃ: " + err.Error(),
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
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "РЎРµСЂРІРёСЃ РЅРµ РЅР°Р№РґРµРЅ"})
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
			"error": "РЈ РІР°СЃ РЅРµС‚ РїСЂР°РІ РґР»СЏ РґРѕСЃС‚СѓРїР° Рє СЌС‚РѕРјСѓ СЃРµСЂРІРёСЃСѓ.",
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
	debugLog("DEBUG: Found %d internal roles for service %s", len(serviceRoles), service.Key)
	if len(serviceRoles) > 0 {
		debugLog("DEBUG: First role: %+v", serviceRoles[0])
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
	debugLog("DEBUG: Found %d external roles for service %s", len(externalRoles), service.Key)

	// Get available external permissions for this service (permissions with auth.<serviceKey>.* pattern)
	externalPermissions, err := models.GetExternalPermissionsForService(service.Key)
	if err != nil {
		log.Printf("Warning: Failed to get external permissions for service %s: %v", service.Key, err)
		externalPermissions = []models.ExternalPermissionCategory{}
	}
	debugLog("DEBUG: Found %d external permission categories for service %s", len(externalPermissions), service.Key)

	// Determine manage mode - true if user is service manager but not system admin
	manageMode := !isSystemAdmin && isServiceManager

	// Check permissions for this specific service (external permissions like auth.referal.*)
	// These permissions control what user can do when accessing service settings via external role
	servicePermPrefix := fmt.Sprintf("auth.%s.", service.Key)

	// Check external roles permissions for the current user
	// Can be granted via global auth.external_roles.* OR service-specific auth.<service>.roles.*
	canViewExternalRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, "auth.external_roles.view") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.view") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*")
	canCreateExternalRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, "auth.external_roles.create") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.create") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*")
	canEditExternalRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, "auth.external_roles.edit") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.edit") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*")
	canDeleteExternalRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, "auth.external_roles.delete") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.delete") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*")

	// Roles management permissions (for internal service roles)
	canViewRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.view") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.view") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.*")
	canCreateRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.create") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.create") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.*")
	canEditRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.edit") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.edit") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.*")
	canDeleteRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.delete") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.delete") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.*")

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
	canAssignRoles := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.assign_roles") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"roles.assign") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"service_roles.assign") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.*")
	canImportUsers := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.import") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.*")
	canExportUsers := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.export") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"users.*")

	// Logs permissions
	canViewLogs := isSystemAdmin || isServiceManager ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"logs.view") ||
		models.HasAuthPermission(user.ID, "auth.logs.view") ||
		models.HasAuthPermission(user.ID, "auth.logs.system.view")

	// Settings permissions
	canViewSettings := isSystemAdmin ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"settings.view") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"settings.*")
	canEditSettings := isSystemAdmin ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"settings.edit") ||
		models.HasAuthPermission(user.ID, servicePermPrefix+"settings.*")

	// Check if user can manage internal roles (has access to service management)
	// Now based on actual permissions
	canManageInternalRoles := canCreateRoles || canEditRoles || canDeleteRoles

	// Check for import success message
	importSuccess := c.Query("import_success")

	templateData := gin.H{
		"title":                  "Р”РµС‚Р°Р»Рё СЃРµСЂРІРёСЃР°",
		"service":                service,
		"serviceRoles":           serviceRoles,
		"serviceUsers":           serviceUsers,
		"externalRoles":          externalRoles,
		"externalPermissions":    externalPermissions,
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
	debugLog("DEBUG: Template data for service %s - serviceRoles count: %d, externalRoles count: %d", service.Key, len(serviceRoles), len(externalRoles))
	debugLog("DEBUG: Permissions check - isSystemAdmin: %v, isServiceManager: %v, hasExternalRoleAccess: %v", isSystemAdmin, isServiceManager, hasExternalRoleAccess)
	debugLog("DEBUG: Role permissions - canCreateRoles: %v, canEditRoles: %v, canDeleteRoles: %v, canViewRoles: %v, canAssignRoles: %v", canCreateRoles, canEditRoles, canDeleteRoles, canViewRoles, canAssignRoles)
	debugLog("DEBUG: User permissions - canViewUsers: %v, canAddUsers: %v, canEditUsers: %v, canDeleteUsers: %v", canViewUsers, canAddUsers, canEditUsers, canDeleteUsers)

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
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "РЎРµСЂРІРёСЃ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Check access - allow system admin, service admin, or service manager
	isSystemAdmin := c.GetBool("isSystemAdmin")
	isServiceManager := c.GetBool("isServiceManager")
	hasAccess := isSystemAdmin || isServiceManager || c.GetString("serviceKey") == service.Key

	if !hasAccess {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "РЈ РІР°СЃ РЅРµС‚ РїСЂР°РІ РґР»СЏ РёР·РјРµРЅРµРЅРёСЏ СЌС‚РѕРіРѕ СЃРµСЂРІРёСЃР°.",
		})
		return
	}

	// Get form data
	name := c.PostForm("name")
	description := c.PostForm("description")
	icon := c.PostForm("icon")
	newKey := c.PostForm("key")
	confirmKeyChange := c.PostForm("confirmKeyChange")

	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќР°Р·РІР°РЅРёРµ СЃРµСЂРІРёСЃР° РѕР±СЏР·Р°С‚РµР»СЊРЅРѕ"})
		return
	}

	if newKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РљР»СЋС‡ СЃРµСЂРІРёСЃР° РѕР±СЏР·Р°С‚РµР»РµРЅ"})
		return
	}

	// Check if key is being changed
	keyChanged := newKey != service.Key
	if keyChanged {
		// Require confirmation for key changes
		if confirmKeyChange != "true" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":                 "РР·РјРµРЅРµРЅРёРµ РєР»СЋС‡Р° СЃРµСЂРІРёСЃР° С‚СЂРµР±СѓРµС‚ РїРѕРґС‚РІРµСЂР¶РґРµРЅРёСЏ. Р­С‚Рѕ РјРѕР¶РµС‚ РїРѕРІР»РёСЏС‚СЊ РЅР° РёРЅС‚РµРіСЂР°С†РёРё.",
				"message":               "РР·РјРµРЅРµРЅРёРµ РєР»СЋС‡Р° СЃРµСЂРІРёСЃР° С‚СЂРµР±СѓРµС‚ РїРѕРґС‚РІРµСЂР¶РґРµРЅРёСЏ. Р­С‚Рѕ РјРѕР¶РµС‚ РїРѕРІР»РёСЏС‚СЊ РЅР° РёРЅС‚РµРіСЂР°С†РёРё.",
				"requires_confirmation": true,
				"key_change":            true,
			})
			return
		}

		// Check if new key already exists
		existingService, err := models.GetServiceByKey(newKey)
		if err == nil && existingService.ID != service.ID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "РЎРµСЂРІРёСЃ СЃ С‚Р°РєРёРј РєР»СЋС‡РѕРј СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓРµС‚"})
			return
		}
	}

	// Update service with new key and permissions
	err = models.UpdateService(service.ID, newKey, name, description, icon, service.AvailablePermissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё РѕР±РЅРѕРІР»РµРЅРёРё СЃРµСЂРІРёСЃР°: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/services/"+newKey)
}

// deleteServiceHandler performs soft delete of a service (system admin only)
// The service is marked as deleted but can be restored
func deleteServiceHandler(c *gin.Context) {
	// SECURITY: Only system admins can delete services
	if !c.GetBool("isSystemAdmin") {
		c.HTML(http.StatusForbidden, "error.html", gin.H{"error": "РЈРґР°Р»РµРЅРёРµ СЃРµСЂРІРёСЃР° РґРѕСЃС‚СѓРїРЅРѕ С‚РѕР»СЊРєРѕ СЃРёСЃС‚РµРјРЅС‹Рј Р°РґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂР°Рј"})
		return
	}

	serviceKey := c.Param("serviceKey")

	// Verify service exists
	_, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "РЎРµСЂРІРёСЃ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Perform soft delete
	err = models.SoftDeleteService(serviceKey)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "РќРµ СѓРґР°Р»РѕСЃСЊ СѓРґР°Р»РёС‚СЊ СЃРµСЂРІРёСЃ: " + err.Error(),
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

	// Only system admin can restore services
	isSystemAdmin := c.GetBool("isSystemAdmin")
	if !isSystemAdmin {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"error": "РўРѕР»СЊРєРѕ СЃРёСЃС‚РµРјРЅС‹Р№ Р°РґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂ РјРѕР¶РµС‚ РІРѕСЃСЃС‚Р°РЅР°РІР»РёРІР°С‚СЊ СЃРµСЂРІРёСЃС‹",
		})
		return
	}

	// Perform restore
	err := models.RestoreService(serviceKey)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "РќРµ СѓРґР°Р»РѕСЃСЊ РІРѕСЃСЃС‚Р°РЅРѕРІРёС‚СЊ СЃРµСЂРІРёСЃ: " + err.Error(),
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
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "РЎРµСЂРІРёСЃ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Perform hard delete
	err = models.HardDeleteService(serviceKey)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "РќРµ СѓРґР°Р»РѕСЃСЊ РѕРєРѕРЅС‡Р°С‚РµР»СЊРЅРѕ СѓРґР°Р»РёС‚СЊ СЃРµСЂРІРёСЃ: " + err.Error(),
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "РРјСЏ СЂР°Р·СЂРµС€РµРЅРёСЏ РѕР±СЏР·Р°С‚РµР»СЊРЅРѕ"})
		return
	}

	// Validate service exists
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "РЎРµСЂРІРёСЃ РЅРµ РЅР°Р№РґРµРЅ"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё РґРѕР±Р°РІР»РµРЅРёРё СЂР°Р·СЂРµС€РµРЅРёСЏ: " + err.Error()})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "РРјСЏ СЂР°Р·СЂРµС€РµРЅРёСЏ РѕР±СЏР·Р°С‚РµР»СЊРЅРѕ"})
		return
	}

	// Validate service exists
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "РЎРµСЂРІРёСЃ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Remove permission from service (soft delete)
	err = models.RemovePermissionFromService(service.Key, permissionName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё СѓРґР°Р»РµРЅРёРё СЂР°Р·СЂРµС€РµРЅРёСЏ: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/services/"+service.Key)
}

func createServiceRoleHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	roleName := c.PostForm("role_name")
	roleDescription := c.PostForm("role_description")

	debugLog("DEBUG createServiceRoleHandler: serviceKey=%s, roleName=%s, roleDescription=%s", serviceKey, roleName, roleDescription)

	if roleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РРјСЏ СЂРѕР»Рё РѕР±СЏР·Р°С‚РµР»СЊРЅРѕ"})
		return
	}

	// Validate service exists
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		log.Printf("ERROR createServiceRoleHandler: Service not found: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "РЎРµСЂРІРёСЃ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Get permissions from form (checkboxes)
	var permissions []string
	c.Request.ParseForm()
	debugLog("DEBUG createServiceRoleHandler: PostForm data: %+v", c.Request.PostForm)

	// Get permissions from checkbox array (modern form uses name="permissions")
	permissions = c.Request.Form["permissions"]
	debugLog("DEBUG createServiceRoleHandler: Permissions from form array: %v", permissions)

	// Fallback: check for old format with perm_ prefix (if any legacy forms exist)
	if len(permissions) == 0 {
		for key, values := range c.Request.PostForm {
			if len(key) > 5 && key[:5] == "perm_" && len(values) > 0 && values[0] == "on" {
				permName := key[5:] // Remove "perm_" prefix
				permissions = append(permissions, permName)
				debugLog("DEBUG createServiceRoleHandler: Added permission from perm_ format: %s", permName)
			}
		}
	}

	debugLog("DEBUG createServiceRoleHandler: Final permissions list: %v", permissions)

	// Create the role
	debugLog("DEBUG createServiceRoleHandler: Creating role with permissions: %v", permissions)
	_, err = models.CreateRole(service.Key, roleName, roleDescription, permissions)
	if err != nil {
		log.Printf("ERROR createServiceRoleHandler: Failed to create role: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РќРµ СѓРґР°Р»РѕСЃСЊ СЃРѕР·РґР°С‚СЊ СЂРѕР»СЊ: " + err.Error()})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "РРјСЏ СЂРѕР»Рё РѕР±СЏР·Р°С‚РµР»СЊРЅРѕ"})
		return
	}

	if serviceKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РљР»СЋС‡ СЃРµСЂРІРёСЃР° РѕР±СЏР·Р°С‚РµР»РµРЅ"})
		return
	}

	// Get form data
	newRoleName := c.PostForm("name")
	roleDescription := c.PostForm("description")

	log.Printf("updateServiceRoleHandler: newRoleName=%s, roleDescription=%s", newRoleName, roleDescription)

	if newRoleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРѕРІРѕРµ РёРјСЏ СЂРѕР»Рё РѕР±СЏР·Р°С‚РµР»СЊРЅРѕ"})
		return
	}

	// Validate service exists
	_, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "РЎРµСЂРІРёСЃ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Find role by service and name
	role, err := models.GetRoleByServiceAndName(serviceKey, roleName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Р РѕР»СЊ РЅРµ РЅР°Р№РґРµРЅР°"})
		return
	}

	// Get permissions from form (checkboxes)
	permissions := c.PostFormArray("permissions")

	// Update the role
	err = models.UpdateRole(role.ID, serviceKey, newRoleName, roleDescription, permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РќРµ СѓРґР°Р»РѕСЃСЊ РѕР±РЅРѕРІРёС‚СЊ СЂРѕР»СЊ: " + err.Error()})
		return
	}

	// Redirect back to service page with roles tab active
	c.Redirect(http.StatusFound, "/services/"+serviceKey)
}

func deleteServiceRoleHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	roleName := c.Param("roleId") // actually role name now

	if roleName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РРјСЏ СЂРѕР»Рё РѕР±СЏР·Р°С‚РµР»СЊРЅРѕ"})
		return
	}

	if serviceKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РљР»СЋС‡ СЃРµСЂРІРёСЃР° РѕР±СЏР·Р°С‚РµР»РµРЅ"})
		return
	}

	// Validate service exists
	_, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "РЎРµСЂРІРёСЃ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Find role by service and name
	role, err := models.GetRoleByServiceAndName(serviceKey, roleName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Р РѕР»СЊ РЅРµ РЅР°Р№РґРµРЅР°"})
		return
	}

	// Delete role
	err = models.DeleteRole(role.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё СѓРґР°Р»РµРЅРёРё СЂРѕР»Рё: " + err.Error()})
		return
	}

	c.Redirect(http.StatusFound, "/services/"+serviceKey)
}

func assignUserToServiceRoleHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "User role assignment not implemented yet"})
}

func getServiceUsersHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")

	// Validate service exists
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "РЎРµСЂРІРёСЃ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Get users with roles in this service
	users, err := models.GetUsersWithServiceRoles(service.Key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїРѕР»СѓС‡РµРЅРёСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users":   users,
		"service": service.Name,
	})
}

func addUserToServiceHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	currentUser := c.MustGet("user").(*models.User)

	// Check permission: system admin, service manager, auth external permission, or service-level permission
	isSystemAdmin := c.GetBool("isSystemAdmin")
	isServiceManager := c.GetBool("isServiceManager")
	servicePermPrefix := fmt.Sprintf("auth.%s.", serviceKey)
	hasAuthPerm := models.HasAuthPermission(currentUser.ID, servicePermPrefix+"users.add") ||
		models.HasAuthPermission(currentUser.ID, servicePermPrefix+"users.*")
	hasServicePerm := models.HasServicePermission(currentUser.ID, serviceKey, models.PermServiceUsersAdd)

	if !isSystemAdmin && !isServiceManager && !hasAuthPerm && !hasServicePerm {
		c.JSON(http.StatusForbidden, gin.H{"error": "РЈ РІР°СЃ РЅРµС‚ РїСЂР°РІ РЅР° РґРѕР±Р°РІР»РµРЅРёРµ РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№ РІ СЌС‚РѕС‚ СЃРµСЂРІРёСЃ"})
		return
	}

	var req struct {
		Identifier        string   `json:"identifier"`
		LastName          string   `json:"last_name"`
		FirstName         string   `json:"first_name"`
		FullName          string   `json:"full_name"` // legacy, kept for backward compatibility
		ServiceKey        string   `json:"service_key"`
		Roles             []string `json:"roles"`
		ExternalRoleNames []string `json:"externalRoleNames"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if req.Identifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Identifier is required"})
		return
	}

	if len(req.Roles) == 0 && len(req.ExternalRoleNames) == 0 {
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
	targetUser, err := models.GetUserByEmailOrUsername(req.Identifier)
	if err != nil || targetUser == nil {
		// If user not found and we have name fields, create new user
		hasName := req.LastName != "" || req.FirstName != "" || req.FullName != ""
		if hasName {
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

			var userID primitive.ObjectID
			if req.LastName != "" || req.FirstName != "" {
				// New path: create with separate name fields
				userID, err = models.CreateUserWithNames(username, email, "temporary123", req.LastName, req.FirstName, "", "", []string{})
			} else {
				// Legacy path: full_name only
				userID, err = models.CreateUser(username, email, "temporary123", req.FullName, []string{})
			}
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create new user: " + err.Error()})
				return
			}

			// Get the created user
			targetUser, err = models.GetUserByObjectID(userID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve created user"})
				return
			}
		} else {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
	}

	// Assign internal service roles
	for _, roleName := range req.Roles {
		err := models.AssignUserToServiceRole(targetUser.ID, service.Key, roleName, currentUser.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign role: " + roleName})
			return
		}
	}

	// Assign external roles (auth-service roles that grant access to this service)
	for _, extRoleName := range req.ExternalRoleNames {
		err := models.AssignUserToServiceRole(targetUser.ID, "auth", extRoleName, currentUser.ID, serviceKey)
		if err != nil {
			log.Printf("Warning: Failed to assign external role '%s' to user %s: %v", extRoleName, targetUser.ID.Hex(), err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign external role: " + extRoleName})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User added to service successfully",
		"user": gin.H{
			"id":       targetUser.ID.Hex(),
			"username": targetUser.Username,
			"email":    targetUser.Email,
			"fullName": targetUser.FullName,
		},
		"assignedRoles":         req.Roles,
		"assignedExternalRoles": req.ExternalRoleNames,
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
	// SECURITY: Only process external roles if the request explicitly includes them
	// This prevents lower-privilege admins from accidentally wiping external roles
	// when they can't even see the external roles checkboxes in the UI
	if req.ExternalRoleNames != nil {
		// Get external roles defined for this service (lookup once, not in loop)
		externalRolesForService, _ := models.GetExternalRolesForService(service.Key)
		externalRoleNamesSet := make(map[string]bool)
		for _, extRole := range externalRolesForService {
			externalRoleNamesSet[extRole.Name] = true
		}

		// Get current external roles for this user in auth service
		// IMPORTANT: must filter by ManagedService == serviceKey to avoid
		// seeing roles assigned for other services as "current" for this service
		currentExternalRoles := make(map[string]bool)
		if currentAssignments != nil {
			for _, assignment := range currentAssignments {
				if assignment.ServiceKey == "auth" && assignment.IsActive && assignment.ManagedService == serviceKey {
					if externalRoleNamesSet[assignment.RoleName] {
						currentExternalRoles[assignment.RoleName] = true
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
				err := models.RemoveUserFromServiceRole(userObjectID, "auth", roleName, serviceKey)
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
				err := models.AssignUserToServiceRole(userObjectID, "auth", roleName, currentUser.ID, serviceKey)
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
	// Prevent browser from caching this response — data can change at any time
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
	c.Header("Pragma", "no-cache")

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

	// РћРїСЂРµРґРµР»СЏРµРј, РµСЃС‚СЊ Р»Рё Сѓ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ РґРѕСЃС‚СѓРї Рє СЃРµСЂРІРёСЃСѓ
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

	// Check permission - need system admin, service manager, or specific permission
	isSystemAdmin := c.GetBool("isSystemAdmin")
	isServiceManager := c.GetBool("isServiceManager")
	servicePermPrefix := fmt.Sprintf("auth.%s.", serviceKey)
	if !isSystemAdmin && !isServiceManager &&
		!models.HasAuthPermission(user.ID, "auth.external_roles.create") &&
		!models.HasAuthPermission(user.ID, servicePermPrefix+"roles.create") &&
		!models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*") {
		c.JSON(http.StatusForbidden, gin.H{"error": "РќРµС‚ СЂР°Р·СЂРµС€РµРЅРёСЏ РЅР° СЃРѕР·РґР°РЅРёРµ РІРЅРµС€РЅРёС… СЂРѕР»РµР№"})
		return
	}

	var input struct {
		Name        string   `json:"name" binding:"required"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		log.Printf("ERROR: createExternalRoleHandler - invalid input: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}

	log.Printf("INFO: createExternalRoleHandler - creating role '%s' for service '%s' with %d permissions", input.Name, serviceKey, len(input.Permissions))

	// Validate that external role name doesn't conflict with existing internal auth-service roles
	// This prevents ambiguity when GetRoleByServiceAndName("auth", name) is called
	existingRole, err := models.GetRoleByServiceAndName("auth", input.Name)
	if err == nil && existingRole != nil && existingRole.IsInternal() {
		log.Printf("ERROR: createExternalRoleHandler - name '%s' conflicts with internal auth-service role", input.Name)
		c.JSON(http.StatusConflict, gin.H{
			"error": fmt.Sprintf("РРјСЏ '%s' СѓР¶Рµ РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ РІРЅСѓС‚СЂРµРЅРЅРµР№ СЂРѕР»СЊСЋ auth-СЃРµСЂРІРёСЃР°. Р’С‹Р±РµСЂРёС‚Рµ РґСЂСѓРіРѕРµ РёРјСЏ.", input.Name),
		})
		return
	}

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
		ID:             primitive.NewObjectID(),
		ServiceKey:     "auth", // Role lives in auth-service
		Name:           input.Name,
		Description:    input.Description,
		Permissions:    input.Permissions,
		RoleType:       models.RoleTypeExternal,
		ManagedService: serviceKey,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
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

// updateExternalRoleHandler updates an existing external role
func updateExternalRoleHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	serviceKey := c.Param("serviceKey")
	roleName := c.Param("roleName")

	debugLog("DEBUG updateExternalRoleHandler: serviceKey=%s, roleName=%s, user=%s", serviceKey, roleName, user.Username)

	// Check permission - need system admin, service manager, or specific permission
	isSystemAdmin := c.GetBool("isSystemAdmin")
	isServiceManager := c.GetBool("isServiceManager")
	servicePermPrefix := fmt.Sprintf("auth.%s.", serviceKey)
	if !isSystemAdmin && !isServiceManager &&
		!models.HasAuthPermission(user.ID, "auth.external_roles.edit") &&
		!models.HasAuthPermission(user.ID, servicePermPrefix+"roles.edit") &&
		!models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*") {
		c.JSON(http.StatusForbidden, gin.H{"error": "РќРµС‚ СЂР°Р·СЂРµС€РµРЅРёСЏ РЅР° СЂРµРґР°РєС‚РёСЂРѕРІР°РЅРёРµ РІРЅРµС€РЅРёС… СЂРѕР»РµР№"})
		return
	}

	var input struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		log.Printf("ERROR updateExternalRoleHandler: JSON parse error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}

	debugLog("DEBUG updateExternalRoleHandler: input name=%s, desc=%s, perms=%d", input.Name, input.Description, len(input.Permissions))

	// Get existing role by name + managed service to avoid collisions
	existingRole, err := models.GetExternalRoleByNameAndService(roleName, serviceKey)
	if err != nil {
		log.Printf("ERROR updateExternalRoleHandler: role '%s' not found for managed service '%s': %v", roleName, serviceKey, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		return
	}

	debugLog("DEBUG updateExternalRoleHandler: existing role found, ID=%s, currentName=%s, serviceKey=%s",
		existingRole.ID.Hex(), existingRole.Name, existingRole.ServiceKey)

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

	// Check for name conflict if name is being changed
	if input.Name != "" && input.Name != existingRole.Name {
		// Check conflict with internal auth roles
		internalConflict, err := models.GetRoleByServiceAndName("auth", input.Name)
		if err == nil && internalConflict != nil && internalConflict.IsInternal() {
			log.Printf("ERROR updateExternalRoleHandler: name conflict with internal role '%s'", input.Name)
			c.JSON(http.StatusConflict, gin.H{
				"error": fmt.Sprintf("Р РѕР»СЊ СЃ РёРјРµРЅРµРј '%s' СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓРµС‚", input.Name),
			})
			return
		}
		// Check conflict with external role for the same managed service
		conflicting, err := models.GetExternalRoleByNameAndService(input.Name, serviceKey)
		if err == nil && conflicting != nil {
			log.Printf("ERROR updateExternalRoleHandler: name conflict - role '%s' already exists for service '%s' (ID=%s)",
				input.Name, serviceKey, conflicting.ID.Hex())
			c.JSON(http.StatusConflict, gin.H{
				"error": fmt.Sprintf("Р РѕР»СЊ СЃ РёРјРµРЅРµРј '%s' СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓРµС‚", input.Name),
			})
			return
		}
	}

	// Update fields
	if input.Name != "" {
		existingRole.Name = input.Name
	}
	existingRole.Description = input.Description
	existingRole.Permissions = input.Permissions
	existingRole.RoleType = models.RoleTypeExternal
	existingRole.ManagedService = serviceKey
	existingRole.UpdatedAt = time.Now()

	if err := models.UpdateServiceRole(existingRole); err != nil {
		log.Printf("ERROR updateExternalRoleHandler: UpdateServiceRole failed for role '%s' (ID=%s): %v",
			roleName, existingRole.ID.Hex(), err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role: " + err.Error()})
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
	serviceKey := c.Param("serviceKey")
	roleName := c.Param("roleName")

	// Check permission - need system admin, service manager, or specific permission
	isSystemAdmin := c.GetBool("isSystemAdmin")
	isServiceManager := c.GetBool("isServiceManager")
	servicePermPrefix := fmt.Sprintf("auth.%s.", serviceKey)
	if !isSystemAdmin && !isServiceManager &&
		!models.HasAuthPermission(user.ID, "auth.external_roles.delete") &&
		!models.HasAuthPermission(user.ID, servicePermPrefix+"roles.delete") &&
		!models.HasAuthPermission(user.ID, servicePermPrefix+"roles.*") {
		c.JSON(http.StatusForbidden, gin.H{"error": "РќРµС‚ СЂР°Р·СЂРµС€РµРЅРёСЏ РЅР° СѓРґР°Р»РµРЅРёРµ РІРЅРµС€РЅРёС… СЂРѕР»РµР№"})
		return
	}

	// Get existing role by name + managed service to avoid collisions
	existingRole, err := models.GetExternalRoleByNameAndService(roleName, serviceKey)
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

	// Note: DeleteServiceRole already cascade-deletes user role assignments,
	// so no need to call RemoveRoleFromAllUsers separately.

	log.Printf("Deleted external role '%s'", roleName)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "External role deleted successfully",
	})
}

// ========== AUTH ROLES API HANDLERS ==========

// getExternalRoleHandler returns external role data for the UI (authenticated, no API key needed)
func getExternalRoleHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	roleName := c.Param("roleName")

	debugLog("DEBUG: getExternalRoleHandler called for service=%s, role=%s", serviceKey, roleName)

	// Find the external role by name + managed service
	role, err := models.GetExternalRoleByNameAndService(roleName, serviceKey)
	if err != nil {
		log.Printf("ERROR: getExternalRoleHandler - role '%s' not found for service '%s': %v", roleName, serviceKey, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Р’РЅРµС€РЅСЏСЏ СЂРѕР»СЊ РЅРµ РЅР°Р№РґРµРЅР° РґР»СЏ РґР°РЅРЅРѕРіРѕ СЃРµСЂРІРёСЃР°"})
		return
	}

	// Get users with this role
	users, err := models.GetUsersByServiceRole("auth", roleName)
	userCount := 0
	if err == nil {
		userCount = len(users)
	}

	c.JSON(http.StatusOK, gin.H{
		"id":              role.ID.Hex(),
		"name":            role.Name,
		"description":     role.Description,
		"permissions":     role.Permissions,
		"role_type":       role.RoleType,
		"managed_service": role.ManagedService,
		"user_count":      userCount,
		"created_at":      role.CreatedAt,
		"updated_at":      role.UpdatedAt,
	})
}

// getExternalRoleUsersHandler returns users who have a specific external role (UI-accessible, no API key needed)
func getExternalRoleUsersHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	roleName := c.Param("roleName")

	debugLog("DEBUG: getExternalRoleUsersHandler called for service=%s, role=%s", serviceKey, roleName)

	// Verify the role exists and is an external role for this service
	_, err := models.GetExternalRoleByNameAndService(roleName, serviceKey)
	if err != nil {
		log.Printf("ERROR: getExternalRoleUsersHandler - role '%s' not found for service '%s': %v", roleName, serviceKey, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Р’РЅРµС€РЅСЏСЏ СЂРѕР»СЊ РЅРµ РЅР°Р№РґРµРЅР° РґР»СЏ РґР°РЅРЅРѕРіРѕ СЃРµСЂРІРёСЃР°"})
		return
	}

	users, err := models.GetUsersByServiceRole("auth", roleName)
	if err != nil {
		log.Printf("ERROR: getExternalRoleUsersHandler - error getting users for role %s: %v", roleName, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° Р·Р°РіСЂСѓР·РєРё РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№"})
		return
	}

	var result []gin.H
	for _, user := range users {
		result = append(result, gin.H{
			"id":        user.ID.Hex(),
			"username":  user.Username,
			"email":     user.Email,
			"full_name": user.GetFullName(),
		})
	}

	if result == nil {
		result = []gin.H{}
	}

	c.JSON(http.StatusOK, result)
}

// getAuthRoleByNameHandler returns a role from auth-service by name
func getAuthRoleByNameHandler(c *gin.Context) {
	roleName := c.Param("roleName")
	debugLog("DEBUG: getAuthRoleByNameHandler called for roleName: '%s'", roleName)

	role, err := models.GetServiceRoleByName("auth", roleName)
	if err != nil {
		log.Printf("ERROR: getAuthRoleByNameHandler - role '%s' not found: %v", roleName, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		return
	}

	debugLog("DEBUG: getAuthRoleByNameHandler - found role: %s with %d permissions", role.Name, len(role.Permissions))
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
