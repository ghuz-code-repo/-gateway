package routes

import (
	"auth-service/models"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// PolicyAPIRoutes sets up policy management API routes
func PolicyAPIRoutes(router *gin.Engine) {
	api := router.Group("/api/v1")
	{
		// Policy evaluation endpoint
		api.POST("/evaluate", evaluatePolicy)
		
		// Service roles manag		c.HTML(http.StatusOK, "admin_policies.html", gin.H{ment
		api.GET("/services/:service/roles", getServiceRoles)
		api.POST("/services/:service/roles", createServiceRole)
		api.PUT("/services/:service/roles/:role_id", updateServiceRole)
		api.DELETE("/services/:service/roles/:role_id", deleteServiceRole)
		
		// Service permissions management
		api.GET("/services/:service/permissions", getServicePermissions)
		api.POST("/services/:service/permissions", createServicePermission)
		
		// Cache management
		api.GET("/cache/stats", getCacheStats)
		api.POST("/cache/invalidate/:service", invalidateServiceCache)
		api.DELETE("/cache/clear", clearCache)
		
		// Health check for policy service
		api.GET("/health", healthCheck)
	}
}

// evaluatePolicy handles policy evaluation requests
func evaluatePolicy(c *gin.Context) {
	var req models.PolicyEvaluationRequest
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Validate required fields
	if req.Service == "" || len(req.UserRoles) == 0 || req.Resource == "" || req.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required fields: service, user_roles, resource, action",
		})
		return
	}

	// Evaluate policy
	response, err := models.EvaluatePolicy(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Policy evaluation failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// getServiceRoles retrieves all roles for a service
func getServiceRoles(c *gin.Context) {
	service := c.Param("service")
	
	if service == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service parameter is required"})
		return
	}

	roles, err := models.GetServiceRoles(service)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve service roles",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"service": service,
		"roles": roles,
		"count": len(roles),
	})
}

// createServiceRole creates a new role for a service
func createServiceRole(c *gin.Context) {
	service := c.Param("service")
	
	var role models.ServiceRole
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid role data",
			"details": err.Error(),
		})
		return
	}

	// Set service from URL parameter
	role.Service = service
	
	// Validate role data
	if role.Name == "" || role.DisplayName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Role name and display_name are required",
		})
		return
	}

	// Get user ID from context (set by authentication middleware)
	userID, exists := c.Get("user_id")
	if exists {
		role.CreatedBy = userID.(string)
	} else {
		role.CreatedBy = "api_user"
	}

	err := models.CreateServiceRole(&role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create service role",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Service role created successfully",
		"role": role,
	})
}

// updateServiceRole updates an existing service role
func updateServiceRole(c *gin.Context) {
	service := c.Param("service")
	roleID := c.Param("role_id")
	
	var role models.ServiceRole
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid role data",
			"details": err.Error(),
		})
		return
	}

	// Set service from URL parameter
	role.Service = service

	err := models.UpdateServiceRole(roleID, &role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update service role",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Service role updated successfully",
		"role": role,
	})
}

// deleteServiceRole deletes a service role
func deleteServiceRole(c *gin.Context) {
	roleID := c.Param("role_id")
	
	err := models.DeleteServiceRole(roleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete service role",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Service role deleted successfully",
	})
}

// getServicePermissions retrieves all permissions for a service
func getServicePermissions(c *gin.Context) {
	service := c.Param("service")
	
	if service == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service parameter is required"})
		return
	}

	permissions, err := models.GetServicePermissions(service)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve service permissions",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"service": service,
		"permissions": permissions,
		"count": len(permissions),
	})
}

// createServicePermission creates a new permission for a service
func createServicePermission(c *gin.Context) {
	service := c.Param("service")
	
	var permission models.ServicePermission
	if err := c.ShouldBindJSON(&permission); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid permission data",
			"details": err.Error(),
		})
		return
	}

	// Set service from URL parameter
	permission.Service = service
	
	// Validate permission data
	if permission.Resource == "" || permission.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Permission resource and action are required",
		})
		return
	}

	err := models.CreateServicePermission(&permission)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create service permission",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Service permission created successfully",
		"permission": permission,
	})
}

// getCacheStats returns cache statistics
func getCacheStats(c *gin.Context) {
	stats := models.GetCacheStats()
	c.JSON(http.StatusOK, gin.H{
		"cache_stats": stats,
		"timestamp": fmt.Sprintf("%d", models.GetCurrentTimestamp()),
	})
}

// invalidateServiceCache invalidates cache for a specific service
func invalidateServiceCache(c *gin.Context) {
	service := c.Param("service")
	
	if service == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service parameter is required"})
		return
	}

	models.InvalidateServiceCache(service)
	
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Cache invalidated for service: %s", service),
		"service": service,
	})
}

// clearCache clears all cache entries
func clearCache(c *gin.Context) {
	models.ClearAllCache()
	
	c.JSON(http.StatusOK, gin.H{
		"message": "All cache entries cleared",
	})
}

// healthCheck returns health status of the policy service
func healthCheck(c *gin.Context) {
	// Check database connection
	dbStatus := "connected"
	if !models.IsDBConnected() {
		dbStatus = "disconnected"
	}
	
	// Get cache stats
	cacheStats := models.GetCacheStats()
	
	// Determine overall health
	healthy := dbStatus == "connected"
	status := "healthy"
	if !healthy {
		status = "unhealthy"
	}
	
	response := gin.H{
		"status": status,
		"timestamp": fmt.Sprintf("%d", models.GetCurrentTimestamp()),
		"database": dbStatus,
		"cache": cacheStats,
		"services": []string{"referal", "gateway"},
	}
	
	if healthy {
		c.JSON(http.StatusOK, response)
	} else {
		c.JSON(http.StatusServiceUnavailable, response)
	}
}

// Admin UI routes for policy management
func PolicyAdminRoutes(admin *gin.RouterGroup) {
	log.Println("FUNCTION START: PolicyAdminRoutes executing...")
	log.Println("Registering policy admin routes...")
	
	// Policy management dashboard
	admin.GET("/policies", policiesAdminPage)
	admin.GET("/policies/:service", serviceAdminPage)
	
	// ТЕСТ ПРОСТОГО МАРШРУТА
	admin.GET("/test-cache", func(c *gin.Context) {
		c.String(http.StatusOK, "TEST OK")
	})
	
	// Service role management pages
	admin.GET("/policies/:service/roles", rolesAdminPage)
	admin.POST("/policies/:service/roles", createRoleAdminPage)
	
	// Service permission management pages
	admin.GET("/policies/:service/permissions", permissionsAdminPage)
	admin.POST("/policies/:service/permissions", createPermissionAdminPage)
	
	// Cache management page (both generic and service-specific)
	admin.GET("/cache", cacheAdminPage)
	log.Println("DEBUG: About to register service cache route...")
	admin.GET("/policies/:service/cache", serviceCacheAdminPage)
	log.Println("DEBUG: Service cache route registered.")
	
	log.Println("Policy admin routes registration complete.")
}

// policiesAdminPage shows the main policies management page
func policiesAdminPage(c *gin.Context) {
	services := []string{"referal", "gateway"}
	
	c.HTML(http.StatusOK, "admin_policies.html", gin.H{
		"title": "Policy Management",
		"services": services,
	})
}

// serviceAdminPage shows policy management for a specific service
func serviceAdminPage(c *gin.Context) {
	service := c.Param("service")
	
	roles, err := models.GetServiceRoles(service)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to load service roles: " + err.Error(),
		})
		return
	}
	
	permissions, err := models.GetServicePermissions(service)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Failed to load service permissions: " + err.Error(),
		})
		return
	}
	
	c.HTML(http.StatusOK, "admin_service_policies.html", gin.H{
		"title": fmt.Sprintf("Policy Management - %s", service),
		"service": service,
		"roles": roles,
		"permissions": permissions,
	})
}

// rolesAdminPage shows role management for a service
func rolesAdminPage(c *gin.Context) {
	service := c.Param("service")
	
	roles, err := models.GetServiceRoles(service)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to load roles",
			"details": err.Error(),
		})
		return
	}
	
	c.HTML(http.StatusOK, "admin/roles.html", gin.H{
		"title": fmt.Sprintf("Roles - %s", service),
		"service": service,
		"roles": roles,
	})
}

// createRoleAdminPage handles role creation from admin interface
func createRoleAdminPage(c *gin.Context) {
	service := c.Param("service")
	
	var role models.ServiceRole
	if err := c.ShouldBind(&role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid form data",
			"details": err.Error(),
		})
		return
	}
	
	role.Service = service
	role.CreatedBy = "admin"
	
	err := models.CreateServiceRole(&role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create role",
			"details": err.Error(),
		})
		return
	}
	
	c.Redirect(http.StatusSeeOther, "/admin/policies/"+service+"/roles")
}

// permissionsAdminPage shows permission management for a service
func permissionsAdminPage(c *gin.Context) {
	service := c.Param("service")
	
	permissions, err := models.GetServicePermissions(service)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to load permissions",
			"details": err.Error(),
		})
		return
	}
	
	c.HTML(http.StatusOK, "admin/permissions.html", gin.H{
		"title": fmt.Sprintf("Permissions - %s", service),
		"service": service,
		"permissions": permissions,
	})
}

// createPermissionAdminPage handles permission creation from admin interface
func createPermissionAdminPage(c *gin.Context) {
	service := c.Param("service")
	
	var permission models.ServicePermission
	if err := c.ShouldBind(&permission); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid form data",
			"details": err.Error(),
		})
		return
	}
	
	permission.Service = service
	
	err := models.CreateServicePermission(&permission)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create permission",
			"details": err.Error(),
		})
		return
	}
	
	c.Redirect(http.StatusSeeOther, "/admin/policies/"+service+"/permissions")
}

// cacheAdminPage shows cache management interface
func cacheAdminPage(c *gin.Context) {
	service := c.Param("service")
	stats := models.GetCacheStats()
	
	// Mock recent activities for demonstration
	recentActivities := []gin.H{
		{"action": "Cache cleared", "service": service, "user": "admin", "time": "2 minutes ago"},
		{"action": "Policy updated", "service": service, "user": "admin", "time": "15 minutes ago"},
	}
	
	c.HTML(http.StatusOK, "admin/cache.html", gin.H{
		"title": "Cache Management - " + service,
		"service": service,
		"cache_stats": stats,
		"recent_activities": recentActivities,
	})
}

// serviceCacheAdminPage shows service-specific cache management interface
func serviceCacheAdminPage(c *gin.Context) {
	service := c.Param("service")
	stats := models.GetCacheStats()
	
	// Mock recent activities for demonstration
	recentActivities := []gin.H{
		{"action": "Cache cleared", "service": service, "user": "admin", "time": "2 minutes ago"},
		{"action": "Policy updated", "service": service, "user": "admin", "time": "15 minutes ago"},
	}
	
	c.HTML(http.StatusOK, "admin/cache.html", gin.H{
		"title": "Cache Management - " + service,
		"service": service,
		"cache_stats": stats,
		"recent_activities": recentActivities,
	})
}

// Exported functions that main.go expects
func HealthCheck(c *gin.Context) {
	healthCheck(c)
}

func EvaluatePolicy(c *gin.Context) {
	evaluatePolicy(c)
}

func GetServiceRoles(c *gin.Context) {
	getServiceRoles(c)
}

func CreateServiceRole(c *gin.Context) {
	createServiceRole(c)
}

func UpdateServiceRole(c *gin.Context) {
	updateServiceRole(c)
}

func DeleteServiceRole(c *gin.Context) {
	deleteServiceRole(c)
}

func GetServicePermissions(c *gin.Context) {
	getServicePermissions(c)
}

func CreateServicePermission(c *gin.Context) {
	createServicePermission(c)
}

func GetCacheStats(c *gin.Context) {
	getCacheStats(c)
}

func InvalidateServiceCache(c *gin.Context) {
	invalidateServiceCache(c)
}

func ClearCache(c *gin.Context) {
	clearCache(c)
}
