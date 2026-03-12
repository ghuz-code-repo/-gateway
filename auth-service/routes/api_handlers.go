package routes

import (
	"auth-service/models"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// getUserServicePermissionsHandler returns user permissions for a specific service
func getUserServicePermissionsHandler(c *gin.Context) {
	userID := c.Param("userId")
	serviceKey := c.Param("serviceKey")

	// Convert userID to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID format",
		})
		return
	}

	// Get user
	user, err := models.GetUserByObjectID(userObjectID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	// Get user's roles and permissions for the service
	permissions, err := models.GetUserPermissionsForService(userObjectID, serviceKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get user permissions: " + err.Error(),
		})
		return
	}

	// Get user's roles for the service
	roles, err := models.GetUserRolesForService(userObjectID, serviceKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get user roles: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":     userID,
		"service_key": serviceKey,
		"permissions": permissions,
		"roles":       roles,
		"username":    user.Username,
		"full_name":   user.GetFullName(),
		"is_admin":    models.IsSystemAdmin(userObjectID),
	})
}

// getUserDocumentsHandler returns user documents
func getUserDocumentsHandler(c *gin.Context) {
	userID := c.Param("userId")
	// documentType := c.Query("type") // Unused for now

	// Convert userID to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID format",
		})
		return
	}

	// Get user
	user, err := models.GetUserByObjectID(userObjectID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	// Get user documents
	documents := user.Documents

	// For now, ignore document type filtering to avoid type issues
	// TODO: Implement proper document type filtering if needed

	c.JSON(http.StatusOK, gin.H{
		"user_id":   userID,
		"username":  user.Username,
		"full_name": user.GetFullName(),
		"documents": documents,
	})
}

// healthCheckHandler returns service health status
func healthCheckHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "auth-service",
		"timestamp": gin.H{},
	})
}

// getUsersByServiceRoleHandler returns users with a specific role for a service
func getUsersByServiceRoleHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	roleName := c.Param("roleName")

	// Get all users with this role for the service
	users, err := models.GetUsersByServiceRole(serviceKey, roleName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get users: " + err.Error(),
		})
		return
	}

	// Return user list with basic info
	// Initialize empty slice to ensure we always return [] instead of null
	result := make([]gin.H, 0)
	for _, user := range users {
		result = append(result, gin.H{
			"user_id":    user.ID.Hex(),
			"username":   user.Username,
			"email":      user.Email,
			"full_name":  user.GetFullName(),
			"short_name": user.GetShortName(),
		})
	}

	c.JSON(http.StatusOK, result)
}

// getUsersByServicePermissionHandler returns users with a specific permission for a service
func getUsersByServicePermissionHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	permissionName := c.Param("permissionName")

	// Get all users with this permission for the service
	users, err := models.GetUsersByServicePermission(serviceKey, permissionName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get users: " + err.Error(),
		})
		return
	}

	// Return user list with basic info
	// Initialize empty slice to ensure we always return [] instead of null
	result := make([]gin.H, 0)
	for _, user := range users {
		result = append(result, gin.H{
			"user_id":    user.ID.Hex(),
			"username":   user.Username,
			"email":      user.Email,
			"full_name":  user.GetFullName(),
			"short_name": user.GetShortName(),
		})
	}

	c.JSON(http.StatusOK, result)
}
