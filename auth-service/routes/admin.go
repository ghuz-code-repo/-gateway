package routes

// This file has been refactored and most functionality moved to specialized files:
//
// - user_management.go: User administration handlers
// - service_management.go: Service administration handlers
// - middleware.go: Authentication and authorization middleware
//
// This file contains only legacy functions that are still referenced
// but should be migrated to the appropriate specialized files.

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Legacy function placeholders - actual implementations moved to other files
func migrationStatusHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Migration endpoints not implemented yet"})
}

func runMigrationHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Migration endpoints not implemented yet"})
}

func validateMigrationHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Migration endpoints not implemented yet"})
}

func rollbackMigrationHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Migration endpoints not implemented yet"})
}

// Legacy role management - should be moved to separate file
func listRolesHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Role management not implemented yet"})
}

func showRoleFormHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Role management not implemented yet"})
}

func createRoleHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Role management not implemented yet"})
}

func getRoleHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Role management not implemented yet"})
}

func updateRoleHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Role management not implemented yet"})
}

func deleteRoleHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Role management not implemented yet"})
}

// Legacy permission management - should be moved to separate file
func listPermissionsHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Permission management not implemented yet"})
}

func showPermissionFormHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Permission management not implemented yet"})
}

func createPermissionHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Permission management not implemented yet"})
}

func getPermissionHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Permission management not implemented yet"})
}

func updatePermissionHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Permission management not implemented yet"})
}

func deletePermissionHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Permission management not implemented yet"})
}
