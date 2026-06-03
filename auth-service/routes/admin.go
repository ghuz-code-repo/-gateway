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
	"auth-service/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Legacy function placeholders - actual implementations moved to other files
func migrationStatusHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Эндпоинты миграции ещё не реализованы"})
}

func runMigrationHandler(c *gin.Context) {
	// Run ADR-001 schema migration
	result, err := models.MigrateToADR001Schema()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
			"result":  result,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"result":  result,
	})
}

func validateMigrationHandler(c *gin.Context) {
	err := models.ValidateMigration()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Проверка пройдена",
	})
}

func rollbackMigrationHandler(c *gin.Context) {
	err := models.RollbackMigration()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Откат выполнен",
	})
}

func cleanupOrphanedDataHandler(c *gin.Context) {
	result, err := models.CleanupOrphanedUserServiceRoles()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
			"result":  result,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"result":  result,
	})
}

// Legacy role management - should be moved to separate file
func listRolesHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Управление ролями ещё не реализовано"})
}

func showRoleFormHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Управление ролями ещё не реализовано"})
}

func createRoleHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Управление ролями ещё не реализовано"})
}

func getRoleHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Управление ролями ещё не реализовано"})
}

func updateRoleHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Управление ролями ещё не реализовано"})
}

func deleteRoleHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Управление ролями ещё не реализовано"})
}

// Legacy permission management - should be moved to separate file
func listPermissionsHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Управление разрешениями ещё не реализовано"})
}

func showPermissionFormHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Управление разрешениями ещё не реализовано"})
}

func createPermissionHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Управление разрешениями ещё не реализовано"})
}

func getPermissionHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Управление разрешениями ещё не реализовано"})
}

func updatePermissionHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Управление разрешениями ещё не реализовано"})
}

func deletePermissionHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Управление разрешениями ещё не реализовано"})
}
