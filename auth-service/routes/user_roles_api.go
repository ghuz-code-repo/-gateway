package routes

import (
	"auth-service/models"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// getUserRolesDataHandler returns categorized roles data for user edit page
func getUserRolesDataHandler(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID пользователя"})
		return
	}

	// Get user
	user, err := models.GetUserByObjectID(objectID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	}

	// Get categorized roles
	userRoles, err := models.GetUserRolesByCategory(objectID)
	if err != nil {
		log.Printf("Error getting user roles by category: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении ролей пользователя"})
		return
	}

	// Get all available roles
	authRoles, err := models.GetAuthServiceInternalRoles()
	if err != nil {
		log.Printf("Error getting auth service roles: %v", err)
		authRoles = []models.RoleWithUsers{}
	}

	servicesWithRoles, err := models.GetAllServicesWithRolesCategorized()
	if err != nil {
		log.Printf("Error getting services with roles: %v", err)
		servicesWithRoles = []models.ServiceWithRolesCategorized{}
	}

	c.JSON(http.StatusOK, gin.H{
		"user":              user,
		"userRoles":         userRoles,
		"authRoles":         authRoles,
		"servicesWithRoles": servicesWithRoles,
	})
}

// assignServiceRoleHandler assigns a service role to a user
func assignServiceRoleHandler(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Неверный ID пользователя"})
		return
	}

	// Get current user (who is assigning the role)
	currentUser := c.MustGet("user").(*models.User)

	// Parse request body
	var req struct {
		ServiceKey string `json:"serviceKey" binding:"required"`
		RoleName   string `json:"roleName" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Неверные данные запроса"})
		return
	}

	// Permission check
	// For auth-service roles: need auth.users.assign_roles
	// For external service roles: need auth.<service>.roles.assign
	// For internal service roles: need auth.<service>.users.assign_roles (future)

	if req.ServiceKey == "auth" {
		// Assigning auth-service role
		if !requireAuthPermission(c, "auth.users.assign_roles") {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "Нет прав для назначения ролей auth-service"})
			return
		}
	} else {
		// Assigning external or internal service role
		// Check if user can assign roles for this service
		perm := fmt.Sprintf("auth.%s.roles.assign", req.ServiceKey)
		if !requireAuthPermission(c, perm) {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "error": fmt.Sprintf("Нет прав для назначения ролей сервиса %s", req.ServiceKey)})
			return
		}
	}

	// Check if role exists
	role, err := models.GetRoleByServiceAndName(req.ServiceKey, req.RoleName)
	if err != nil || role == nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Роль не найдена"})
		return
	}

	// Check if user already has this role
	existingRoles, err := models.GetUserServiceRolesByUserID(objectID)
	if err == nil {
		for _, existingRole := range existingRoles {
			if existingRole.ServiceKey == req.ServiceKey && existingRole.RoleName == req.RoleName && existingRole.IsActive {
				c.JSON(http.StatusOK, gin.H{"success": true, "message": "Роль уже назначена пользователю"})
				return
			}
		}
	}

	// Assign role
	userServiceRole := models.UserServiceRole{
		UserID:     objectID,
		ServiceKey: req.ServiceKey,
		RoleName:   req.RoleName,
		AssignedAt: time.Now(),
		AssignedBy: currentUser.ID,
		IsActive:   true,
	}

	if err := models.CreateUserServiceRole(userServiceRole); err != nil {
		log.Printf("Error assigning role %s:%s to user %s: %v", req.ServiceKey, req.RoleName, userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Ошибка при назначении роли"})
		return
	}

	log.Printf("Successfully assigned role %s:%s to user %s by %s", req.ServiceKey, req.RoleName, userID, currentUser.Username)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Роль успешно назначена",
	})
}

// removeServiceRoleHandler removes a service role from a user
func removeServiceRoleHandler(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Неверный ID пользователя"})
		return
	}

	// Get current user (who is removing the role)
	currentUser := c.MustGet("user").(*models.User)

	// Parse request body
	var req struct {
		ServiceKey string `json:"serviceKey" binding:"required"`
		RoleName   string `json:"roleName" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Неверные данные запроса"})
		return
	}

	// Permission check (same as assign)
	if req.ServiceKey == "auth" {
		if !requireAuthPermission(c, "auth.users.assign_roles") {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "Нет прав для удаления ролей auth-service"})
			return
		}
	} else {
		perm := fmt.Sprintf("auth.%s.roles.assign", req.ServiceKey)
		if !requireAuthPermission(c, perm) {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "error": fmt.Sprintf("Нет прав для удаления ролей сервиса %s", req.ServiceKey)})
			return
		}
	}

	// Remove role (deactivate)
	err = models.DeactivateUserServiceRole(objectID, req.ServiceKey, req.RoleName)
	if err != nil {
		log.Printf("Error removing role %s:%s from user %s: %v", req.ServiceKey, req.RoleName, userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Ошибка при удалении роли"})
		return
	}

	log.Printf("Successfully removed role %s:%s from user %s by %s", req.ServiceKey, req.RoleName, userID, currentUser.Username)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Роль успешно удалена",
	})
}
