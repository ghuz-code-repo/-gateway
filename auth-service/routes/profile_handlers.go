package routes

import (
	"auth-service/models"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// SetupProfileRoutes настраивает роуты для профиля (доступные через /profile)
func SetupProfileRoutes(router *gin.Engine) {
	// Эти роуты будут доступны через nginx прокси /profile -> auth-service:80/profile
	router.GET("/profile", authRequired(), profileHandler)
	router.POST("/profile", authRequired(), updateProfileHandler) // JavaScript отправляет POST на /profile
	router.POST("/profile/update", authRequired(), updateProfileHandler)
	router.POST("/profile/avatar", authRequired(), uploadAvatarHandler)
	router.GET("/profile/avatar/original", authRequired(), getOriginalAvatarHandler)
	router.GET("/profile/avatar/original/file", authRequired(), getOriginalAvatarFileHandler)
	router.DELETE("/profile/remove-avatar", authRequired(), removeAvatarHandler)
	router.POST("/profile/password", authRequired(), changePasswordHandler)
	router.POST("/profile/document", authRequired(), uploadDocumentHandler)
	router.POST("/profile/document/delete", authRequired(), deleteDocumentHandler)
	router.GET("/profile/document/:id", authRequired(), downloadDocumentHandler)

	// Document system routes for profile
	router.GET("/profile/documents", authRequired(), getMyDocumentsHandler)
	router.GET("/profile/documents/:id", authRequired(), getUserDocumentHandler)
	router.GET("/profile/documents/:id/attachments", authRequired(), getDocumentAttachmentsHandler)
	router.POST("/profile/documents", authRequired(), createUserDocumentHandler)
	router.PUT("/profile/documents/:id", authRequired(), updateUserDocumentHandler)
	router.DELETE("/profile/documents/:id", authRequired(), deleteUserDocumentHandler)
	router.POST("/profile/documents/:id/attachments", authRequired(), addDocumentAttachmentHandler)
	router.DELETE("/profile/documents/:id/attachments/:attachmentId", authRequired(), removeDocumentAttachmentHandler)
	router.GET("/profile/documents/:id/attachments/:attachmentId/download", authRequired(), downloadDocumentAttachmentHandler)
	router.GET("/profile/documents/:id/attachments/:attachmentId/preview", authRequired(), previewDocumentAttachmentHandler)
}

// profileHandler shows the user profile page
func profileHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	// Get user's service roles
	userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
	if err != nil {
		userServiceRoles = []models.UserServiceRole{}
	}

	// Group roles by service
	serviceRolesMap := make(map[string][]string)
	for _, usr := range userServiceRoles {
		if usr.IsActive {
			serviceRolesMap[usr.ServiceKey] = append(serviceRolesMap[usr.ServiceKey], usr.RoleName)
		}
	}

	// Get service display names
	services, _ := models.GetAllServices()
	serviceNames := make(map[string]string)
	for _, service := range services {
		serviceNames[service.Key] = service.Name
	}

	// Prepare user roles for template
	var userRoles []map[string]interface{}
	for serviceKey, roles := range serviceRolesMap {
		serviceName := serviceNames[serviceKey]
		if serviceName == "" {
			serviceName = serviceKey
		}
		userRoles = append(userRoles, map[string]interface{}{
			"ServiceKey":  serviceKey,
			"ServiceName": serviceName,
			"Roles":       roles,
		})
	}

	c.HTML(http.StatusOK, "profile.html", gin.H{
		"title":        "Личный кабинет",
		"username":     user.Username,
		"full_name":    user.GetFullName(),
		"short_name":   user.GetShortName(),
		"user":         user,
		"userRoles":    userRoles,
		"serviceRoles": serviceRolesMap,
		"serviceNames": serviceNames,
		"timestamp":    time.Now().Unix(),
	})
}

// updateProfileHandler updates user profile information
func updateProfileHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	email := c.PostForm("email")
	lastName := c.PostForm("lastName")
	firstName := c.PostForm("firstName")
	middleName := c.PostForm("middleName")
	suffix := c.PostForm("suffix")
	phone := c.PostForm("phone")
	position := c.PostForm("position")
	department := c.PostForm("department")

	log.Printf("updateProfileHandler: user=%s, email=%s, lastName=%s, firstName=%s, middleName=%s, suffix=%s, phone=%s, position=%s, department=%s\n",
		user.Username, email, lastName, firstName, middleName, suffix, phone, position, department)

	err := models.UpdateUserProfile(user.ID, email, lastName, firstName, middleName, suffix, phone, position, department)
	if err != nil {
		log.Printf("updateProfileHandler error: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить профиль"})
		return
	}

	// Get updated user data
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Профиль успешно обновлен",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Профиль успешно обновлен",
		"user": gin.H{
			"email":      updatedUser.Email,
			"lastName":   updatedUser.LastName,
			"firstName":  updatedUser.FirstName,
			"middleName": updatedUser.MiddleName,
			"suffix":     updatedUser.Suffix,
			"fullName":   updatedUser.GetFullName(),
			"shortName":  updatedUser.GetShortName(),
			"phone":      updatedUser.Phone,
			"position":   updatedUser.Position,
			"department": updatedUser.Department,
		},
	})
}

// changePasswordHandler handles password change
func changePasswordHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	currentPassword := c.PostForm("current_password")
	newPassword := c.PostForm("new_password")
	confirmPassword := c.PostForm("confirm_password")

	log.Printf("changePasswordHandler: user=%s, currentPassword len=%d, newPassword len=%d, confirmPassword len=%d\n",
		user.Username, len(currentPassword), len(newPassword), len(confirmPassword))

	// Verify current password
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный текущий пароль"})
		return
	}

	// Check if new passwords match
	if newPassword != confirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Новые пароли не совпадают"})
		return
	}

	// Validate new password
	if err := models.ValidatePassword(newPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update password
	err = models.ChangeUserPassword(user.ID, newPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось изменить пароль"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Пароль успешно изменен"})
}

// Avatar and document handlers are implemented in separate files:
// - Avatar handlers: separate avatar_handlers.go file (not yet created)
// - Document handlers: document_handlers.go file
