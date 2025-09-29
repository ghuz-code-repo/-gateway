package routes

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"auth-service/models"
)

// SetupAllRoutes configures all routes for the application
func SetupAllRoutes(router *gin.Engine) {
	// Set up authentication routes
	SetupAuthRoutes(router)
	
	// Set up admin routes (includes user and service management)
	SetupAdminRoutes(router)
	
	// Set up profile routes
	SetupProfileRoutes(router)
	
	// API endpoints for internal service communication (no auth required)
	api := router.Group("/api")
	{
		api.GET("/test", testAPIHandler)
		api.POST("/services/:serviceKey/permissions/sync", syncServicePermissionsHandler)
		api.GET("/users/:userId/documents", getUserDocumentsAPIHandler)
		api.GET("/users/:userId/profile", getUserProfileAPIHandler)
	}
}

// SetupAuthRoutes configures all the routes for authentication
func SetupAuthRoutes(router *gin.Engine) {
	// Basic routes
	router.GET("/", homeHandler)
	router.GET("/menu", authRequired(), menuHandler)
	
	// Authentication routes
	router.GET("/login", loginPageHandler)
	router.POST("/login", loginHandler)
	router.GET("/logout", logoutHandler)
	router.GET("/verify", verifyHandler)
	router.GET("/access-denied", accessDeniedHandler)
	
	// Password recovery routes
	router.GET("/forgot-password", forgotPasswordPageHandler)
	router.POST("/forgot-password", forgotPasswordHandler)
	router.GET("/reset-password", resetPasswordPageHandler)
	router.POST("/reset-password", resetPasswordHandler)

	// Document system routes
	router.GET("/document-types", authRequired(), getDocumentTypesHandler)
}

// SetupAdminRoutes sets up routes for the admin panel
func SetupAdminRoutes(router *gin.Engine) {
	// User management routes
	users := router.Group("/users")
	users.Use(adminAuthRequired())
	{
		users.GET("/", usersManagementHandler)  // New enhanced management page
		users.GET("/test", usersManagementTestHandler) // Test page for debugging
		users.GET("/legacy", listUsersHandler) // Old page for backward compatibility
		users.GET("/new", showEnhancedUserFormHandler)
		users.GET("/new/legacy", showUserFormHandler) // Old form for backward compatibility
		users.POST("/", createUserHandler)
		users.GET("/:id", showEnhancedUserFormHandler) // Use enhanced form for editing
		users.GET("/:id/debug", debugUserRolesHandler) // Debug roles for user
		users.GET("/:id/legacy", getUserHandler)     // Old handler for backward compatibility
		users.POST("/:id", updateUserHandler)
		users.POST("/:id/delete", deleteUserHandler)
		users.POST("/:id/reset-password", sendPasswordResetHandler)
		users.POST("/:id/ban", banUserHandler)
		users.POST("/:id/unban", unbanUserHandler)
		// Avatar management for specific users (admin access)
		users.POST("/:id/avatar", adminUploadAvatarHandler)
		users.GET("/:id/avatar/original", adminGetOriginalAvatarHandler)
		users.GET("/:id/avatar/original/file", adminGetOriginalAvatarFileHandler)
		users.DELETE("/:id/remove-avatar", adminRemoveAvatarHandler)
		users.GET("/import", showUserImportFormHandler)
		users.POST("/import", importUsersHandler)
		users.GET("/import/logs", showImportLogsHandler)
		users.GET("/import/logs/:id", showImportLogDetailsHandler)
		users.GET("/export", exportUsersHandler)
		users.GET("/template", downloadUsersTemplateHandler)
		// Document management for specific users (admin access)
		users.GET("/:id/documents", getUserDocumentsByIDHandler) // Get documents for user
		users.POST("/:id/documents", createUserDocumentHandlerAdmin) // Create new document for user
		users.GET("/:id/documents/:docId", getUserDocumentHandlerAdmin) // Get specific document
		users.PUT("/:id/documents/:docId", updateUserDocumentHandlerAdmin) // Update document
		users.DELETE("/:id/documents/:docId", deleteUserDocumentHandlerAdmin) // Delete document
		users.GET("/:id/documents/:docId/attachments", getUserDocumentAttachmentsByIDHandler) // Get attachments for document
		users.POST("/:id/documents/:docId/attachments", addDocumentAttachmentHandlerAdmin) // Add attachment to document
		users.DELETE("/:id/documents/:docId/attachments/:attachmentId", removeDocumentAttachmentHandlerAdmin) // Remove attachment
		users.GET("/:id/documents/:docId/attachments/:attachmentId/download", downloadDocumentAttachmentHandlerAdmin) // Download attachment
		users.GET("/:id/documents/:docId/attachments/:attachmentId/preview", previewDocumentAttachmentHandlerAdmin) // Preview attachment
	}

	// Admin utility routes
	admin := router.Group("/admin")
	admin.Use(adminAuthRequired())
	{
		admin.GET("/update-user-email", updateUserEmailPageHandler)
		admin.POST("/update-user-email", updateUserEmailHandler)
	}
	
	// Notification service settings (only for system admins) - separate routing
	router.GET("/notification-settings", adminAuthRequired(), getNotificationSettings)
	router.POST("/notification-settings", adminAuthRequired(), updateNotificationSettings)
	router.POST("/notification-settings/test", adminAuthRequired(), testNotificationSettings)

	// Service management
	services := router.Group("/services")
	services.Use(serviceAdminAuthRequired())
	{
		services.GET("/", listServicesHandlerWithAccess)
		services.GET("/new", showServiceFormHandler)
		services.POST("/", createServiceHandler)
		services.GET("/:serviceKey", getServiceHandlerWithAccess)
		services.POST("/:serviceKey", updateServiceHandlerWithAccess)
		services.POST("/:serviceKey/delete", deleteServiceHandler)
		services.POST("/:serviceKey/permissions", addServicePermissionHandler)
		services.PUT("/:serviceKey/permissions/:permName", updateServicePermissionHandler)
		services.POST("/:serviceKey/permissions/:permName/delete", deleteServicePermissionHandler)
		services.POST("/:serviceKey/permissions/sync", syncServicePermissionsHandler) // Sync permissions from service (authenticated)
		
		// Service roles management
		services.POST("/:serviceKey/roles", createServiceRoleHandler)
		services.GET("/:serviceKey/roles/:roleId", getServiceRoleHandler)
		services.POST("/:serviceKey/roles/:roleId", updateServiceRoleHandler)
		services.POST("/:serviceKey/roles/:roleId/delete", deleteServiceRoleHandler)
		services.POST("/:serviceKey/assign-role", assignUserToServiceRoleHandler)

		// User management for services
		services.GET("/:serviceKey/users", getServiceUsersHandler)
		services.POST("/:serviceKey/users", addUserToServiceHandler)
		services.PUT("/:serviceKey/users/:userId/roles", updateUserServiceRolesHandler)
	}

	// Check user existence endpoint
	router.GET("/check-user-exists", serviceAdminAuthRequired(), checkUserExistsHandler)

	// Service-specific Excel import/export routes (extending services group)
	services.GET("/:serviceKey/import", serviceImportPageHandler)           // Show import page for service
	services.POST("/:serviceKey/import", serviceImportHandler)             // Process Excel import for service
	services.GET("/:serviceKey/export", serviceExportHandler)              // Export existing users for service (with data)
	services.GET("/:serviceKey/template", serviceTemplateHandler)          // Download empty template for service
	services.GET("/:serviceKey/import/logs", serviceImportLogsHandler)     // Get import logs for service

	// Migration management (placeholder for now)
	migration := router.Group("/migration")
	migration.Use(adminAuthRequired())
	{
		migration.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "Migration endpoints not implemented yet"})
		})
	}
}

// testAPIHandler handles API test requests
func testAPIHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "API works"})
}

// accessDeniedHandler shows access denied page
func accessDeniedHandler(c *gin.Context) {
	service := c.Query("service")
	redirect := c.Query("redirect")
	
	c.HTML(http.StatusForbidden, "access-denied.html", gin.H{
		"service": service,
		"redirect": redirect,
		"title": "Доступ запрещен",
	})
}

// getUserDocumentsAPIHandler returns user documents via API
func getUserDocumentsAPIHandler(c *gin.Context) {
	userID := c.Param("userId")
	
	documents, err := models.GetUserDocuments(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user documents"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"documents": documents,
	})
}

// getUserProfileAPIHandler returns user profile data via API
func getUserProfileAPIHandler(c *gin.Context) {
	userID := c.Param("userId")
	
	user, err := models.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"username": user.Username,
		"email": user.Email,
		"full_name": user.FullName,
		"first_name": user.FirstName,
		"last_name": user.LastName,
		"phone": user.Phone,
		"avatar_path": user.AvatarPath,
		"passport_number": user.PassportNumber,
		"passport_issued_by": user.PassportIssuedBy,
		"passport_issued_date": user.PassportIssuedDate,
		"address": user.Address,
		"birth_date": user.BirthDate,
	})
}
