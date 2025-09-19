package routes

import (
	"github.com/gin-gonic/gin"
)

// SetupAllRoutes configures all routes for the application
func SetupAllRoutes(router *gin.Engine) {
	// Set up authentication routes
	SetupAuthRoutes(router)
	
	// Set up admin routes (includes user and service management)
	SetupAdminRoutes(router)
	
	// Set up profile routes
	SetupProfileRoutes(router)
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
		users.GET("/:id/password", getUserPasswordHandler)
		users.POST("/:id/ban", banUserHandler)
		users.POST("/:id/unban", unbanUserHandler)
		users.GET("/import", showUserImportFormHandler)
		users.POST("/import", importUsersHandler)
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

	// Service management
	services := router.Group("/services")
	services.Use(serviceAdminAuthRequired())
	{
		services.GET("/", listServicesHandlerWithAccess)
		services.GET("/new", showServiceFormHandler)
		services.POST("/", createServiceHandler)
		services.GET("/:id", getServiceHandlerWithAccess)
		services.POST("/:id", updateServiceHandlerWithAccess)
		services.POST("/:id/delete", deleteServiceHandler)
		services.POST("/:id/permissions", addServicePermissionHandler)
		services.PUT("/:id/permissions/:permName", updateServicePermissionHandler)
		services.POST("/:id/permissions/:permName/delete", deleteServicePermissionHandler)
		
		// Service roles management
		services.POST("/:id/roles", createServiceRoleHandler)
		services.GET("/:id/roles/:roleId", getServiceRoleHandler)
		services.POST("/:id/roles/:roleId", updateServiceRoleHandler)
		services.POST("/:id/roles/:roleId/delete", deleteServiceRoleHandler)
		services.POST("/:id/assign-role", assignUserToServiceRoleHandler)

		// User management for services
		services.GET("/:id/users", getServiceUsersHandler)
		services.POST("/:id/users", addUserToServiceHandler)
		services.PUT("/:id/users/:userId/roles", updateUserServiceRolesHandler)
	}

	// Check user existence endpoint
	router.GET("/check-user-exists", serviceAdminAuthRequired(), checkUserExistsHandler)

	// Migration management (placeholder for now)
	migration := router.Group("/migration")
	migration.Use(adminAuthRequired())
	{
		migration.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "Migration endpoints not implemented yet"})
		})
	}
}
