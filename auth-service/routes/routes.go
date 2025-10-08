package routes

import (
	"net/http"
	"time"
	"log"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
		api.GET("/users/:userId/documents/grouped", getUserDocumentsGroupedAPIHandler)
		api.GET("/users/:userId/documents/for-service/:serviceKey", getUserDocumentsForServiceAPIHandler)
		api.POST("/users/:userId/documents", createUserDocumentAPIHandler)
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
	router.GET("/available-services", authRequired(), getAvailableServicesHandler)
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
	// List all services (admin only)
	router.GET("/services/", adminAuthRequired(), listServicesHandlerWithAccess)
	router.GET("/services/new", adminAuthRequired(), showServiceFormHandler)
	router.POST("/services/", adminAuthRequired(), createServiceHandler)
	
	// Service-specific management (service admin or system admin)
	router.GET("/services/:serviceKey", serviceAdminAuthRequired(), getServiceHandlerWithAccess)
	router.POST("/services/:serviceKey", serviceAdminAuthRequired(), updateServiceHandlerWithAccess)
	router.POST("/services/:serviceKey/delete", serviceAdminAuthRequired(), deleteServiceHandler)
	router.POST("/services/:serviceKey/permissions", serviceAdminAuthRequired(), addServicePermissionHandler)
	router.PUT("/services/:serviceKey/permissions/:permName", serviceAdminAuthRequired(), updateServicePermissionHandler)
	router.POST("/services/:serviceKey/permissions/:permName/delete", serviceAdminAuthRequired(), deleteServicePermissionHandler)
	router.POST("/services/:serviceKey/permissions/sync", serviceAdminAuthRequired(), syncServicePermissionsHandler) // Sync permissions from service (authenticated)
	
	// Service roles management
	router.POST("/services/:serviceKey/roles", serviceAdminAuthRequired(), createServiceRoleHandler)
	router.GET("/services/:serviceKey/roles/:roleId", serviceAdminAuthRequired(), getServiceRoleHandler)
	router.POST("/services/:serviceKey/roles/:roleId", serviceAdminAuthRequired(), updateServiceRoleHandler)
	router.POST("/services/:serviceKey/roles/:roleId/delete", serviceAdminAuthRequired(), deleteServiceRoleHandler)
	router.POST("/services/:serviceKey/assign-role", serviceAdminAuthRequired(), assignUserToServiceRoleHandler)

	// User management for services
	router.GET("/services/:serviceKey/users", serviceAdminAuthRequired(), getServiceUsersHandler)
	router.POST("/services/:serviceKey/users", serviceAdminAuthRequired(), addUserToServiceHandler)
	router.PUT("/services/:serviceKey/users/:userId/roles", serviceAdminAuthRequired(), updateUserServiceRolesHandler)

	// Service-specific Excel import/export routes
	router.GET("/services/:serviceKey/import", serviceAdminAuthRequired(), serviceImportPageHandler)           // Show import page for service
	router.POST("/services/:serviceKey/import", serviceAdminAuthRequired(), serviceImportHandler)             // Process Excel import for service
	router.GET("/services/:serviceKey/export", serviceAdminAuthRequired(), serviceExportHandler)              // Export existing users for service (with data)
	router.GET("/services/:serviceKey/template", serviceAdminAuthRequired(), serviceTemplateHandler)          // Download empty template for service
	router.GET("/services/:serviceKey/import/logs", serviceAdminAuthRequired(), serviceImportLogsHandler)     // Get import logs for service

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
	
	log.Printf("DEBUG getUserDocumentsAPIHandler: Getting documents for user %s", userID)
	
	documents, err := models.GetUserDocuments(userID)
	if err != nil {
		log.Printf("DEBUG getUserDocumentsAPIHandler: User %s not found or has no documents: %v", userID, err)
		// Return empty result instead of error for users without documents
		c.JSON(http.StatusOK, gin.H{
			"user_id": userID,
			"documents": []interface{}{},
		})
		return
	}
	
	log.Printf("DEBUG getUserDocumentsAPIHandler: Found %d documents for user %s", len(documents), userID)
	
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

// getUserDocumentsGroupedAPIHandler returns user documents grouped by document type via API
func getUserDocumentsGroupedAPIHandler(c *gin.Context) {
	userID := c.Param("userId")
	
	documents, err := models.GetUserDocuments(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user documents"})
		return
	}
	
	// Group documents by document_group
	groupedDocuments := make(map[string]interface{})
	
	for _, doc := range documents {
		// Get document type to access group information
		docType, err := models.GetDocumentTypeByKey(doc.DocumentType)
		if err != nil {
			continue // Skip documents with invalid type
		}
		
		// Use document_group as key, fallback to document type if group is empty
		groupKey := docType.DocumentGroup
		if groupKey == "" {
			groupKey = docType.ID
		}
		
		// If this group doesn't exist yet, create it
		if _, exists := groupedDocuments[groupKey]; !exists {
			groupedDocuments[groupKey] = gin.H{
				"group": groupKey,
				"documents": []interface{}{},
			}
		}
		
		// Add document to the group
		groupData := groupedDocuments[groupKey].(gin.H)
		documents := groupData["documents"].([]interface{})
		groupData["documents"] = append(documents, doc)
		groupedDocuments[groupKey] = groupData
	}
	
	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"grouped_documents": groupedDocuments,
	})
}

// getDocumentPriority returns priority for document types within the same group
// Higher number means higher priority
func getDocumentPriority(docType string) int {
	switch docType {
	case "passport":    // Узбекский паспорт - высший приоритет
		return 3
	case "passport_ru": // Российский паспорт
		return 2
	case "pinfl":       // ПИНФЛ - низший приоритет
		return 1
	default:
		return 0
	}
}

// getUserDocumentsForServiceAPIHandler returns user documents for specific service via API
// From each document group, selects the document that is used for the given service
// If multiple documents in a group are used for the service, takes the last added one
func getUserDocumentsForServiceAPIHandler(c *gin.Context) {
	userID := c.Param("userId")
	serviceKey := c.Param("serviceKey")
	
	log.Printf("DEBUG getUserDocumentsForServiceAPIHandler: Getting documents for user %s, service %s", userID, serviceKey)
	
	documents, err := models.GetUserDocuments(userID)
	if err != nil {
		log.Printf("DEBUG getUserDocumentsForServiceAPIHandler: User %s not found or has no documents: %v", userID, err)
		// Return empty result instead of error for users without documents
		c.JSON(http.StatusOK, gin.H{
			"user_id": userID,
			"service_key": serviceKey,
			"documents_for_service": make(map[string]interface{}),
		})
		return
	}
	
	log.Printf("DEBUG getUserDocumentsForServiceAPIHandler: Found %d documents for user %s", len(documents), userID)
	
	// Group documents by document_group and filter by service
	serviceDocuments := make(map[string]interface{})
	
	for _, doc := range documents {
		// Check if this document is used for the requested service
		isUsedForService := false
		for _, allowedService := range doc.AllowedServices {
			if allowedService == serviceKey {
				isUsedForService = true
				break
			}
		}
		
		if !isUsedForService {
			continue // Skip documents not used for this service
		}
		
		// Get document type to access group information
		docType, err := models.GetDocumentTypeByKey(doc.DocumentType)
		if err != nil {
			log.Printf("ERROR getUserDocumentsForServiceAPIHandler: Failed to get document type for %s: %v", doc.DocumentType, err)
			continue // Skip documents with invalid type
		}
		
		// Use document_group as key, fallback to document type if group is empty
		groupKey := docType.DocumentGroup
		if groupKey == "" {
			groupKey = docType.ID
		}
		
		// Check if we already have a document for this group
		if existingDoc, exists := serviceDocuments[groupKey]; exists {
			// Use priority-based selection for identity documents
			existingDocType := existingDoc.(map[string]interface{})["document"].(models.UserDocument).DocumentType
			currentDocType := doc.DocumentType
			
			shouldReplace := false
			
			// Priority for identity documents: passport > passport_ru > pinfl
			if groupKey == "identity" {
				currentPriority := getDocumentPriority(currentDocType)
				existingPriority := getDocumentPriority(existingDocType)
				
				if currentPriority > existingPriority {
					shouldReplace = true
				} else if currentPriority == existingPriority {
					// Same priority, use creation date
					existingCreatedAt := existingDoc.(map[string]interface{})["created_at"].(string)
					currentCreatedAt := doc.CreatedAt.Format("2006-01-02T15:04:05.000Z")
					shouldReplace = currentCreatedAt > existingCreatedAt
				}
			} else {
				// For other groups, use creation date
				existingCreatedAt := existingDoc.(map[string]interface{})["created_at"].(string)
				currentCreatedAt := doc.CreatedAt.Format("2006-01-02T15:04:05.000Z")
				shouldReplace = currentCreatedAt > existingCreatedAt
			}
			
			if shouldReplace {
				serviceDocuments[groupKey] = map[string]interface{}{
					"group": groupKey,
					"document": doc,
					"created_at": doc.CreatedAt.Format("2006-01-02T15:04:05.000Z"),
				}
			}
		} else {
			// First document for this group
			serviceDocuments[groupKey] = map[string]interface{}{
				"group": groupKey,
				"document": doc,
				"created_at": doc.CreatedAt.Format("2006-01-02T15:04:05.000Z"),
			}
		}
	}
	
	// Prepare final response - extract just the documents
	finalDocuments := make(map[string]interface{})
	for groupKey, groupData := range serviceDocuments {
		groupMap := groupData.(map[string]interface{})
		finalDocuments[groupKey] = gin.H{
			"group": groupKey,
			"document": groupMap["document"],
		}
	}
	
	log.Printf("DEBUG getUserDocumentsForServiceAPIHandler: Returning %d document groups for user %s, service %s", len(finalDocuments), userID, serviceKey)
	
	c.JSON(http.StatusOK, gin.H{
		"user_id": userID,
		"service_key": serviceKey,
		"documents_for_service": finalDocuments,
	})
}

// createUserDocumentAPIHandler creates a new document for a user via API
func createUserDocumentAPIHandler(c *gin.Context) {
	userID := c.Param("userId")
	
	// Parse JSON body
	var requestBody struct {
		DocumentType     string                 `json:"document_type" binding:"required"`
		Title           string                 `json:"title" binding:"required"`
		Fields          map[string]interface{} `json:"fields" binding:"required"`
		AllowedServices []string               `json:"allowed_services"`
		Status          string                 `json:"status"`
	}
	
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}
	
	// Validate user exists
	_, err := models.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	
	// Validate document type exists
	_, err = models.GetDocumentTypeByKey(requestBody.DocumentType)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid document type"})
		return
	}
	
	// Set default status if not provided
	if requestBody.Status == "" {
		requestBody.Status = "draft"
	}
	
	// Set default allowed services if not provided
	if len(requestBody.AllowedServices) == 0 {
		requestBody.AllowedServices = []string{}
	}
	
	// Create document
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}
	
	document := models.UserDocument{
		DocumentType:     requestBody.DocumentType,
		Title:           requestBody.Title,
		Fields:          requestBody.Fields,
		AllowedServices: requestBody.AllowedServices,
		Status:          requestBody.Status,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	
	err = models.AddUserDocumentNew(userObjectID, document)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create document: " + err.Error()})
		return
	}
	
	c.JSON(http.StatusCreated, gin.H{
		"message": "Document created successfully",
		"document": document,
	})
}
