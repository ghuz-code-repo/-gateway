package routes

import (
	"auth-service/models"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// getDocumentTypesHandler returns all available document types
func getDocumentTypesHandler(c *gin.Context) {
	log.Println("Fetching document types...")
	documentTypes, err := models.GetAllDocumentTypes()
	if err != nil {
		log.Printf("Error fetching document types: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить типы документов"})
		return
	}

	log.Printf("Found %d document types", len(documentTypes))
	for i, dt := range documentTypes {
		log.Printf("Document type %d: ID=%s, Name=%s, Fields=%d", i, dt.ID, dt.Name, len(dt.Fields))
	}
	c.JSON(http.StatusOK, documentTypes)
}

// getAvailableServicesHandler returns all available services for document usage
func getAvailableServicesHandler(c *gin.Context) {
	log.Println("Fetching available services...")
	services, err := models.GetAllServices()
	if err != nil {
		log.Printf("Error fetching services: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить список сервисов"})
		return
	}

	// Format services for the frontend
	var serviceOptions []gin.H
	for _, service := range services {
		serviceOptions = append(serviceOptions, gin.H{
			"key":         service.Key,
			"name":        service.Name,
			"description": service.Description,
		})
	}

	log.Printf("Found %d services", len(serviceOptions))
	c.JSON(http.StatusOK, serviceOptions)
}

// getMyDocumentsHandler returns all documents for the current user  
func getMyDocumentsHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	log.Printf("Getting documents for user: %s (username: %s)", user.ID.Hex(), user.Username)

	// Get updated user data to get documents
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	log.Printf("User found: %s, documents count: %d", updatedUser.Username, len(updatedUser.Documents))

	// Convert UserDocument to response format
	var documents []map[string]interface{}
	for i, doc := range updatedUser.Documents {
		log.Printf("Processing document %d: type=%s, title=%s", i, doc.DocumentType, doc.Title)
		docResponse := map[string]interface{}{
			"id":            fmt.Sprintf("%d", i), // Use index as ID since documents don't have separate IDs
			"document_type": doc.DocumentType,
			"title":         doc.Title,
			"fields":        doc.Fields,
			"status":        doc.Status,
			"created_at":    doc.CreatedAt,
			"updated_at":    doc.UpdatedAt,
		}
		documents = append(documents, docResponse)
	}

	log.Printf("Found %d documents for user %s", len(documents), user.ID.Hex())
	c.JSON(http.StatusOK, documents)
}

// getUserDocumentHandler returns a specific document for the current user
func getUserDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	documentID := c.Param("id")
	
	log.Printf("Getting document %s for user: %s", documentID, user.ID.Hex())
	
	// Get updated user data to get documents
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(documentID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	doc := updatedUser.Documents[docIndex]
	docResponse := map[string]interface{}{
		"id":            fmt.Sprintf("%d", docIndex),
		"document_type": doc.DocumentType,
		"title":         doc.Title,
		"fields":        doc.Fields,
		"status":        doc.Status,
		"created_at":    doc.CreatedAt,
		"updated_at":    doc.UpdatedAt,
	}

	c.JSON(http.StatusOK, docResponse)
}

// Placeholder implementations for complex document operations
func uploadDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	
	log.Printf("Uploading document for user: %s", user.ID.Hex())

	// Parse multipart form
	err := c.Request.ParseMultipartForm(99 << 20) // 99 MB max
	if err != nil {
		log.Printf("Error parsing multipart form: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка обработки формы"})
		return
	}

	// Get form fields
	documentType := c.PostForm("document_type")
	title := c.PostForm("title")
	
	if documentType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Тип документа обязателен"})
		return
	}
	
	if title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Название документа обязательно"})
		return
	}

	// Create new document first
	newDoc := models.UserDocument{
		DocumentType: documentType,
		Title:        title,
		Fields:       make(map[string]interface{}),
		Status:       "draft",
		Attachments:  []models.DocumentAttachment{},
	}
	
	// Add document to user
	if err := models.AddUserDocumentNew(user.ID, newDoc); err != nil {
		log.Printf("Error adding document: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при создании документа"})
		return
	}

	log.Printf("Document uploaded successfully for user %s: %s", user.Username, title)
	c.JSON(http.StatusCreated, gin.H{
		"message": "Документ успешно загружен",
		"document_type": documentType,
		"title": title,
	})
}

func deleteDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	documentID := c.Param("id")
	
	log.Printf("Deleting document (profile) %s for user: %s", documentID, user.ID.Hex())

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(documentID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Get updated user data to access documents
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Remove document
	updatedUser.Documents = append(updatedUser.Documents[:docIndex], updatedUser.Documents[docIndex+1:]...)
	
	// Update user in database
	if err := models.UpdateUserDocuments(user.ID, updatedUser.Documents); err != nil {
		log.Printf("Error updating user documents: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при удалении документа"})
		return
	}
	
	log.Printf("Document deleted successfully from profile for user %s", user.Username)
	c.JSON(http.StatusOK, gin.H{"message": "Документ успешно удален"})
}

func downloadDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	documentID := c.Param("id")
	
	log.Printf("Downloading document %s for user: %s", documentID, user.ID.Hex())

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(documentID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Get updated user data to access documents
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	doc := updatedUser.Documents[docIndex]
	
	// Return document info as JSON (could be modified to return actual files)
	c.JSON(http.StatusOK, gin.H{
		"document": gin.H{
			"id": docIndex,
			"title": doc.Title,
			"type": doc.DocumentType,
			"fields": doc.Fields,
			"attachments": doc.Attachments,
			"created_at": doc.CreatedAt,
			"updated_at": doc.UpdatedAt,
		},
	})
}

func getDocumentAttachmentsHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	documentID := c.Param("id")
	
	log.Printf("Getting attachments for document %s, user: %s", documentID, user.ID.Hex())

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(documentID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Get updated user data to access documents
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Get document attachments
	doc := updatedUser.Documents[docIndex]
	var attachments []map[string]interface{}
	
	for _, attachment := range doc.Attachments {
		attachmentResponse := map[string]interface{}{
			"id":            attachment.ID.Hex(),
			"filename":      attachment.FileName,
			"original_name": attachment.OriginalName,
			"size":          attachment.Size,
			"content_type":  attachment.ContentType,
			"uploaded_at":   attachment.UploadedAt,
		}
		attachments = append(attachments, attachmentResponse)
	}

	log.Printf("Found %d attachments for document %s", len(attachments), documentID)
	c.JSON(http.StatusOK, attachments)
}

func createUserDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	
	var request struct {
		DocumentType string                 `json:"document_type"`
		Title        string                 `json:"title"`
		Fields       map[string]interface{} `json:"fields"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		log.Printf("Error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	
	// Validate required fields
	if request.DocumentType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Тип документа обязателен"})
		return
	}
	
	if request.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Название документа обязательно"})
		return
	}
	
	// Create new document
	newDoc := models.UserDocument{
		DocumentType: request.DocumentType,
		Title:        request.Title,
		Fields:       request.Fields,
		Status:       "draft",
		Attachments:  []models.DocumentAttachment{},
	}
	
	if newDoc.Fields == nil {
		newDoc.Fields = make(map[string]interface{})
	}
	
	// Add document to user
	if err := models.AddUserDocumentNew(user.ID, newDoc); err != nil {
		log.Printf("Error adding document: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при создании документа"})
		return
	}

	// Get updated user to get the document ID
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		log.Printf("Error getting updated user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении документа"})
		return
	}

	// Find the last document (newest one)
	var documentId string
	if len(updatedUser.Documents) > 0 {
		documentId = fmt.Sprintf("%d", len(updatedUser.Documents)-1) // Use index as ID
	}

	log.Printf("Document created successfully for user %s: %s", user.Username, request.Title)
	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "Документ успешно создан",
		"document_type": request.DocumentType,
		"title": request.Title,
		"document_id": documentId,
	})
}

func updateUserDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	documentID := c.Param("id")
	
	log.Printf("Updating document %s for user: %s", documentID, user.ID.Hex())

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(documentID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Get updated user data to access documents
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Get form data
	var updateData struct {
		Fields map[string]interface{} `json:"fields"`
	}

	// Try to parse JSON first
	if err := c.ShouldBindJSON(&updateData); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}

	log.Printf("Update data fields: %v", updateData.Fields)

	// Update document fields directly
	if len(updateData.Fields) > 0 {
		// Update the document fields directly
		updatedUser.Documents[docIndex].Fields = updateData.Fields
		updatedUser.Documents[docIndex].UpdatedAt = time.Now()
		
		// Save updated documents
		err = models.UpdateUserDocuments(user.ID, updatedUser.Documents)
		if err != nil {
			log.Printf("Error updating document fields: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить поля документа"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Документ успешно обновлен",
	})
}

func deleteUserDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	documentID := c.Param("id")
	
	log.Printf("Deleting document %s for user: %s (username: %s)", documentID, user.ID.Hex(), user.Username)

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(documentID, "%d", &docIndex); err != nil {
		log.Printf("ERROR: Invalid document ID format: %s", documentID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Get updated user data to access documents
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		log.Printf("ERROR: Failed to get user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		log.Printf("ERROR: Document index out of range: %d (total: %d)", docIndex, len(updatedUser.Documents))
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	documentToDelete := updatedUser.Documents[docIndex]
	log.Printf("Found document to delete: %s (type: %s, attachments: %d)", documentToDelete.Title, documentToDelete.DocumentType, len(documentToDelete.Attachments))

	// Delete associated files from disk
	for _, attachment := range documentToDelete.Attachments {
		if attachment.FilePath != "" {
			log.Printf("Deleting file: %s", attachment.FilePath)
			if err := os.Remove(attachment.FilePath); err != nil {
				log.Printf("WARNING: Failed to delete file %s: %v", attachment.FilePath, err)
				// Continue deletion even if file removal fails
			}
		}
	}

	// Remove document from slice
	updatedUser.Documents = append(updatedUser.Documents[:docIndex], updatedUser.Documents[docIndex+1:]...)
	
	// Update user documents in database
	if err := models.UpdateUserDocuments(user.ID, updatedUser.Documents); err != nil {
		log.Printf("ERROR: Failed to update user after document deletion: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при обновлении пользователя"})
		return
	}

	log.Printf("Successfully deleted document %d for user %s. Remaining documents: %d", docIndex, user.ID.Hex(), len(updatedUser.Documents))
	c.JSON(http.StatusOK, gin.H{"message": "Документ успешно удален"})
}

func addDocumentAttachmentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	documentID := c.Param("id")
	
	log.Printf("Adding attachment to document %s for user: %s", documentID, user.ID.Hex())

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(documentID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Get updated user data to access documents
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Debug: Log all form fields
	log.Printf("Request Method: %s", c.Request.Method)
	log.Printf("Content-Type: %s", c.Request.Header.Get("Content-Type"))
	
	// Parse multipart form first
	err = c.Request.ParseMultipartForm(99 << 20) // 99 MB max
	if err != nil {
		log.Printf("Error parsing multipart form: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка обработки формы"})
		return
	}
	
	// Log all form fields
	if c.Request.MultipartForm != nil {
		log.Printf("Form fields: %v", c.Request.MultipartForm.Value)
		log.Printf("Form files: %v", c.Request.MultipartForm.File)
	}

	// Get the uploaded file
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		log.Printf("Error getting uploaded file: %v", err)
		// Try alternative field names
		file, header, err = c.Request.FormFile("attachment")
		if err != nil {
			log.Printf("Error getting uploaded file as 'attachment': %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Файл не найден в запросе"})
			return
		}
	}
	defer file.Close()

	log.Printf("Uploading file: %s, size: %d", header.Filename, header.Size)

	// Create directory structure
	doc := updatedUser.Documents[docIndex]
	userDir := fmt.Sprintf("/root/data/%s", user.ID.Hex())
	docDir := filepath.Join(userDir, "documents", doc.DocumentType)
	
	if err := os.MkdirAll(docDir, 0755); err != nil {
		log.Printf("Error creating directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания директории"})
		return
	}

	// Generate unique filename
	fileExt := filepath.Ext(header.Filename)
	baseName := strings.TrimSuffix(header.Filename, fileExt)
	timestamp := time.Now().Unix()
	uniqueFilename := fmt.Sprintf("%s_%d%s", baseName, timestamp, fileExt)
	filePath := filepath.Join(docDir, uniqueFilename)

	// Create the file
	dst, err := os.Create(filePath)
	if err != nil {
		log.Printf("Error creating file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания файла"})
		return
	}
	defer dst.Close()

	// Copy file content
	if _, err := io.Copy(dst, file); err != nil {
		log.Printf("Error copying file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения файла"})
		return
	}

	// Create attachment record
	attachment := models.DocumentAttachment{
		ID:           primitive.NewObjectID(),
		FileName:     uniqueFilename,
		OriginalName: header.Filename,
		FilePath:     filePath,
		ContentType:  header.Header.Get("Content-Type"),
		Size:         header.Size,
		UploadedAt:   time.Now(),
	}

	// Add attachment to document in database
	err = models.AddDocumentAttachmentByIndex(user.ID, docIndex, attachment)
	if err != nil {
		log.Printf("Error adding attachment to database: %v", err)
		// Clean up file if database update fails
		os.Remove(filePath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения в базу данных"})
		return
	}

	log.Printf("Successfully added attachment: %s", uniqueFilename)
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Файл успешно загружен",
		"attachment": gin.H{
			"id":            attachment.ID.Hex(),
			"filename":      attachment.FileName,
			"original_name": attachment.OriginalName,
			"size":          attachment.Size,
			"content_type":  attachment.ContentType,
			"uploaded_at":   attachment.UploadedAt,
		},
	})
}

func removeDocumentAttachmentHandler(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Пользователь не авторизован"})
		return
	}

	userModel := user.(*models.User)
	docID := c.Param("id")
	attachmentID := c.Param("attachmentId")

	log.Printf("Removing attachment %s from document %s for user: %s", attachmentID, docID, userModel.ID.Hex())

	// Parse document index
	docIndex, err := strconv.Atoi(docID)
	if err != nil {
		log.Printf("Invalid document ID: %s", docID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Get current user data
	updatedUser, err := models.GetUserByID(userModel.ID.Hex())
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения пользователя"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		log.Printf("Document index out of bounds: %d", docIndex)
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Find attachment to get file path for deletion
	var attachmentPath string
	var attachmentIndex = -1
	doc := updatedUser.Documents[docIndex]
	
	for i, attachment := range doc.Attachments {
		if attachment.ID.Hex() == attachmentID {
			attachmentPath = attachment.FilePath
			attachmentIndex = i
			break
		}
	}

	if attachmentIndex == -1 {
		log.Printf("Attachment not found: %s", attachmentID)
		c.JSON(http.StatusNotFound, gin.H{"error": "Вложение не найдено"})
		return
	}

	// Convert attachment ID to ObjectID
	attachmentObjectID, err := primitive.ObjectIDFromHex(attachmentID)
	if err != nil {
		log.Printf("Invalid attachment ID: %s", attachmentID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID вложения"})
		return
	}

	// Remove attachment from database
	err = models.RemoveDocumentAttachmentByIndex(userModel.ID, docIndex, attachmentObjectID)
	if err != nil {
		log.Printf("Error removing attachment from database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления из базы данных"})
		return
	}

	// Remove physical file
	if attachmentPath != "" {
		if err := os.Remove(attachmentPath); err != nil {
			log.Printf("Warning: Could not remove file %s: %v", attachmentPath, err)
			// Don't return error here as database operation succeeded
		} else {
			log.Printf("Successfully removed file: %s", attachmentPath)
		}
	}

	log.Printf("Successfully removed attachment: %s", attachmentID)
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Вложение успешно удалено",
	})
}

func downloadDocumentAttachmentHandler(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Пользователь не авторизован"})
		return
	}

	userModel := user.(*models.User)
	docID := c.Param("id")
	attachmentID := c.Param("attachmentId")

	log.Printf("Downloading attachment %s from document %s for user: %s", attachmentID, docID, userModel.ID.Hex())

	// Parse document index
	docIndex, err := strconv.Atoi(docID)
	if err != nil {
		log.Printf("Invalid document ID: %s", docID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Get current user data
	updatedUser, err := models.GetUserByID(userModel.ID.Hex())
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения пользователя"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		log.Printf("Document index out of bounds: %d", docIndex)
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Find attachment
	var attachment *models.DocumentAttachment
	doc := updatedUser.Documents[docIndex]
	
	for i := range doc.Attachments {
		if doc.Attachments[i].ID.Hex() == attachmentID {
			attachment = &doc.Attachments[i]
			break
		}
	}

	if attachment == nil {
		log.Printf("Attachment not found: %s", attachmentID)
		c.JSON(http.StatusNotFound, gin.H{"error": "Вложение не найдено"})
		return
	}

	// DEBUG: Log attachment details for download
	log.Printf("Found attachment: ID=%s, FileName=%s, OriginalName=%s, FilePath=%s", 
		attachment.ID.Hex(), attachment.FileName, attachment.OriginalName, attachment.FilePath)

	// Check if file exists with fallback paths
	if _, err := os.Stat(attachment.FilePath); os.IsNotExist(err) {
		log.Printf("File not found: %s", attachment.FilePath)
		
		// Try alternative paths
		workingDir, _ := os.Getwd()
		log.Printf("Current working directory: %s", workingDir)
		
		// Try relative path
		relativePath := filepath.Join("./", attachment.FilePath)
		if _, err := os.Stat(relativePath); err == nil {
			log.Printf("Found file at relative path: %s", relativePath)
			attachment.FilePath = relativePath
		} else {
			// Try data directory path
			dataPath := filepath.Join("./data", userModel.ID.Hex(), "documents", doc.DocumentType, attachment.FileName)
			if _, err := os.Stat(dataPath); err == nil {
				log.Printf("Found file at data path: %s", dataPath)
				attachment.FilePath = dataPath
			} else {
				log.Printf("File not found in any location. Checked paths: %s, %s, %s", attachment.FilePath, relativePath, dataPath)
				c.JSON(http.StatusNotFound, gin.H{"error": "Файл не найден на диске"})
				return
			}
		}
	}

	// Set headers for download
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", attachment.OriginalName))
	c.Header("Content-Type", attachment.ContentType)
	c.Header("Content-Length", fmt.Sprintf("%d", attachment.Size))

	// Serve the file
	c.File(attachment.FilePath)
}

func previewDocumentAttachmentHandler(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Пользователь не авторизован"})
		return
	}

	userModel := user.(*models.User)
	docID := c.Param("id")
	attachmentID := c.Param("attachmentId")

	log.Printf("Previewing attachment %s from document %s for user: %s", attachmentID, docID, userModel.ID.Hex())

	// Parse document index
	docIndex, err := strconv.Atoi(docID)
	if err != nil {
		log.Printf("Invalid document ID: %s", docID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Get current user data
	updatedUser, err := models.GetUserByID(userModel.ID.Hex())
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения пользователя"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		log.Printf("Document index out of bounds: %d", docIndex)
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Find attachment
	var attachment *models.DocumentAttachment
	doc := updatedUser.Documents[docIndex]
	
	for i := range doc.Attachments {
		if doc.Attachments[i].ID.Hex() == attachmentID {
			attachment = &doc.Attachments[i]
			break
		}
	}

	if attachment == nil {
		log.Printf("Attachment not found: %s", attachmentID)
		c.JSON(http.StatusNotFound, gin.H{"error": "Вложение не найдено"})
		return
	}

	// Check if file exists
	if _, err := os.Stat(attachment.FilePath); os.IsNotExist(err) {
		log.Printf("File not found: %s", attachment.FilePath)
		c.JSON(http.StatusNotFound, gin.H{"error": "Файл не найден на диске"})
		return
	}

	// Set headers for inline display (preview)
	c.Header("Content-Type", attachment.ContentType)
	c.Header("Content-Length", fmt.Sprintf("%d", attachment.Size))
	
	// For images, PDFs and other previewable content, display inline
	if strings.HasPrefix(attachment.ContentType, "image/") || 
	   attachment.ContentType == "application/pdf" ||
	   strings.HasPrefix(attachment.ContentType, "text/") {
		c.Header("Content-Disposition", "inline")
	} else {
		// For other file types, still allow inline but browser will decide
		c.Header("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", attachment.OriginalName))
	}

	// Serve the file for preview
	c.File(attachment.FilePath)
}
