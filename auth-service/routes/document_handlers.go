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

// getUserDocumentsHandler returns all documents for the current user
func getUserDocumentsHandler(c *gin.Context) {
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
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Document upload implementation moved to separate service"})
}

func deleteDocumentHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Document deletion implementation moved to separate service"})
}

func downloadDocumentHandler(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Document download implementation moved to separate service"})
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
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Document creation implementation moved to separate service"})
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
		Fields map[string]string `json:"fields"`
	}

	// Try to parse JSON first
	if err := c.ShouldBindJSON(&updateData); err != nil {
		// If JSON parsing fails, try form data
		updateData.Fields = make(map[string]string)
		
		// Get all form values that start with "field_"
		for key, values := range c.Request.PostForm {
			if strings.HasPrefix(key, "field_") && len(values) > 0 {
				fieldName := strings.TrimPrefix(key, "field_")
				updateData.Fields[fieldName] = values[0]
				log.Printf("Form field: %s = %s", fieldName, values[0])
			}
		}
	}

	log.Printf("Update data fields: %v", updateData.Fields)

	// Update document fields
	if len(updateData.Fields) > 0 {
		err = models.UpdateUserDocumentFields(user.ID, docIndex, updateData.Fields)
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
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Document deletion implementation moved to separate service"})
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
	userDir := fmt.Sprintf("/data/%s", user.ID.Hex())
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

	// Check if file exists
	if _, err := os.Stat(attachment.FilePath); os.IsNotExist(err) {
		log.Printf("File not found: %s", attachment.FilePath)
		c.JSON(http.StatusNotFound, gin.H{"error": "Файл не найден на диске"})
		return
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
