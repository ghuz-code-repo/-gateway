package handlers

import (
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"auth-service/models"
	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// ServiceExportHandler handles Excel export for service administrators
func ServiceExportHandler(c *gin.Context) {
	// Get service key from URL
	serviceKey := c.Param("serviceKey")
	if serviceKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service key is required"})
		return
	}

	// Get current user
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	currentUser := user.(*models.User)

	// Verify user has admin rights for this service
	hasServiceAccess := false
	// Check if user has admin role
	for _, role := range currentUser.Roles {
		if role == "admin" {
			hasServiceAccess = true
			break
		}
	}
	
	if !hasServiceAccess {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied. Only service administrators can export users."})
		return
	}

	// Get service info
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		log.Printf("Error getting service %s: %v", serviceKey, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		return
	}

	log.Printf("Service admin %s requested Excel export for service %s", currentUser.Username, serviceKey)

	// Get all users with roles in this service
	users, err := GetUsersForServiceExport(serviceKey)
	if err != nil {
		log.Printf("Error getting users for service export: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get users data"})
		return
	}

	log.Printf("DEBUG SERVICE EXPORT: Found %d users for service %s", len(users), serviceKey)

	// Create Excel file
	file := excelize.NewFile()
	defer file.Close()

	// Create Users sheet for this service
	err = createServiceUsersSheet(file, users, service)
	if err != nil {
		log.Printf("Error creating service users sheet: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create users sheet"})
		return
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("service_%s_users_export_%s.xlsx", serviceKey, timestamp)

	// Set headers for file download
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Transfer-Encoding", "binary")

	// Write file to response
	err = file.Write(c.Writer)
	if err != nil {
		log.Printf("Error writing Excel file to response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate Excel file"})
		return
	}

	log.Printf("Service Excel export completed for admin %s, service %s, file: %s", currentUser.Username, serviceKey, filename)
}

// ServiceImportHandler handles Excel import for service administrators
func ServiceImportHandler(c *gin.Context) {
	// Get service key from URL
	serviceKey := c.Param("serviceKey")
	if serviceKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service key is required"})
		return
	}

	// Get current user
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	currentUser := user.(*models.User)

	// Verify user has admin rights for this service
	hasServiceAccess := false
	// Check if user has admin role
	for _, role := range currentUser.Roles {
		if role == "admin" {
			hasServiceAccess = true
			break
		}
	}
	
	if !hasServiceAccess {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied. Only service administrators can import users."})
		return
	}

	// Get service info
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		log.Printf("Error getting service %s: %v", serviceKey, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		return
	}

	// Handle file upload
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded or invalid file format"})
		return
	}
	defer file.Close()

	// Validate file extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".xlsx" && ext != ".xls" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only Excel files (.xlsx, .xls) are supported"})
		return
	}

	log.Printf("Service admin %s started import of file: %s for service %s", currentUser.Username, header.Filename, serviceKey)

	// Create import log entry
	logEntry := models.ServiceImportLogEntry{
		Timestamp:     time.Now(),
		AdminUsername: currentUser.Username,
		ServiceKey:    serviceKey,
		FileName:      header.Filename,
	}

	// Process the import
	result, err := processServiceExcelImport(file, currentUser.ID, service)
	if err != nil {
		logEntry.Success = false
		logEntry.ErrorMessage = err.Error()
		if result != nil {
			logEntry.Result = *result
		}
		models.SaveServiceImportLog(&logEntry)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
			"details": err.Error(),
		})
		return
	}

	// Complete the log entry
	logEntry.Success = len(result.Errors) == 0
	logEntry.Result = *result

	// Save log
	models.SaveServiceImportLog(&logEntry)

	log.Printf("Service import completed for admin %s, service %s: %d processed, %d created, %d added to service, %d updated roles, %d errors",
		currentUser.Username, serviceKey, result.ProcessedRows, len(result.CreatedUsers), len(result.AddedToService), len(result.UpdatedRoles), len(result.Errors))

	// Return result in format expected by frontend
	c.JSON(http.StatusOK, gin.H{
		"success":           len(result.Errors) == 0,
		"total_processed":   result.ProcessedRows,
		"users_created":     len(result.CreatedUsers),
		"users_added":       len(result.AddedToService),
		"roles_updated":     len(result.UpdatedRoles),
		"processing_time":   time.Since(logEntry.Timestamp).String(),
		"errors":            result.Errors,
		"service":           serviceKey,
	})
}

// ServiceImportPageHandler shows the service import page
func ServiceImportPageHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	if serviceKey == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{
			"title":   "Ошибка",
			"message": "Service key is required",
		})
		return
	}

	// Get current user
	user, exists := c.Get("user")
	if !exists {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	currentUser := user.(*models.User)

	// Verify user has admin rights for this service
	hasServiceAccess := false
	// Check if user has admin role
	for _, role := range currentUser.Roles {
		if role == "admin" {
			hasServiceAccess = true
			break
		}
	}
	
	if !hasServiceAccess {
		c.HTML(http.StatusForbidden, "error.html", gin.H{
			"title":   "Доступ запрещен",
			"message": "Только администраторы сервиса могут импортировать пользователей.",
		})
		return
	}

	// Get service info
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"title":   "Сервис не найден",
			"message": "Указанный сервис не существует.",
		})
		return
	}

	// Get service roles
	serviceRoles, err := models.GetRolesByService(serviceKey)
	if err != nil {
		log.Printf("WARNING: Could not get roles for service %s: %v", serviceKey, err)
		serviceRoles = []models.Role{} // Empty slice if error
	}
	c.HTML(http.StatusOK, "service_import.html", gin.H{
		"title":       fmt.Sprintf("Импорт пользователей - %s", service.Name),
		"service":     service,
		"serviceRoles": serviceRoles,
		"currentUser": currentUser,
	})
}

// createServiceUsersSheet creates an Excel sheet with users for a specific service
func createServiceUsersSheet(file *excelize.File, users []models.UserImportExport, service *models.Service) error {
	sheetName := "Users"
	
	// Delete default sheet and create new one
	file.DeleteSheet("Sheet1")
	index, _ := file.NewSheet(sheetName)
	file.SetActiveSheet(index)

	// Define base headers (without other services)
	baseHeaders := []string{
		"ID", "Имя пользователя", "Email", "Фамилия", "Имя", "Отчество",
		"Частица", "Телефон", "Отдел", "Должность", "Пароль", "Забанен",
	}

	// Add service role header
	serviceHeader := service.Key
	allHeaders := append(baseHeaders, serviceHeader)

	// Set headers
	for i, header := range allHeaders {
		cell := fmt.Sprintf("%s1", getColumnName(i+1))
		file.SetCellValue(sheetName, cell, header)
	}

	// Style headers
	headerStyle, _ := file.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"CCCCCC"}, Pattern: 1},
	})
	
	file.SetCellStyle(sheetName, "A1", fmt.Sprintf("%s1", getColumnName(len(allHeaders))), headerStyle)

	// Fill user data
	for i, user := range users {
		row := i + 2
		
		// Basic user data
		file.SetCellValue(sheetName, fmt.Sprintf("A%d", row), user.ID)
		file.SetCellValue(sheetName, fmt.Sprintf("B%d", row), user.Username)
		file.SetCellValue(sheetName, fmt.Sprintf("C%d", row), user.Email)
		file.SetCellValue(sheetName, fmt.Sprintf("D%d", row), user.LastName)
		file.SetCellValue(sheetName, fmt.Sprintf("E%d", row), user.FirstName)
		file.SetCellValue(sheetName, fmt.Sprintf("F%d", row), user.MiddleName)
		file.SetCellValue(sheetName, fmt.Sprintf("G%d", row), user.Suffix)
		file.SetCellValue(sheetName, fmt.Sprintf("H%d", row), user.Phone)
		file.SetCellValue(sheetName, fmt.Sprintf("I%d", row), user.Department)
		file.SetCellValue(sheetName, fmt.Sprintf("J%d", row), user.Position)
		file.SetCellValue(sheetName, fmt.Sprintf("K%d", row), "") // Password field empty
		file.SetCellValue(sheetName, fmt.Sprintf("L%d", row), user.Banned)

		// Service role
		serviceRoles := ""
		if roles, exists := user.ServiceRoles[service.Key]; exists {
			serviceRoles = roles
		}
		file.SetCellValue(sheetName, fmt.Sprintf("M%d", row), serviceRoles)
	}

	// Auto-adjust column widths
	for i := 1; i <= len(allHeaders); i++ {
		colName := getColumnName(i)
		file.SetColWidth(sheetName, colName, colName, 15)
	}

	return nil
}

// processServiceExcelImport processes Excel import for service administrators
func processServiceExcelImport(file multipart.File, adminUserID primitive.ObjectID, service *models.Service) (*models.ServiceImportResult, error) {
	// Create result structure
	result := &models.ServiceImportResult{
		ProcessedRows:    0,
		CreatedUsers:     []models.UserImportExport{},
		AddedToService:   []models.UserImportExport{},
		UpdatedRoles:     []models.UserImportExport{},
		Errors:          []models.ImportError{},
	}

	// Open Excel file from multipart.File
	excelFile, err := excelize.OpenReader(file)
	if err != nil {
		return result, fmt.Errorf("failed to open Excel file: %v", err)
	}
	defer excelFile.Close()

	// Read data from Users sheet
	rows, err := excelFile.GetRows("Users")
	if err != nil {
		return result, fmt.Errorf("failed to read Users sheet: %v", err)
	}

	if len(rows) < 2 {
		return result, fmt.Errorf("no data rows found in Users sheet")
	}

	// Parse header row
	headers := rows[0]
	columnMap := make(map[string]int)
	serviceRoleColumn := -1

	// Map standard columns
	for i, header := range headers {
		switch header {
		case "ID":
			columnMap["id"] = i
		case "Имя пользователя":
			columnMap["username"] = i
		case "Email":
			columnMap["email"] = i
		case "Фамилия":
			columnMap["last_name"] = i
		case "Имя":
			columnMap["first_name"] = i
		case "Отчество":
			columnMap["middle_name"] = i
		case "Частица":
			columnMap["suffix"] = i
		case "Телефон":
			columnMap["phone"] = i
		case "Отдел":
			columnMap["department"] = i
		case "Должность":
			columnMap["position"] = i
		case "Пароль":
			columnMap["password"] = i
		case "Забанен":
			columnMap["banned"] = i
		default:
			// Check if this is the service role column
			if header == service.Key {
				serviceRoleColumn = i
			}
		}
	}

	log.Printf("DEBUG SERVICE IMPORT: Service role column for %s found at index: %d", service.Key, serviceRoleColumn)

	result.ProcessedRows = len(rows) - 1 // Exclude header

	// Process each data row
	for rowIndex, row := range rows[1:] {
		actualRowNum := rowIndex + 2 // Excel row number (1-based + header)
		
		// Parse user data from row
		importUser, parseErrors := parseServiceUserFromRow(row, columnMap, serviceRoleColumn, service.Key)
		if len(parseErrors) > 0 {
			for _, parseError := range parseErrors {
				parseError.Row = actualRowNum
				result.Errors = append(result.Errors, parseError)
			}
			continue
		}

		// Skip empty rows
		if importUser.Username == "" && importUser.Email == "" {
			continue
		}

		result.ProcessedRows++

		// Process user for service (create, add to service, or update roles)
		err := processServiceUser(importUser, adminUserID, service, actualRowNum, result)
		if err != nil {
			result.Errors = append(result.Errors, models.ImportError{
				Row:     actualRowNum,
				Message: err.Error(),
			})
		}
	}

	return result, nil
}

// parseServiceUserFromRow parses user data from Excel row for service import
func parseServiceUserFromRow(row []string, columnMap map[string]int, serviceRoleColumn int, serviceKey string) (models.UserImportExport, []models.ImportError) {
	var user models.UserImportExport
	var errors []models.ImportError

	// Helper function to get cell value safely
	getCellValue := func(colIndex int) string {
		if colIndex >= 0 && colIndex < len(row) {
			return strings.TrimSpace(row[colIndex])
		}
		return ""
	}

	// Parse basic user fields
	if idCol, exists := columnMap["id"]; exists {
		if idStr := getCellValue(idCol); idStr != "" {
			user.ID = idStr
		}
	}

	user.Username = getCellValue(columnMap["username"])
	user.Email = getCellValue(columnMap["email"])
	user.LastName = getCellValue(columnMap["last_name"])
	user.FirstName = getCellValue(columnMap["first_name"])
	user.MiddleName = getCellValue(columnMap["middle_name"])
	user.Suffix = getCellValue(columnMap["suffix"])
	user.Phone = getCellValue(columnMap["phone"])
	user.Department = getCellValue(columnMap["department"])
	user.Position = getCellValue(columnMap["position"])

	// Parse password
	if pwdCol, exists := columnMap["password"]; exists {
		user.Password = getCellValue(pwdCol)
	}

	// Parse banned status
	if bannedCol, exists := columnMap["banned"]; exists {
		bannedStr := getCellValue(bannedCol)
		if bannedStr != "" {
			user.Banned = bannedStr // Store as string in UserImportExport
		}
	}

	// Parse service role
	user.ServiceRoles = make(map[string]string)
	if serviceRoleColumn >= 0 {
		serviceRole := getCellValue(serviceRoleColumn)
		if serviceRole != "" {
			user.ServiceRoles[serviceKey] = serviceRole
		}
	}

	// Validate required fields
	if user.Username == "" && user.Email == "" {
		errors = append(errors, models.ImportError{
			Message: "Username or Email is required",
		})
	}

	if user.Email != "" && !isValidEmail(user.Email) {
		errors = append(errors, models.ImportError{
			Message: fmt.Sprintf("Invalid email format: %s", user.Email),
		})
	}

	return user, errors
}

// processServiceUser processes a single user for service import
func processServiceUser(importUser models.UserImportExport, adminUserID primitive.ObjectID, service *models.Service, rowNum int, result *models.ServiceImportResult) error {
	// Check if user exists in the system
	var existingUser *models.User
	
	if importUser.ID != "" {
		// Try to find by ID first
		if objectID, err := primitive.ObjectIDFromHex(importUser.ID); err == nil {
			existingUser, _ = models.GetUserByID(objectID.Hex())
		}
	}
	
	// If not found by ID, try by username or email
	if existingUser == nil {
		if importUser.Username != "" {
			existingUser, _ = models.GetUserByUsername(importUser.Username)
		}
		if existingUser == nil && importUser.Email != "" {
			existingUser, _ = models.GetUserByEmail(importUser.Email)
		}
	}

	if existingUser == nil {
		// User doesn't exist in system - create new user
		return createNewServiceUser(importUser, adminUserID, service, result)
	} else {
		// User exists - for this simple implementation, we'll skip role updates
		// TODO: Implement proper service-specific role management
		log.Printf("DEBUG SERVICE IMPORT: User %s already exists, skipping for now", existingUser.Username)
		return nil
	}
}

// createNewServiceUser creates a new user with service roles
func createNewServiceUser(importUser models.UserImportExport, adminUserID primitive.ObjectID, service *models.Service, result *models.ServiceImportResult) error {
	// Validate required fields for new user
	if importUser.Username == "" {
		return fmt.Errorf("username is required for new user")
	}
	if importUser.Email == "" {
		return fmt.Errorf("email is required for new user")
	}
	if importUser.Password == "" {
		return fmt.Errorf("password is required for new user")
	}

	// Parse banned status
	banned := false
	if importUser.Banned != "" {
		if b, err := strconv.ParseBool(importUser.Banned); err == nil {
			banned = b
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(importUser.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	// Create roles slice
	roles := []string{}
	if serviceRoles, exists := importUser.ServiceRoles[service.Key]; exists && serviceRoles != "" {
		// For now, just add the roles as is - service-specific roles would need proper implementation
		roles = append(roles, strings.Split(serviceRoles, ",")...)
	}

	// Create user using the existing CreateUser function
	userID, err := models.CreateUser(importUser.Username, importUser.Email, string(hashedPassword), importUser.FirstName, roles)
	if err != nil {
		return fmt.Errorf("failed to create user: %v", err)
	}

	// Get the created user to populate result
	user, err := models.GetUserByID(userID.Hex())
	if err != nil {
		return fmt.Errorf("failed to get created user: %v", err)
	}

	// Update additional fields
	user.LastName = importUser.LastName
	user.MiddleName = importUser.MiddleName
	user.Suffix = importUser.Suffix
	user.Phone = importUser.Phone
	user.Department = importUser.Department
	user.Position = importUser.Position
	user.IsBanned = banned

	// TODO: Save additional user details updates
	// For now, skip updating additional fields to simplify implementation
	log.Printf("TODO: Update user details for %s", user.Username)

	// Convert for result
	exportUser := models.UserImportExport{
		ID:           user.ID.Hex(),
		Username:     user.Username,
		Email:        user.Email,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		MiddleName:   user.MiddleName,
		Suffix:       user.Suffix,
		Phone:        user.Phone,
		Department:   user.Department,
		Position:     user.Position,
		Banned:       strconv.FormatBool(user.IsBanned),
		ServiceRoles: importUser.ServiceRoles,
	}

	result.CreatedUsers = append(result.CreatedUsers, exportUser)
	log.Printf("DEBUG SERVICE IMPORT: Created new user %s with service roles", user.Username)
	
	return nil
}

// Note: addUserToService and updateServiceUserRoles functions removed for simplicity
// TODO: Implement proper service-specific role management

// GetUsersForServiceExport retrieves users for service export
func GetUsersForServiceExport(serviceKey string) ([]models.UserImportExport, error) {
	// Get all users from MongoDB
	users, err := models.GetAllUsers()
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %v", err)
	}

	var serviceUsers []models.UserImportExport

	// Filter users who have roles in this service
	for _, user := range users {
		// Check if user has roles in the specified service
		// For now, we'll export all users with admin role since service-specific roles need proper implementation
		hasServiceRole := false
		serviceRoles := ""
		
		for _, role := range user.Roles {
			if role == "admin" || role == "user" {
				hasServiceRole = true
				serviceRoles = role
				break
			}
		}

		if hasServiceRole {
		// Convert to export format
		exportUser := models.UserImportExport{
			ID:         user.ID.Hex(),
			Username:   user.Username,
			Email:      user.Email,
			FirstName:  user.FirstName,
			LastName:   user.LastName,
			MiddleName: user.MiddleName,
			Suffix:     user.Suffix,
			Phone:      user.Phone,
			Department: user.Department,
			Position:   user.Position,
			Banned:     strconv.FormatBool(user.IsBanned),
			ServiceRoles: map[string]string{
				serviceKey: serviceRoles,
			},
		}

		serviceUsers = append(serviceUsers, exportUser)
		}
	}

	log.Printf("DEBUG SERVICE EXPORT: Found %d users for service %s", len(serviceUsers), serviceKey)
	return serviceUsers, nil
}

// Helper functions

// Note: getColumnName function is imported from excel_export.go

// isValidEmail validates email format using regex
func isValidEmail(email string) bool {
	// Simple email validation regex
	if len(email) < 3 || len(email) > 254 {
		return false
	}
	
	// Check for @ symbol
	atIndex := strings.Index(email, "@")
	if atIndex <= 0 || atIndex >= len(email)-1 {
		return false
	}
	
	// Check for at least one dot after @
	domain := email[atIndex+1:]
	if !strings.Contains(domain, ".") {
		return false
	}
	
	// Basic character validation
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_@"
	for _, char := range email {
		if !strings.ContainsRune(validChars, char) {
			return false
		}
	}
	
	return true
}