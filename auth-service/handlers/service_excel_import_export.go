package handlers

import (
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"auth-service/models"

	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

	// Access already verified by middleware, no additional check needed

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

	// Access already verified by middleware, no additional check needed

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

	// Redirect back to service page with success message
	successMessage := fmt.Sprintf("Импорт завершен: %d обработано, %d создано, %d добавлено в сервис, %d ролей обновлено",
		result.ProcessedRows, len(result.CreatedUsers), len(result.AddedToService), len(result.UpdatedRoles))

	if len(result.Errors) > 0 {
		successMessage += fmt.Sprintf(", %d ошибок", len(result.Errors))
	}

	// Store success message in session or as query parameter
	redirectURL := fmt.Sprintf("/services/%s?import_success=%s", serviceKey,
		url.QueryEscape(successMessage))

	c.Redirect(http.StatusFound, redirectURL)
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
		ProcessedRows:  0,
		CreatedUsers:   []models.UserImportExport{},
		AddedToService: []models.UserImportExport{},
		UpdatedRoles:   []models.UserImportExport{},
		Errors:         []models.ImportError{},
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

	// Initialize processed rows counter
	result.ProcessedRows = 0

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
			continue // Don't count rows with parse errors
		}

		// Skip empty rows
		if importUser.Username == "" && importUser.Email == "" {
			continue // Don't count empty rows
		}

		// Count only rows that we actually try to process
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
		// User exists - add to service or update roles

		// Check if service roles are specified for this user
		if serviceRoles, exists := importUser.ServiceRoles[service.Key]; exists && serviceRoles != "" {
			roles := strings.Split(serviceRoles, ",")
			rolesAdded := false

			// Check if user already has roles in this service
			existingRoles, err := models.GetUserServiceRolesFromCollection(existingUser.ID.Hex(), service.Key)
			if err != nil {
				log.Printf("WARNING: Failed to get existing roles for user %s: %v", existingUser.Username, err)
				existingRoles = []string{}
			}

			for _, role := range roles {
				role = strings.TrimSpace(role)
				if role != "" {
					// Check if this role already exists
					hasRole := false
					for _, existingRole := range existingRoles {
						if existingRole == role {
							hasRole = true
							break
						}
					}

					if hasRole {
						continue
					}

					userServiceRole := models.UserServiceRole{
						UserID:     existingUser.ID,
						ServiceKey: service.Key,
						RoleName:   role,
						IsActive:   true,
					}

					err := models.CreateUserServiceRole(userServiceRole)
					if err != nil {
						log.Printf("WARNING: Failed to create service role %s for existing user %s: %v", role, existingUser.Username, err)
					} else {
						rolesAdded = true
					}
				}
			}

			// Only add to result if new roles were actually added
			if rolesAdded {
				// Convert for result
				exportUser := models.UserImportExport{
					ID:           existingUser.ID.Hex(),
					Username:     existingUser.Username,
					Email:        existingUser.Email,
					FirstName:    existingUser.FirstName,
					LastName:     existingUser.LastName,
					MiddleName:   existingUser.MiddleName,
					Suffix:       existingUser.Suffix,
					Phone:        existingUser.Phone,
					Department:   existingUser.Department,
					Position:     existingUser.Position,
					Banned:       strconv.FormatBool(existingUser.IsBanned),
					ServiceRoles: importUser.ServiceRoles,
				}

				result.AddedToService = append(result.AddedToService, exportUser)
			}
		}

		return nil
	}
}

// createNewServiceUser creates a new user with service roles
func createNewServiceUser(importUser models.UserImportExport, adminUserID primitive.ObjectID, service *models.Service, result *models.ServiceImportResult) error {
	// Validate required fields - only email is required
	if importUser.Email == "" {
		return fmt.Errorf("email is required for new user")
	}

	// Auto-generate username from email if not provided
	if importUser.Username == "" {
		atIndex := strings.Index(importUser.Email, "@")
		if atIndex > 0 {
			importUser.Username = importUser.Email[:atIndex]
		} else {
			return fmt.Errorf("invalid email format: cannot extract username")
		}
	}

	// Auto-generate secure password if not provided
	if importUser.Password == "" {
		importUser.Password = models.GenerateSecurePassword()
	}

	log.Printf("Creating new service user %s with email %s", importUser.Username, importUser.Email)

	// Create user using CreateUserWithNames function with all fields
	userID, err := models.CreateUserWithNames(
		importUser.Username,
		importUser.Email,
		importUser.Password,
		importUser.LastName,
		importUser.FirstName,
		importUser.MiddleName,
		importUser.Suffix,
		[]string{}, // No system roles for now
	)
	if err != nil {
		log.Printf("ERROR SERVICE IMPORT: Failed to create user %s: %v", importUser.Username, err)
		return fmt.Errorf("failed to create user: %v", err)
	}

	// Update additional profile fields if provided
	if importUser.Phone != "" || importUser.Position != "" || importUser.Department != "" {
		err = models.UpdateUserProfile(
			userID,
			importUser.Email,
			importUser.LastName,
			importUser.FirstName,
			importUser.MiddleName,
			importUser.Suffix,
			importUser.Phone,
			importUser.Position,
			importUser.Department,
		)
		if err != nil {
			log.Printf("WARNING: Failed to update user profile: %v", err)
		}
	}

	// Set banned status if specified
	if importUser.Banned != "" {
		if banned, err := strconv.ParseBool(importUser.Banned); err == nil && banned {
			// TODO: Implement ban functionality if needed
		}
	}

	// Create service roles if specified
	if serviceRoles, exists := importUser.ServiceRoles[service.Key]; exists && serviceRoles != "" {
		roles := strings.Split(serviceRoles, ",")
		for _, role := range roles {
			role = strings.TrimSpace(role)
			if role != "" {
				userServiceRole := models.UserServiceRole{
					UserID:     userID,
					ServiceKey: service.Key,
					RoleName:   role,
					IsActive:   true,
				}

				err := models.CreateUserServiceRole(userServiceRole)
				if err != nil {
					log.Printf("WARNING: Failed to create service role %s for user %s: %v", role, importUser.Username, err)
				}
			}
		}
	}

	// Get the created user to populate result
	user, err := models.GetUserByID(userID.Hex())
	if err != nil {
		return fmt.Errorf("failed to get created user: %v", err)
	}

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

	return nil
}

// Note: addUserToService and updateServiceUserRoles functions removed for simplicity
// TODO: Implement proper service-specific role management

// GetUsersForServiceExport retrieves users for service export using batch queries.
func GetUsersForServiceExport(serviceKey string) ([]models.UserImportExport, error) {
	// 1. Get distinct user IDs with roles in this service (single aggregation)
	userIDs, err := models.GetDistinctUserIDsByServiceKey(serviceKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get user IDs for service: %v", err)
	}

	if len(userIDs) == 0 {
		return []models.UserImportExport{}, nil
	}

	// 2. Batch-load all users in one query
	users, err := models.GetUsersByIDs(userIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to batch-load users: %v", err)
	}

	// 3. Batch-load all service roles for these users in one query
	rolesMap, err := models.GetUserServiceRolesByUserIDs(userIDs, serviceKey)
	if err != nil {
		return nil, fmt.Errorf("failed to batch-load roles: %v", err)
	}

	// 4. Assemble export data
	exportUsers := make([]models.UserImportExport, 0, len(users))
	for _, user := range users {
		roles := rolesMap[user.ID]
		if len(roles) == 0 {
			continue
		}

		roleNames := make([]string, 0, len(roles))
		for _, r := range roles {
			roleNames = append(roleNames, r.RoleName)
		}

		exportUsers = append(exportUsers, models.UserImportExport{
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
				serviceKey: strings.Join(roleNames, ","),
			},
		})
	}

	log.Printf("Service export: %d users for service %s", len(exportUsers), serviceKey)
	return exportUsers, nil
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

// ServiceTemplateHandler generates an empty Excel template for service user imports
func ServiceTemplateHandler(c *gin.Context) {
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

	// Access already verified by middleware, no additional check needed

	// Get service info
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		log.Printf("Error getting service %s: %v", serviceKey, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		return
	}

	log.Printf("Service admin %s requested Excel template for service %s", currentUser.Username, serviceKey)

	// Create Excel file
	file := excelize.NewFile()
	defer file.Close()

	// Create empty Users sheet template for this service
	err = createServiceTemplateSheet(file, service)
	if err != nil {
		log.Printf("Error creating service template sheet: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create template sheet"})
		return
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("service_%s_users_template_%s.xlsx", serviceKey, timestamp)

	// Set headers for file download
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Transfer-Encoding", "binary")

	// Write file to response
	err = file.Write(c.Writer)
	if err != nil {
		log.Printf("Error writing Excel template file to response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate Excel template"})
		return
	}

	log.Printf("Successfully generated Excel template for service %s", serviceKey)
}

// ServiceImportPageHandler shows the import page for a service
func ServiceImportPageHandler(c *gin.Context) {
	// Get service key from URL
	serviceKey := c.Param("serviceKey")
	if serviceKey == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Service key is required"})
		return
	}

	// Get current user
	user, exists := c.Get("user")
	if !exists {
		c.HTML(http.StatusUnauthorized, "error.html", gin.H{"error": "User not authenticated"})
		return
	}
	currentUser := user.(*models.User)

	// Access already verified by middleware, no additional check needed

	// Get service info
	service, err := models.GetServiceByKey(serviceKey)
	if err != nil {
		log.Printf("Error getting service %s: %v", serviceKey, err)
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "Service not found"})
		return
	}

	// Check for success message
	successMsg := c.Query("success")

	c.HTML(http.StatusOK, "service_import.html", gin.H{
		"title":   "Импорт пользователей",
		"service": service,
		"user":    currentUser,
		"success": successMsg,
	})
}

// createServiceTemplateSheet creates an empty Excel template for service user imports
func createServiceTemplateSheet(file *excelize.File, service *models.Service) error {
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

	// Add example row with instructions
	exampleRow := 2
	file.SetCellValue(sheetName, fmt.Sprintf("A%d", exampleRow), "Оставить пустым для новых пользователей")
	file.SetCellValue(sheetName, fmt.Sprintf("B%d", exampleRow), "username_example")
	file.SetCellValue(sheetName, fmt.Sprintf("C%d", exampleRow), "user@example.com")
	file.SetCellValue(sheetName, fmt.Sprintf("D%d", exampleRow), "Иванов")
	file.SetCellValue(sheetName, fmt.Sprintf("E%d", exampleRow), "Иван")
	file.SetCellValue(sheetName, fmt.Sprintf("F%d", exampleRow), "Иванович")
	file.SetCellValue(sheetName, fmt.Sprintf("G%d", exampleRow), "")
	file.SetCellValue(sheetName, fmt.Sprintf("H%d", exampleRow), "+7 123 456 7890")
	file.SetCellValue(sheetName, fmt.Sprintf("I%d", exampleRow), "ИТ")
	file.SetCellValue(sheetName, fmt.Sprintf("J%d", exampleRow), "Разработчик")
	file.SetCellValue(sheetName, fmt.Sprintf("K%d", exampleRow), "password123")
	file.SetCellValue(sheetName, fmt.Sprintf("L%d", exampleRow), "false")
	file.SetCellValue(sheetName, fmt.Sprintf("M%d", exampleRow), "user")

	// Style example row
	exampleStyle, _ := file.NewStyle(&excelize.Style{
		Font: &excelize.Font{Italic: true, Color: "666666"},
	})

	file.SetCellStyle(sheetName, fmt.Sprintf("A%d", exampleRow), fmt.Sprintf("%s%d", getColumnName(len(allHeaders)), exampleRow), exampleStyle)

	// Auto-adjust column widths
	for i := 1; i <= len(allHeaders); i++ {
		colName := getColumnName(i)
		file.SetColWidth(sheetName, colName, colName, 15)
	}

	return nil
}
