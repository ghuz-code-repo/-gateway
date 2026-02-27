package handlers

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"auth-service/models"
)

// ImportUsersFromExcel handles Excel file upload and import
func ImportUsersFromExcel(c *gin.Context) {
	// Get current user for logging
	currentUser, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	user := currentUser.(*models.User)

	// Create import log entry
	logEntry := models.ImportLogEntry{
		Timestamp:     time.Now(),
		AdminUsername: user.Username,
		Result: models.ImportResult{
			ProcessedRows:      0,
			CreatedUsers:       []models.UserImportExport{},
			UpdatedUsers:       []models.UserImportExport{},
			DeletedUsers:       []models.UserImportExport{},
			BannedUsers:        []models.UserImportExport{},
			UnbannedUsers:      []models.UserImportExport{},
			Errors:             []models.ImportError{},
			EmailNotifications: []models.EmailNotification{},
		},
	}

	// Get uploaded file
	fileHeader, err := c.FormFile("file")
	if err != nil {
		logEntry.Success = false
		logEntry.ErrorMessage = "No file uploaded"
		models.SaveImportLog(&logEntry)
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}

	logEntry.FileName = fileHeader.Filename
	log.Printf("User %s started import of file: %s", user.Username, fileHeader.Filename)

	// Open uploaded file
	file, err := fileHeader.Open()
	if err != nil {
		logEntry.Success = false
		logEntry.ErrorMessage = fmt.Sprintf("Failed to open file: %v", err)
		models.SaveImportLog(&logEntry)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to open file"})
		return
	}
	defer file.Close()

	// Read Excel file
	excelFile, err := excelize.OpenReader(file)
	if err != nil {
		logEntry.Success = false
		logEntry.ErrorMessage = fmt.Sprintf("Failed to read Excel file: %v", err)
		models.SaveImportLog(&logEntry)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Excel file"})
		return
	}
	defer excelFile.Close()

	// Process the import
	result, err := processExcelImport(excelFile, user.ID)
	if err != nil {
		logEntry.Success = false
		logEntry.ErrorMessage = err.Error()
		if result != nil {
			logEntry.Result = *result
		}
		models.SaveImportLog(&logEntry)
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
	models.SaveImportLog(&logEntry)

	log.Printf("Import completed for user %s: %d processed, %d created, %d updated, %d deleted, %d banned, %d unbanned, %d errors",
		user.Username, result.ProcessedRows, len(result.CreatedUsers), len(result.UpdatedUsers),
		len(result.DeletedUsers), len(result.BannedUsers), len(result.UnbannedUsers), len(result.Errors))

	// Return result in format expected by frontend
	c.JSON(http.StatusOK, gin.H{
		"success":         len(result.Errors) == 0,
		"total_processed": result.ProcessedRows,
		"users_created":   len(result.CreatedUsers),
		"users_updated":   len(result.UpdatedUsers),
		"users_deleted":   len(result.DeletedUsers),
		"users_banned":    len(result.BannedUsers),
		"users_unbanned":  len(result.UnbannedUsers),
		"users_skipped":   0, // We don't currently track skipped users
		"processing_time": time.Since(logEntry.Timestamp).String(),
		"errors":          result.Errors,
		"dry_run":         false,
		"result":          result,
	})
}

// processExcelImport processes the Excel file and imports users
func processExcelImport(file *excelize.File, adminUserID primitive.ObjectID) (*models.ImportResult, error) {
	result := &models.ImportResult{
		ProcessedRows:      0,
		CreatedUsers:       []models.UserImportExport{},
		UpdatedUsers:       []models.UserImportExport{},
		DeletedUsers:       []models.UserImportExport{},
		BannedUsers:        []models.UserImportExport{},
		UnbannedUsers:      []models.UserImportExport{},
		Errors:             []models.ImportError{},
		EmailNotifications: []models.EmailNotification{},
	}

	// Get Users sheet
	usersSheet := "Users"
	sheets := file.GetSheetList()
	sheetExists := false
	for _, sheet := range sheets {
		if sheet == usersSheet {
			sheetExists = true
			break
		}
	}

	if !sheetExists {
		return result, fmt.Errorf("Users sheet not found in Excel file")
	}

	// Read all rows from Users sheet
	rows, err := file.GetRows(usersSheet)
	if err != nil {
		return result, fmt.Errorf("failed to read Users sheet: %v", err)
	}

	if len(rows) < 2 {
		return result, fmt.Errorf("no data rows found in Users sheet")
	}

	// Parse header row to understand column structure
	headers := rows[0]
	columnMap := make(map[string]int)
	serviceColumns := make(map[string]int) // service name -> column index

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
		case "Удалить":
			columnMap["delete_user"] = i
		default:
			// Check if this is a service column (looking by Key since export uses service.Key for headers)
			if service, err := models.GetServiceByKey(header); err == nil {
				serviceColumns[service.Key] = i
			}
		}
	}

	result.ProcessedRows = len(rows) - 1 // Exclude header

	// Process each data row
	for rowIndex, row := range rows[1:] {
		actualRowNum := rowIndex + 2 // Excel row number (1-based + header)

		// Parse user data from row
		importUser, parseErrors := parseUserFromRow(row, columnMap, serviceColumns)
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

		// Process user (create or update)
		err := processUser(importUser, adminUserID, actualRowNum, result)
		if err != nil {
			result.Errors = append(result.Errors, models.ImportError{
				Row:     actualRowNum,
				Message: err.Error(),
			})
		}
	}

	return result, nil
}

// parseUserFromRow parses a user from an Excel row
func parseUserFromRow(row []string, columnMap map[string]int, serviceColumns map[string]int) (models.UserImportExport, []models.ImportError) {
	user := models.UserImportExport{
		ServiceRoles: make(map[string]string),
	}
	var errors []models.ImportError

	// Helper function to get cell value safely
	getCellValue := func(colIndex int) string {
		if colIndex >= 0 && colIndex < len(row) {
			return strings.TrimSpace(row[colIndex])
		}
		return ""
	}

	// Parse basic fields
	user.ID = getCellValue(columnMap["id"])
	user.Username = getCellValue(columnMap["username"])
	user.Email = getCellValue(columnMap["email"])
	user.LastName = getCellValue(columnMap["last_name"])
	user.FirstName = getCellValue(columnMap["first_name"])
	user.MiddleName = getCellValue(columnMap["middle_name"])
	user.Suffix = getCellValue(columnMap["suffix"])
	user.Phone = getCellValue(columnMap["phone"])
	user.Department = getCellValue(columnMap["department"])
	user.Position = getCellValue(columnMap["position"])
	user.Password = getCellValue(columnMap["password"])
	user.Banned = getCellValue(columnMap["banned"])
	user.DeleteUser = getCellValue(columnMap["delete_user"])

	// Validate required fields
	if user.Username == "" {
		errors = append(errors, models.ImportError{
			Field:   "Имя пользователя",
			Message: "Имя пользователя обязательно",
		})
	}

	if user.Email == "" {
		errors = append(errors, models.ImportError{
			Field:   "Email",
			Message: "Email обязателен",
		})
	}

	// Parse service roles - process ALL service columns, including empty ones
	for serviceKey, colIndex := range serviceColumns {
		rolesStr := getCellValue(colIndex)

		if rolesStr != "" {
			// Clean up roles string and validate
			roles := strings.Split(rolesStr, ",")
			validRoles := []string{}

			for _, role := range roles {
				role = strings.TrimSpace(role)
				if role != "" {
					validRoles = append(validRoles, role)
				}
			}

			user.ServiceRoles[serviceKey] = strings.Join(validRoles, ",")
		} else {
			// Empty roles string means remove all roles for this service
			user.ServiceRoles[serviceKey] = ""
		}
	}

	return user, errors
}

// processUser creates or updates a user based on import data
func processUser(importUser models.UserImportExport, adminUserID primitive.ObjectID, rowNum int, result *models.ImportResult) error {
	var existingUser *models.User
	var err error
	isNewUser := false

	// Check if user should be deleted
	if strings.ToLower(strings.TrimSpace(importUser.DeleteUser)) == "true" {
		return processUserDeletion(importUser, result)
	}

	// Try to find existing user
	if importUser.ID != "" {
		// Try to find by ID first
		if objectID, err := primitive.ObjectIDFromHex(importUser.ID); err == nil {
			existingUser, err = models.GetUserByID(objectID.Hex())
			if err != nil {
				log.Printf("User with ID %s not found, will search by username/email", importUser.ID)
			}
		}
	}

	// If not found by ID, try by username or email
	if existingUser == nil {
		existingUser, err = models.GetUserByUsername(importUser.Username)
		if err != nil {
			existingUser, err = models.GetUserByEmail(importUser.Email)
			if err != nil {
				// User doesn't exist, will create new
				isNewUser = true
				existingUser = nil // explicitly set to nil
			}
		}
	}

	// Additional safety check
	if existingUser == nil {
		isNewUser = true
	}

	if isNewUser {
		// Create new user
		err := createNewUser(importUser, adminUserID, result)
		if err != nil {
			return err
		}
	} else {
		// Update existing user
		err := updateExistingUser(existingUser, importUser, adminUserID, result)
		if err != nil {
			return err
		}
	}

	return nil
}

// createNewUser creates a new user from import data
func createNewUser(importUser models.UserImportExport, adminUserID primitive.ObjectID, result *models.ImportResult) error {
	// Generate secure password if not provided
	password := importUser.Password
	if password == "" {
		password = models.GenerateSecurePassword()
	}

	log.Printf("Creating new user %s with email %s", importUser.Username, importUser.Email)

	// Create user
	userID, err := models.CreateUserWithNames(
		importUser.Username,
		importUser.Email,
		password,
		importUser.LastName,
		importUser.FirstName,
		importUser.MiddleName,
		importUser.Suffix,
		[]string{}, // will add service roles separately
	)
	if err != nil {
		return fmt.Errorf("failed to create user: %v", err)
	}

	// Update additional fields
	err = models.UpdateUserProfile(userID, importUser.Email, importUser.LastName, importUser.FirstName,
		importUser.MiddleName, importUser.Suffix, importUser.Phone, importUser.Position, importUser.Department)
	if err != nil {
		log.Printf("Warning: Failed to update profile for new user %s: %v", importUser.Username, err)
	}

	// Add service roles
	_, err = updateUserServiceRoles(userID, importUser.ServiceRoles, adminUserID)
	if err != nil {
		log.Printf("Warning: Failed to update service roles for new user %s: %v", importUser.Username, err)
	}

	// Add to result
	importUser.ID = userID.Hex()
	result.CreatedUsers = append(result.CreatedUsers, importUser)

	// Send email notification (non-blocking - errors are logged but don't stop import)
	// Use the original password variable, not importUser.Password which might be modified
	emailResult := sendUserNotification(importUser.Email, "created", password)
	result.EmailNotifications = append(result.EmailNotifications, emailResult)

	// Log email failure but DON'T stop the import process
	// The notification service already stores failed emails with retry mechanism
	if !emailResult.Success {
		log.Printf("⚠️ WARNING: Email notification failed for user %s: %s",
			importUser.Email, emailResult.ErrorMessage)
		log.Printf("⚠️ User created successfully, but notification was not sent.")
		log.Printf("⚠️ Failed email is stored in notification service and will be retried automatically.")
	} else {
		log.Printf("✅ Email notification sent successfully to %s", importUser.Email)
	}

	return nil
}

// updateExistingUser updates an existing user with import data
func updateExistingUser(existingUser *models.User, importUser models.UserImportExport, adminUserID primitive.ObjectID, result *models.ImportResult) error {
	if existingUser == nil {
		return fmt.Errorf("existingUser is nil - this should not happen")
	}

	log.Printf("Updating existing user %s (ID: %s) with email %s", existingUser.Username, existingUser.ID.Hex(), importUser.Email)

	hasChanges := false

	// Check if profile data changed
	if existingUser.FirstName != importUser.FirstName ||
		existingUser.LastName != importUser.LastName ||
		existingUser.MiddleName != importUser.MiddleName ||
		existingUser.Suffix != importUser.Suffix ||
		existingUser.Phone != importUser.Phone ||
		existingUser.Department != importUser.Department ||
		existingUser.Position != importUser.Position ||
		existingUser.Email != importUser.Email {

		hasChanges = true

		// Update profile
		err := models.UpdateUserProfile(existingUser.ID, importUser.Email, importUser.LastName,
			importUser.FirstName, importUser.MiddleName, importUser.Suffix, importUser.Phone,
			importUser.Position, importUser.Department)
		if err != nil {
			return fmt.Errorf("failed to update user profile: %v", err)
		}
	}

	// Update password if provided
	if importUser.Password != "" {
		err := models.ChangeUserPassword(existingUser.ID, importUser.Password)
		if err != nil {
			return fmt.Errorf("failed to update password: %v", err)
		}
		hasChanges = true
	}

	// Update service roles
	rolesChanged, err := updateUserServiceRoles(existingUser.ID, importUser.ServiceRoles, adminUserID)
	if err != nil {
		log.Printf("Warning: Failed to update service roles for user %s: %v", existingUser.Username, err)
	}
	if rolesChanged {
		hasChanges = true
	}

	// Process ban status change
	if importUser.Banned != "" {
		banStatusChanged, err := processBanStatusChange(existingUser, importUser, result)
		if err != nil {
			log.Printf("Warning: Failed to change ban status for user %s: %v", existingUser.Username, err)
		} else if banStatusChanged {
			hasChanges = true
		}
	}

	if hasChanges {
		// Add to result
		importUser.ID = existingUser.ID.Hex()
		importUser.PasswordChanged = importUser.Password != ""
		result.UpdatedUsers = append(result.UpdatedUsers, importUser)

		// Send email notification (CRITICAL: email must be sent)
		// Include password in notification ONLY if it was actually updated
		passwordForEmail := ""
		passwordChanged := importUser.Password != ""
		if passwordChanged {
			// Store original password before any modifications to importUser
			passwordForEmail = importUser.Password
		}

		// Only send email if significant changes occurred (not just role updates)
		profileChanged := existingUser.FirstName != importUser.FirstName ||
			existingUser.LastName != importUser.LastName ||
			existingUser.MiddleName != importUser.MiddleName ||
			existingUser.Suffix != importUser.Suffix ||
			existingUser.Phone != importUser.Phone ||
			existingUser.Department != importUser.Department ||
			existingUser.Position != importUser.Position ||
			existingUser.Email != importUser.Email ||
			passwordChanged

		if profileChanged {
			emailResult := sendUserNotification(importUser.Email, "updated", passwordForEmail)
			result.EmailNotifications = append(result.EmailNotifications, emailResult)

			// Log email failure but DON'T stop the import process
			// The notification service already stores failed emails with retry mechanism
			if !emailResult.Success {
				log.Printf("⚠️ WARNING: Email notification failed for user %s: %s",
					importUser.Email, emailResult.ErrorMessage)
				log.Printf("⚠️ User updated successfully, but notification was not sent.")
				log.Printf("⚠️ Failed email is stored in notification service and will be retried automatically.")
			} else {
				log.Printf("✅ Email notification sent successfully to %s", importUser.Email)
			}
		}
	}

	return nil
}

// updateUserServiceRoles updates user's service roles
func updateUserServiceRoles(userID primitive.ObjectID, serviceRoles map[string]string, adminUserID primitive.ObjectID) (bool, error) {
	hasChanges := false

	// Get current user roles FIRST
	currentRoles, err := models.GetUserServiceRolesByUserID(userID)
	if err != nil {
		return false, err
	}

	if len(serviceRoles) == 0 {
		// If no service roles in import, remove all current user roles
		for _, role := range currentRoles {
			err = models.RemoveUserFromServiceRoles(userID, role.ServiceKey)
			if err != nil {
				log.Printf("Warning: Failed to remove user from service %s: %v", role.ServiceKey, err)
			} else {
				hasChanges = true
			}
		}
		return hasChanges, nil
	}

	// Group current roles by service key (not name)
	currentServiceRoles := make(map[string][]string)
	for _, role := range currentRoles {
		serviceKey := role.ServiceKey
		currentServiceRoles[serviceKey] = append(currentServiceRoles[serviceKey], role.RoleName)
	}

	// Process all services - both with roles and without
	allServiceKeys := make(map[string]bool)
	// Add services from import file
	for serviceKey := range serviceRoles {
		allServiceKeys[serviceKey] = true
	}
	// Add services where user currently has roles (to handle removal)
	for serviceKey := range currentServiceRoles {
		allServiceKeys[serviceKey] = true
	}

	// Update roles for each service
	for serviceKey := range allServiceKeys {
		rolesStr := serviceRoles[serviceKey] // This will be "" if not in import file
		var newRoles []string
		if rolesStr == "" {
			newRoles = []string{} // Explicit empty slice for no roles
		} else {
			roles := strings.Split(rolesStr, ",")
			// Filter out empty strings
			for _, role := range roles {
				role = strings.TrimSpace(role)
				if role != "" {
					newRoles = append(newRoles, role)
				}
			}
		}

		// Get service by key instead of name
		service, err := models.GetServiceByKey(serviceKey)
		if err != nil {
			log.Printf("Warning: Service with key %s not found", serviceKey)
			continue
		}

		// Compare with current roles
		currentRolesList := currentServiceRoles[serviceKey]
		if !equalStringSlices(currentRolesList, newRoles) {
			// Remove all current roles for this service
			err = models.RemoveUserFromServiceRoles(userID, service.Key)
			if err != nil {
				log.Printf("ERROR IMPORT: Failed to remove user from service %s: %v", service.Key, err)
			}

			// Add new roles
			for _, roleName := range newRoles {
				if roleName != "" {
					err = models.AssignUserToServiceRole(userID, service.Key, roleName, adminUserID)
					if err != nil {
						log.Printf("ERROR IMPORT: Failed to assign role %s to user in service %s: %v", roleName, service.Key, err)
					}
				}
			}

			hasChanges = true
		}
	}

	return hasChanges, nil
}

// sendUserNotification sends email notification to user
func sendUserNotification(email, notificationType, password string) models.EmailNotification {
	notification := models.EmailNotification{
		RecipientEmail: email,
		Type:           notificationType,
		SentAt:         time.Now(),
	}

	// Prepare email content
	var subject, body string
	if notificationType == "created" {
		subject = "Ваш аккаунт создан в системе Golden House"
		body = fmt.Sprintf(`Здравствуйте!

Для вас был создан аккаунт в системе Golden House.

Данные для входа:
- Email: %s
- Пароль: %s

Рекомендуем сменить пароль после первого входа.

Ссылка для входа: https://analytics.gh.uz/login

С уважением,
Команда Golden House`, email, password)
	} else {
		subject = "Ваш аккаунт обновлен в системе Golden House"
		body = fmt.Sprintf(`Здравствуйте!

Ваш аккаунт в системе Golden House был обновлен.

Email: %s`, email)
		if password != "" {
			body += fmt.Sprintf(`
Новый пароль: %s

Рекомендуем сменить пароль после входа.`, password)
		}
		body += `

Ссылка для входа: https://analytics.gh.uz/login

С уважением,
Команда Golden House`
	}

	// Try to send email with retry mechanism
	const maxRetries = 3
	var lastError error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		log.Printf("Email attempt %d/%d to %s", attempt, maxRetries, email)

		err := models.SendEmailNotificationNew(email, subject, body)
		if err == nil {
			log.Printf("Email successfully sent to %s on attempt %d", email, attempt)
			notification.Success = true
			return notification
		}

		lastError = err
		log.Printf("Email attempt %d failed for %s: %v", attempt, email, err)

		// If this is not the last attempt, wait before retrying
		if attempt < maxRetries {
			time.Sleep(time.Duration(attempt) * time.Second) // Progressive delay
		}
	}

	// All attempts failed - log and notify admin (but this is not critical for import)
	log.Printf("⚠️ All email attempts failed for %s: %v", email, lastError)
	log.Printf("ℹ️ Email will be stored in notification service with retry mechanism")

	// Try to send fallback notification to admin
	adminEmail := os.Getenv("ADMIN_EMAIL")
	if adminEmail == "" {
		adminEmail = "admin@gh.uz" // Default admin email
	}

	fallbackSubject := "⚠️ Не удалось отправить email пользователю"
	fallbackBody := fmt.Sprintf(`ВНИМАНИЕ! Ошибка доставки email при импорте пользователей.

Не удалось отправить уведомление пользователю:
Email: %s
Тип: %s
Ошибка: %v

Пользователь был успешно создан/обновлен, но НЕ получил email с данными аккаунта.
Email сохранён в notification service и будет повторно отправлен автоматически.

Если автоматическая повторная отправка не сработает, требуется ручная отправка!

Содержимое которое должно было быть отправлено:
Тема: %s

%s`, email, notificationType, lastError, subject, body)

	// Try to send admin notification (single attempt - non-blocking)
	adminErr := models.SendEmailNotificationNew(adminEmail, fallbackSubject, fallbackBody)
	if adminErr != nil {
		log.Printf("⚠️ WARNING: Failed to send admin fallback notification: %v", adminErr)
	} else {
		log.Printf("✅ Admin fallback notification sent to %s", adminEmail)
	}

	notification.Success = false
	notification.ErrorMessage = fmt.Sprintf("Failed to send email after %d attempts: %v. User created/updated successfully, email stored for retry.", maxRetries, lastError)

	return notification
}

// equalStringSlices compares two string slices for equality (order doesn't matter)
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	aMap := make(map[string]bool)
	for _, s := range a {
		aMap[s] = true
	}

	for _, s := range b {
		if !aMap[s] {
			return false
		}
	}

	return true
}

// processUserDeletion handles user deletion
func processUserDeletion(importUser models.UserImportExport, result *models.ImportResult) error {
	var existingUser *models.User
	var err error

	// Try to find existing user
	if importUser.ID != "" {
		// Try to find by ID first
		if objectID, err := primitive.ObjectIDFromHex(importUser.ID); err == nil {
			existingUser, err = models.GetUserByID(objectID.Hex())
		}
	}

	if existingUser == nil {
		// Try to find by username/email
		existingUser, err = models.GetUserByUsernameOrEmail(importUser.Username, importUser.Email)
		if err != nil {
			log.Printf("User %s/%s not found for deletion", importUser.Username, importUser.Email)
			return nil // Skip silently if user doesn't exist
		}
	}

	if existingUser != nil {
		log.Printf("Deleting user %s (ID: %s)", existingUser.Username, existingUser.ID.Hex())

		err := models.DeleteUser(existingUser.ID)
		if err != nil {
			return fmt.Errorf("failed to delete user %s: %v", existingUser.Username, err)
		}

		// Add to deleted users list
		importUser.ID = existingUser.ID.Hex()
		result.DeletedUsers = append(result.DeletedUsers, importUser)

		log.Printf("Successfully deleted user %s", existingUser.Username)
	}

	return nil
}

// processBanStatusChange handles ban/unban operations
func processBanStatusChange(existingUser *models.User, importUser models.UserImportExport, result *models.ImportResult) (bool, error) {
	shouldBeBanned := strings.ToLower(strings.TrimSpace(importUser.Banned)) == "true"

	if existingUser.IsBanned != shouldBeBanned {
		if shouldBeBanned {
			// Ban user
			err := models.BanUser(existingUser.ID, "Заблокирован через импорт Excel")
			if err != nil {
				return false, fmt.Errorf("failed to ban user %s: %v", existingUser.Username, err)
			}

			importUser.ID = existingUser.ID.Hex()
			result.BannedUsers = append(result.BannedUsers, importUser)
			log.Printf("Banned user %s", existingUser.Username)
		} else {
			// Unban user
			err := models.UnbanUser(existingUser.ID)
			if err != nil {
				return false, fmt.Errorf("failed to unban user %s: %v", existingUser.Username, err)
			}

			importUser.ID = existingUser.ID.Hex()
			result.UnbannedUsers = append(result.UnbannedUsers, importUser)
			log.Printf("Unbanned user %s", existingUser.Username)
		}
		return true, nil // Status was changed
	}

	return false, nil // No changes
}
