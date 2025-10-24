package routes

import (
	"auth-service/models"
	"auth-service/handlers"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// listUsersHandler displays all users (legacy)
func listUsersHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	users, err := models.GetAllUsers()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить пользователей",
		})
		return
	}

	// Prepare users with their service roles
	type UserWithServiceRoles struct {
		User         models.User
		ServiceRoles []models.UserServiceRole
	}

	var usersWithRoles []UserWithServiceRoles
	for _, user := range users {
		serviceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
		if err != nil {
			log.Printf("Warning: Failed to get service roles for user %s: %v", user.ID.Hex(), err)
			serviceRoles = []models.UserServiceRole{} // Empty slice if error
		}
		
		usersWithRoles = append(usersWithRoles, UserWithServiceRoles{
			User:         user,
			ServiceRoles: serviceRoles,
		})
	}

	// Get 'imported' query parameter
	importedCount := c.Query("imported")

	c.HTML(http.StatusOK, "users_list.html", gin.H{
		"title":           "Управление пользователями",
		"usersWithRoles":  usersWithRoles,
		"username":        user.Username,
		"full_name":       user.GetFullName(),
		"short_name":      user.GetShortName(),
		"user":            user,
		"imported":        importedCount,
	})
}

// showUserFormHandler shows the form to create a new user
func showUserFormHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	roles, err := models.GetSystemRoles()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить роли",
		})
		return
	}

	// Get all services with their roles
	services, err := models.GetAllServicesWithRolesForTemplate()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить сервисы и их роли",
		})
		return
	}

	c.HTML(http.StatusOK, "user_form.html", gin.H{
		"title":      "Создать пользователя",
		"roles":      roles,
		"services":   services,
		"username":   user.Username,
		"full_name":  user.GetFullName(),
		"short_name": user.GetShortName(),
		"user":       user,
	})
}

// createUserHandler creates a new user
func createUserHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	if c.Request.Method == "GET" {
		roles, _ := models.GetSystemRoles()
		c.HTML(http.StatusOK, "user_form.html", gin.H{
			"title":      "Создать пользователя",
			"roles":      roles,
			"username":   user.Username,
			"full_name":  user.GetFullName(),
			"short_name": user.GetShortName(),
			"user":       user,
		})
		return
	}

	// Handle POST
	username := c.PostForm("username")
	email := c.PostForm("email")
	password := c.PostForm("password")
	lastName := c.PostForm("last_name")
	firstName := c.PostForm("first_name")
	middleName := c.PostForm("middle_name")
	suffix := c.PostForm("suffix")
	phone := c.PostForm("phone")
	position := c.PostForm("position")
	department := c.PostForm("department")
	systemAdmin := c.PostForm("system_admin") // New system admin toggle
	serviceRoles := c.PostFormArray("roles") // Format: "serviceKey-roleName" from template

	// Validate required fields
	if username == "" || email == "" || password == "" || lastName == "" || firstName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Имя пользователя, email, пароль, фамилия и имя обязательны для заполнения",
		})
		return
	}

	// Determine roles based on system admin toggle
	var roleNames []string
	if systemAdmin == "true" {
		roleNames = []string{"system.admin"} // Set system admin role if system admin is checked
	}

	// Create user with extended fields
	newUser := models.User{
		Username:   username,
		Email:      email,
		LastName:   lastName,
		FirstName:  firstName,
		MiddleName: middleName,
		Suffix:     suffix,
		Phone:      phone,
		Position:   position,
		Department: department,
		Roles:      roleNames,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Ошибка при хешировании пароля",
		})
		return
	}
	newUser.Password = string(hashedPassword)

	// Create user in database
	userID, err := models.CreateUserFromStruct(newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Не удалось создать пользователя: " + err.Error(),
		})
		return
	}

	// Assign service roles
	for _, serviceRole := range serviceRoles {
		parts := strings.Split(serviceRole, "-")
		if len(parts) == 2 {
			serviceKey := parts[0]
			roleName := parts[1]
			
			userServiceRole := models.UserServiceRole{
				UserID:     userID,
				ServiceKey: serviceKey,
				RoleName:   roleName,
				AssignedAt: time.Now(),
				AssignedBy: user.ID,
				IsActive:   true,
			}
			
			if err := models.CreateUserServiceRole(userServiceRole); err != nil {
				log.Printf("Warning: Failed to assign service role %s:%s to user %s: %v", 
					serviceKey, roleName, userID.Hex(), err)
			}
		}
	}

	// Send email notification to new user (CRITICAL)
	emailSubject := "Ваш аккаунт создан в системе Golden House"
	emailBody := fmt.Sprintf(`Здравствуйте!

Для вас был создан аккаунт в системе Golden House.

Данные для входа:
- Email: %s
- Пароль: %s

Рекомендуем сменить пароль после первого входа.

Ссылка для входа: https://analytics.gh.uz/login

С уважением,
Команда Golden House`, email, password)

	// Try to send email with retry mechanism
	const maxRetries = 3
	var emailSent bool
	var lastError error
	
	for attempt := 1; attempt <= maxRetries; attempt++ {
		log.Printf("Email attempt %d/%d to %s", attempt, maxRetries, email)
		
		err := models.SendEmailNotificationNew(email, emailSubject, emailBody)
		if err == nil {
			log.Printf("Email successfully sent to %s on attempt %d", email, attempt)
			emailSent = true
			break
		}
		
		lastError = err
		log.Printf("Email attempt %d failed for %s: %v", attempt, email, err)
		
		// If this is not the last attempt, wait before retrying
		if attempt < maxRetries {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	
	// If email failed, send notification to admin
	if !emailSent {
		log.Printf("CRITICAL: All email attempts failed for new user %s: %v", email, lastError)
		
		// Try to notify admin
		adminEmail := os.Getenv("ADMIN_EMAIL")
		if adminEmail == "" {
			adminEmail = "admin@gh.uz"
		}
		
		fallbackSubject := "КРИТИЧНО: Не удалось отправить email новому пользователю"
		fallbackBody := fmt.Sprintf(`ВНИМАНИЕ! Критическая ошибка при создании пользователя.

Пользователь создан, но НЕ получил email с данными для входа:
- Email: %s
- Username: %s
- Пароль: %s

Ошибка отправки: %v

ТРЕБУЕТСЯ РУЧНАЯ ОТПРАВКА ДАННЫХ ПОЛЬЗОВАТЕЛЮ!`, email, username, password, lastError)
		
		adminErr := models.SendEmailNotificationNew(adminEmail, fallbackSubject, fallbackBody)
		if adminErr != nil {
			log.Printf("CRITICAL: Failed to send admin notification: %v", adminErr)
		}
		
		// Return error - user creation should fail if email can't be sent
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Пользователь создан, но не удалось отправить email уведомление. Администратор уведомлен.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"message":  "Пользователь успешно создан и уведомлен по email",
		"redirect": "/users/" + userID.Hex(),
	})
}

// getUserHandler shows the form to edit an existing user
func getUserHandler(c *gin.Context) {
	currentUser := c.MustGet("user").(*models.User)
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный формат ID пользователя"})
		return
	}

	user, err := models.GetUserByObjectID(objectID)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "Пользователь не найден"})
		return
	}

	c.HTML(http.StatusOK, "user_edit.html", gin.H{
		"title":      "Редактировать пользователя",
		"editUser":   user,
		"username":   currentUser.Username,
		"full_name":  currentUser.GetFullName(),
		"short_name": currentUser.GetShortName(),
		"user":       currentUser,
	})
}

// updateUserHandler updates an existing user
func updateUserHandler(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Неверный ID пользователя"})
		return
	}

	// Get current user for logging
	currentUser := c.MustGet("user").(*models.User)

	// Extract form data
	username := c.PostForm("username")
	email := c.PostForm("email")
	password := c.PostForm("password")
	lastName := c.PostForm("last_name")
	firstName := c.PostForm("first_name")
	middleName := c.PostForm("middle_name")
	suffix := c.PostForm("suffix")
	phone := c.PostForm("phone")
	position := c.PostForm("position")
	department := c.PostForm("department")
	systemAdmin := c.PostForm("system_admin") // New system admin toggle
	serviceRoles := c.PostFormArray("roles") // Format: "serviceKey-roleName" from template

	// DEBUG: Log received roles
	log.Printf("DEBUG updateUserHandler: userID=%s, systemAdmin=%s, serviceRoles=%v", userID, systemAdmin, serviceRoles)

	// Get existing user
	existingUser, err := models.GetUserByID(objectID.Hex())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Пользователь не найден"})
		return
	}

	// Validate required fields
	if username == "" || email == "" || lastName == "" || firstName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Имя пользователя, email, фамилия и имя обязательны для заполнения"})
		return
	}

	// Determine roles based on system admin toggle
	var roleNames []string
	if systemAdmin == "true" {
		roleNames = []string{"system.admin"} // Set system admin role if system admin is checked
	}

	// Update user basic information
	updatedUser := existingUser
	updatedUser.Username = username
	updatedUser.Email = email
	updatedUser.LastName = lastName
	updatedUser.FirstName = firstName
	updatedUser.MiddleName = middleName
	updatedUser.Suffix = suffix
	updatedUser.Phone = phone
	updatedUser.Position = position
	updatedUser.Department = department
	updatedUser.Roles = roleNames
	updatedUser.UpdatedAt = time.Now()

	// Update password if provided
	if password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Ошибка при хешировании пароля"})
			return
		}
		updatedUser.Password = string(hashedPassword)
	}

	// Save updated user
	err = models.UpdateUserComplete(*updatedUser)
	if err != nil {
		log.Printf("Error updating user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Не удалось обновить пользователя: " + err.Error()})
		return
	}

	// Check if avatar file exists and sync with database
	userDir := fmt.Sprintf("./data/%s", objectID.Hex())
	avatarPath := filepath.Join(userDir, "avatar.jpg")
	
	if _, err := os.Stat(avatarPath); err == nil {
		// Avatar file exists, make sure database has the correct path using new endpoint
		relativeAvatarPath := fmt.Sprintf("/avatar/%s", objectID.Hex())
		
		// Find original file to set the path too
		extensions := []string{".jpg", ".jpeg", ".png", ".gif"}
		relativeOriginalPath := ""
		for _, ext := range extensions {
			originalTestPath := filepath.Join(userDir, "original"+ext)
			if _, err := os.Stat(originalTestPath); err == nil {
				relativeOriginalPath = fmt.Sprintf("/data/%s/original%s", objectID.Hex(), ext)
				break
			}
		}
		
		// Update avatar paths in database if needed
		if updatedUser.AvatarPath != relativeAvatarPath || updatedUser.OriginalAvatarPath != relativeOriginalPath {
			err = models.UpdateUserAvatar(objectID, relativeAvatarPath)
			if err != nil {
				log.Printf("Warning: Failed to update avatar path in database: %v", err)
			} else {
				log.Printf("DEBUG: Synced avatar path in database: %s", relativeAvatarPath)
			}
		}
	}

	// Update service roles
	log.Printf("DEBUG: Starting service roles update for user %s", objectID.Hex())
	log.Printf("DEBUG: Received %d service roles: %v", len(serviceRoles), serviceRoles)
	
	// First, deactivate all existing service roles for this user
	err = models.DeactivateUserServiceRoles(objectID)
	if err != nil {
		log.Printf("Warning: Failed to deactivate existing service roles for user %s: %v", objectID.Hex(), err)
	} else {
		log.Printf("DEBUG: Deactivated existing service roles for user %s", objectID.Hex())
	}

	// Then assign new service roles
	assignedCount := 0
	for _, serviceRole := range serviceRoles {
		log.Printf("DEBUG: Processing service role: %s", serviceRole)
		// Support both formats: "serviceKey:roleName" (new) and "serviceKey-roleName" (legacy)
		var serviceKey, roleName string
		if strings.Contains(serviceRole, ":") {
			parts := strings.SplitN(serviceRole, ":", 2)
			if len(parts) == 2 {
				serviceKey = parts[0]
				roleName = parts[1]
			}
		} else {
			// Legacy format with dash - use SplitN to handle roles with dashes in name
			parts := strings.SplitN(serviceRole, "-", 2)
			if len(parts) == 2 {
				serviceKey = parts[0]
				roleName = parts[1]
			}
		}
		
		if serviceKey != "" && roleName != "" {
			
			log.Printf("DEBUG: Assigning role %s:%s to user %s", serviceKey, roleName, objectID.Hex())
			
			userServiceRole := models.UserServiceRole{
				UserID:     objectID,
				ServiceKey: serviceKey,
				RoleName:   roleName,
				AssignedAt: time.Now(),
				AssignedBy: currentUser.ID,
				IsActive:   true,
			}
			
			if err := models.CreateUserServiceRole(userServiceRole); err != nil {
				log.Printf("ERROR: Failed to assign service role %s:%s to user %s: %v", 
					serviceKey, roleName, objectID.Hex(), err)
			} else {
				log.Printf("DEBUG: Successfully assigned role %s:%s to user %s", serviceKey, roleName, objectID.Hex())
				assignedCount++
			}
		} else {
			log.Printf("WARNING: Invalid service role format: %s (expected format: serviceKey-roleName)", serviceRole)
		}
	}
	log.Printf("DEBUG: Assigned %d service roles to user %s", assignedCount, objectID.Hex())

	// Check if user data changed significantly to warrant email notification
	dataChanged := existingUser.Email != updatedUser.Email ||
		existingUser.LastName != updatedUser.LastName ||
		existingUser.FirstName != updatedUser.FirstName ||
		existingUser.MiddleName != updatedUser.MiddleName ||
		existingUser.Suffix != updatedUser.Suffix ||
		existingUser.Phone != updatedUser.Phone ||
		existingUser.Department != updatedUser.Department ||
		existingUser.Position != updatedUser.Position
	
	passwordChanged := password != ""
	
	// Send email notification if data or password changed
	if dataChanged || passwordChanged {
		emailSubject := "Ваш аккаунт обновлен в системе Golden House"
		emailBody := fmt.Sprintf(`Здравствуйте!

Ваш аккаунт в системе Golden House был обновлен.

Email: %s`, updatedUser.Email)

		if passwordChanged {
			emailBody += fmt.Sprintf(`

Новый пароль: %s

Рекомендуем сменить пароль после входа.`, password)
		}

		emailBody += `

Ссылка для входа: https://analytics.gh.uz/login

С уважением,
Команда Golden House`

		// Try to send email with retry mechanism
		const maxRetries = 3
		var emailSent bool
		var lastError error
		
		for attempt := 1; attempt <= maxRetries; attempt++ {
			log.Printf("Email attempt %d/%d to %s for update", attempt, maxRetries, updatedUser.Email)
			
			err := models.SendEmailNotificationNew(updatedUser.Email, emailSubject, emailBody)
			if err == nil {
				log.Printf("Update email successfully sent to %s on attempt %d", updatedUser.Email, attempt)
				emailSent = true
				break
			}
			
			lastError = err
			log.Printf("Update email attempt %d failed for %s: %v", attempt, updatedUser.Email, err)
			
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * time.Second)
			}
		}
		
		// If email failed, send notification to admin
		if !emailSent {
			log.Printf("CRITICAL: All update email attempts failed for user %s: %v", updatedUser.Email, lastError)
			
			adminEmail := os.Getenv("ADMIN_EMAIL")
			if adminEmail == "" {
				adminEmail = "admin@gh.uz"
			}
			
			fallbackSubject := "КРИТИЧНО: Не удалось отправить email при обновлении пользователя"
			fallbackBody := fmt.Sprintf(`ВНИМАНИЕ! Критическая ошибка при обновлении пользователя.

Пользователь обновлен, но НЕ получил email уведомление:
- Email: %s
- Username: %s`, updatedUser.Email, updatedUser.Username)

			if passwordChanged {
				fallbackBody += fmt.Sprintf(`
- Новый пароль: %s`, password)
			}

			fallbackBody += fmt.Sprintf(`

Ошибка отправки: %v

ТРЕБУЕТСЯ РУЧНОЕ УВЕДОМЛЕНИЕ ПОЛЬЗОВАТЕЛЯ!`, lastError)
			
			adminErr := models.SendEmailNotificationNew(adminEmail, fallbackSubject, fallbackBody)
			if adminErr != nil {
				log.Printf("CRITICAL: Failed to send admin notification for update: %v", adminErr)
			}
			
			// Return error - update should fail if email can't be sent and data/password changed
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Пользователь обновлен, но не удалось отправить email уведомление. Администратор уведомлен.",
			})
			return
		}
		
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Пользователь успешно обновлен и уведомлен по email",
			"redirect": "/users/" + objectID.Hex(),
		})
	} else {
		// No significant changes, no email needed
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Пользователь успешно обновлен",
			"redirect": "/users/" + objectID.Hex(),
		})
	}
}

// deleteUserHandler deletes a user
func deleteUserHandler(c *gin.Context) {
	userID := c.Param("id")
	
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		// Check if this is an AJAX request
		if c.GetHeader("Content-Type") == "application/json" || c.GetHeader("Accept") == "application/json" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Неверный формат ID пользователя"})
		} else {
			c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный формат ID пользователя"})
		}
		return
	}

	err = models.DeleteUser(objectID)
	if err != nil {
		// Check if this is an AJAX request
		if c.GetHeader("Content-Type") == "application/json" || c.GetHeader("Accept") == "application/json" {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Не удалось удалить пользователя: " + err.Error()})
		} else {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"error": "Не удалось удалить пользователя: " + err.Error(),
			})
		}
		return
	}

	// Check if this is an AJAX request
	if c.GetHeader("Content-Type") == "application/json" || c.GetHeader("Accept") == "application/json" {
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Пользователь успешно удален"})
	} else {
		c.Redirect(http.StatusFound, "/users")
	}
}

// Placeholder for user import functionality
func showUserImportFormHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	c.HTML(http.StatusOK, "user_import.html", gin.H{
		"title":      "Импорт пользователей",
		"username":   user.Username,
		"full_name":  user.GetFullName(),
		"short_name": user.GetShortName(),
		"user":       user,
	})
}

func importUsersHandler(c *gin.Context) {
	// Use the new import handler from handlers package
	handlers.ImportUsersFromExcel(c)
}

// updateUserEmailPageHandler shows the form for updating user email
func updateUserEmailPageHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	username := c.Query("username")
	
	c.HTML(http.StatusOK, "update-user-email.html", gin.H{
		"title":        "Обновление Email Пользователя",
		"username":     user.Username,
		"full_name":    user.GetFullName(),
		"short_name":   user.GetShortName(),
		"user":         user,
		"username_val": username,
	})
}

// updateUserEmailHandler handles updating user email
func updateUserEmailHandler(c *gin.Context) {
	username := c.PostForm("username")
	email := c.PostForm("email")
	
	if username == "" || email == "" {
		c.HTML(http.StatusBadRequest, "update-user-email.html", gin.H{
			"error":        "Имя пользователя и email обязательны для заполнения",
			"username_val": username,
			"email_val":    email,
		})
		return
	}
	
	// Find user by username
	targetUser, err := models.GetUserByEmailOrUsername(username)
	if err != nil || targetUser == nil {
		c.HTML(http.StatusNotFound, "update-user-email.html", gin.H{
			"error":        "Пользователь не найден",
			"username_val": username,
			"email_val":    email,
		})
		return
	}
	
	// Update user email
	err = models.UpdateUserEmail(targetUser.ID, email)
	if err != nil {
		log.Printf("Error updating user email: %v", err)
		c.HTML(http.StatusInternalServerError, "update-user-email.html", gin.H{
			"error":        "Ошибка при обновлении email",
			"username_val": username,
			"email_val":    email,
		})
		return
	}
	
	c.HTML(http.StatusOK, "update-user-email.html", gin.H{
		"success":      "Email пользователя успешно обновлен",
		"username_val": username,
		"email_val":    email,
	})
}

// usersManagementHandler displays enhanced users management page
func usersManagementHandler(c *gin.Context) {
	users, err := models.GetAllUsers()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить пользователей",
		})
		return
	}

	// Prepare users with their service roles
	type UserWithServiceRoles struct {
		User         models.User
		ServiceRoles []models.UserServiceRole
	}

	var usersWithRoles []UserWithServiceRoles
	for _, user := range users {
		serviceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
		if err != nil {
			log.Printf("Warning: Failed to get service roles for user %s: %v", user.ID.Hex(), err)
			serviceRoles = []models.UserServiceRole{} // Empty slice if error
		}
		
		usersWithRoles = append(usersWithRoles, UserWithServiceRoles{
			User:         user,
			ServiceRoles: serviceRoles,
		})
	}

	user := c.MustGet("user").(*models.User)

	c.HTML(http.StatusOK, "users_management.html", gin.H{
		"title":          "Управление пользователями",
		"usersWithRoles": usersWithRoles,
		"user":           user,
		// Add data needed for header
		"username":       user.Username,
		"full_name":      user.GetFullName(),
		"short_name":     user.GetShortName(),
	})
}

// sendPasswordResetHandler sends password reset token to user's email (admin only)
func sendPasswordResetHandler(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Неверный ID пользователя"})
		return
	}

	user, err := models.GetUserByID(objectID.Hex())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Пользователь не найден"})
		return
	}

	if user.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "У пользователя не указан email для восстановления пароля"})
		return
	}

	// Create password reset token using existing logic (same as in forgotPasswordHandler)
	token, err := models.CreatePasswordResetToken(user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Ошибка при создании токена восстановления"})
		return
	}

	// Generate reset link
	resetLink := fmt.Sprintf("http://%s/reset-password?token=%s", c.Request.Host, token.Token)
	
	// Send email using existing template system
	emailSubject, emailBody := models.GetPasswordResetEmail(user.GetFullName(), resetLink)
	err = models.SendEmailNotificationNew(user.Email, emailSubject, emailBody)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Ошибка при отправке email: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Токен восстановления пароля отправлен на email " + user.Email,
	})
}

// banUserHandler bans a user
func banUserHandler(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Неверный ID пользователя"})
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Неверные данные запроса"})
		return
	}

	err = models.BanUser(objectID, req.Reason)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Ошибка при блокировке пользователя"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Пользователь заблокирован"})
}

// unbanUserHandler unbans a user
func unbanUserHandler(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Неверный ID пользователя"})
		return
	}

	err = models.UnbanUser(objectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Ошибка при разблокировке пользователя"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Пользователь разблокирован"})
}

// exportUsersHandler exports all users to Excel
func exportUsersHandler(c *gin.Context) {
	// Use the new export handler from handlers package
	handlers.ExportUsersToExcel(c)
}

// downloadUsersTemplateHandler downloads Excel template for user import
func downloadUsersTemplateHandler(c *gin.Context) {
	// Use the new template generator from handlers package
	handlers.DownloadUsersTemplate(c)
}

// Service-specific Excel import/export handlers

// serviceImportPageHandler shows the import page for service administrators
func serviceImportPageHandler(c *gin.Context) {
	handlers.ServiceImportPageHandler(c)
}

// serviceImportHandler processes Excel import for service administrators
func serviceImportHandler(c *gin.Context) {
	handlers.ServiceImportHandler(c)
}

// serviceExportHandler exports users for service administrators
func serviceExportHandler(c *gin.Context) {
	handlers.ServiceExportHandler(c)
}

// serviceTemplateHandler downloads empty template for service administrators
func serviceTemplateHandler(c *gin.Context) {
	handlers.ServiceTemplateHandler(c)
}

// serviceImportLogsHandler retrieves import logs for a specific service
func serviceImportLogsHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	
	// Get current user and verify service admin permissions
	currentUser := c.MustGet("user").(*models.User)
	
	// Verify user has admin rights for this service
	hasServiceAccess := false
	// Check if user has admin role
	for _, role := range currentUser.Roles {
		if role == "admin" || role == "system.admin" {
			hasServiceAccess = true
			break
		}
	}
	
	if !hasServiceAccess {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Access denied: insufficient permissions for this service",
		})
		return
	}
	
	// Get import logs for service
	logs, err := models.GetServiceImportLogs(serviceKey, 10) // Last 10 logs
	if err != nil {
		log.Printf("Error getting service import logs for %s: %v", serviceKey, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve import logs",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"logs": logs,
	})
}

// showImportLogsHandler shows import logs page
func showImportLogsHandler(c *gin.Context) {
	handlers.ShowImportLogsPage(c)
}

// showImportLogDetailsHandler shows detailed import log
func showImportLogDetailsHandler(c *gin.Context) {
	handlers.ShowImportLogDetails(c)
}



// showEnhancedUserFormHandler shows the enhanced user creation/edit form
func showEnhancedUserFormHandler(c *gin.Context) {
	// Get current logged in user for header
	currentUser := c.MustGet("user").(*models.User)
	
	userID := c.Param("id")
	log.Printf("DEBUG: showEnhancedUserFormHandler called with userID: %s", userID)
	
	// For system admin - we'll use a simple toggle instead of multiple roles
	// So we don't need to load all roles anymore
	var allRoles []models.Role // Empty slice - not using multiple system roles
	
	allServices, err := models.GetAllServicesWithRolesForTemplate()
	if err != nil {
		log.Printf("Warning: Failed to get services: %v", err)
		allServices = []models.ServiceWithRoles{}
	}
	log.Printf("DEBUG: Got %d services", len(allServices))
	
	if userID != "" {
		// Edit mode
		log.Printf("DEBUG: Edit mode for user ID: %s", userID)
		objectID, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			log.Printf("ERROR: Invalid user ID: %v", err)
			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"error": "Неверный ID пользователя",
			})
			return
		}

		user, err := models.GetUserByID(objectID.Hex())
		if err != nil {
			log.Printf("ERROR: User not found: %v", err)
			c.HTML(http.StatusNotFound, "error.html", gin.H{
				"error": "Пользователь не найден",
			})
			return
		}
		log.Printf("DEBUG: Found user: %s (%s)", user.Username, user.Email)

		// Get user's current service roles
		userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
		if err != nil {
			log.Printf("Warning: Failed to get user service roles: %v", err)
			userServiceRoles = []models.UserServiceRole{}
		}
		log.Printf("DEBUG: User has %d service roles", len(userServiceRoles))
		log.Printf("DEBUG: User old roles: %v", user.Roles)

		// If user has no service roles in new system but has old roles, we need to migrate them
		if len(userServiceRoles) == 0 && len(user.Roles) > 0 {
			log.Printf("DEBUG: User has old roles but no new service roles, attempting to show old roles for migration")
			// Convert old roles to display format for migration assistance
			oldRolesInfo := make([]models.UserServiceRole, 0)
			
			// Get all roles to find service mappings
			allRoles, err := models.GetAllRoles()
			if err == nil {
				for _, userRoleName := range user.Roles {
					if userRoleName == "admin" || userRoleName == "system.admin" {
						continue // Skip system admin role
					}
					
					// Find this role in the roles collection
					for _, role := range allRoles {
						if role.Name == userRoleName && role.ServiceKey != "" {
							oldRoleInfo := models.UserServiceRole{
								UserID:      user.ID,
								ServiceKey:  role.ServiceKey,
								RoleName:    role.Name,
								IsActive:    true,
								// Add a marker to show this is from old system
							}
							oldRolesInfo = append(oldRolesInfo, oldRoleInfo)
							log.Printf("DEBUG: Found old role mapping: %s -> %s:%s", userRoleName, role.ServiceKey, role.Name)
						}
					}
				}
			}
			
			// Use old roles info if available
			if len(oldRolesInfo) > 0 {
				userServiceRoles = oldRolesInfo
				log.Printf("DEBUG: Using %d converted old roles for display", len(oldRolesInfo))
			}
		}

		// Check if user is system admin (has "admin" or "system.admin" role)
		isSystemAdmin := false
		for _, role := range user.Roles {
			if role == "admin" || role == "system.admin" {
				isSystemAdmin = true
				break
			}
		}
		log.Printf("DEBUG: User is system admin: %t", isSystemAdmin)

		templateData := gin.H{
			"title":            "Редактирование пользователя",
			"editingUser":      &user, // Renamed to avoid conflict with header's user
			"allRoles":         allRoles,
			"allServices":      allServices,
			"userRoles":        userServiceRoles,
			"isSystemAdmin":    isSystemAdmin,
			// Current user data for header (same as in menu.html)
			"username":         currentUser.Username,
			"full_name":        currentUser.GetFullName(),
			"short_name":       currentUser.GetShortName(),
			"user":             currentUser, // For header template
		}
		log.Printf("DEBUG: Rendering user_form.html with template data")
		log.Printf("DEBUG: currentUser.Username = %s", currentUser.Username)
		log.Printf("DEBUG: currentUser.GetShortName() = %s", currentUser.GetShortName())
		c.HTML(http.StatusOK, "user_form.html", templateData)
	} else {
		// Create mode
		log.Printf("DEBUG: Create mode")
		templateData := gin.H{
			"title":         "Создание нового пользователя",
			"allRoles":      allRoles,
			"allServices":   allServices,
			"userRoles":     []models.UserServiceRole{}, // Empty roles for new user
			"isSystemAdmin": false, // Default for new users
			// Current user data for header (same as in menu.html)
			"username":      currentUser.Username,
			"full_name":     currentUser.GetFullName(),
			"short_name":    currentUser.GetShortName(),
			"user":          currentUser, // For header template
		}
		log.Printf("DEBUG: Rendering user_form.html for new user")
		log.Printf("DEBUG: CREATE MODE - currentUser.Username = %s", currentUser.Username)
		log.Printf("DEBUG: CREATE MODE - currentUser.GetShortName() = %s", currentUser.GetShortName())
		c.HTML(http.StatusOK, "user_form.html", templateData)
	}
}

// debugUserRolesHandler shows debug information about user roles
func debugUserRolesHandler(c *gin.Context) {
	userID := c.Param("id")
	log.Printf("DEBUG: debugUserRolesHandler called with userID: %s", userID)
	
	var allRoles []models.Role
	
	allServices, err := models.GetAllServicesWithRolesForTemplate()
	if err != nil {
		log.Printf("Warning: Failed to get services: %v", err)
		allServices = []models.ServiceWithRoles{}
	}
	log.Printf("DEBUG: Got %d services", len(allServices))
	
	if userID != "" && userID != "new" {
		// Edit mode
		log.Printf("DEBUG: Debug mode for user ID: %s", userID)
		objectID, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			log.Printf("ERROR: Invalid user ID: %v", err)
			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"error": "Неверный ID пользователя",
			})
			return
		}

		user, err := models.GetUserByID(objectID.Hex())
		if err != nil {
			log.Printf("ERROR: User not found: %v", err)
			c.HTML(http.StatusNotFound, "error.html", gin.H{
				"error": "Пользователь не найден",
			})
			return
		}
		log.Printf("DEBUG: Found user: %s (%s)", user.Username, user.Email)

		userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
		if err != nil {
			log.Printf("Warning: Failed to get user service roles: %v", err)
			userServiceRoles = []models.UserServiceRole{}
		}
		log.Printf("DEBUG: User has %d service roles", len(userServiceRoles))

		isSystemAdmin := false
		for _, role := range user.Roles {
			if role == "admin" || role == "system.admin" {
				isSystemAdmin = true
				break
			}
		}

		templateData := gin.H{
			"title":            "Debug: Роли пользователя",
			"user":             &user,
			"allRoles":         allRoles,
			"allServices":      allServices,
			"userRoles":        userServiceRoles,
			"isSystemAdmin":    isSystemAdmin,
		}
		log.Printf("DEBUG: Rendering debug_user_roles.html with template data")
		c.HTML(http.StatusOK, "debug_user_roles.html", templateData)
	} else {
		// Create mode
		log.Printf("DEBUG: Create mode")
		templateData := gin.H{
			"title":         "Создание нового пользователя",
			"allRoles":      allRoles,
			"allServices":   allServices,
			"userRoles":     []models.UserServiceRole{}, // Empty roles for new user
			"isSystemAdmin": false, // Default for new users
		}
		log.Printf("DEBUG: Rendering user_form.html for new user")
		c.HTML(http.StatusOK, "user_form.html", templateData)
	}
}

// usersManagementTestHandler displays test debug page
func usersManagementTestHandler(c *gin.Context) {
	users, err := models.GetAllUsers()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить пользователей",
		})
		return
	}

	// Prepare users with their service roles
	type UserWithServiceRoles struct {
		User         models.User
		ServiceRoles []models.UserServiceRole
	}

	var usersWithRoles []UserWithServiceRoles
	for _, user := range users {
		serviceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
		if err != nil {
			log.Printf("Warning: Failed to get service roles for user %s: %v", user.ID.Hex(), err)
			serviceRoles = []models.UserServiceRole{} // Empty slice if error
		}
		
		usersWithRoles = append(usersWithRoles, UserWithServiceRoles{
			User:         user,
			ServiceRoles: serviceRoles,
		})
	}

	c.HTML(http.StatusOK, "users_management_test.html", gin.H{
		"title":          "ТЕСТОВАЯ страница управления пользователями",
		"usersWithRoles": usersWithRoles,
		"user":           c.MustGet("user").(*models.User),
	})
}

// getUserDocumentsByIDHandler returns all documents for a specific user (for admin use)
func getUserDocumentsByIDHandler(c *gin.Context) {
	userID := c.Param("id")
	log.Printf("Getting documents for user ID: %s", userID)

	// Get user data to get documents
	user, err := models.GetUserByID(userID)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	log.Printf("User found: %s, documents count: %d", user.Username, len(user.Documents))

	// Convert UserDocument to response format
	var documents []map[string]interface{}
	for i, doc := range user.Documents {
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

	log.Printf("Found %d documents for user %s", len(documents), userID)
	c.JSON(http.StatusOK, documents)
}

// getUserDocumentAttachmentsByIDHandler returns attachments for a specific document of a specific user
func getUserDocumentAttachmentsByIDHandler(c *gin.Context) {
	userID := c.Param("id")
	documentID := c.Param("docId")
	
	log.Printf("Getting attachments for document %s of user: %s", documentID, userID)
	
	// Get user data to get documents
	user, err := models.GetUserByID(userID)
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
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	doc := user.Documents[docIndex]
	log.Printf("Document found: %s, attachments count: %d", doc.Title, len(doc.Attachments))

	// Convert attachments to response format
	var attachments []map[string]interface{}
	for _, att := range doc.Attachments {
		attachmentResponse := map[string]interface{}{
			"id":       att.ID.Hex(),
			"filename": att.FileName,
			"filesize": att.Size,
			"filetype": att.ContentType,
			"uploaded": att.UploadedAt,
		}
		attachments = append(attachments, attachmentResponse)
	}

	log.Printf("Found %d attachments for document %s", len(attachments), documentID)
	c.JSON(http.StatusOK, attachments)
}

// Admin document management handlers for user forms

// createUserDocumentHandlerAdmin creates a new document for a user (admin use)
func createUserDocumentHandlerAdmin(c *gin.Context) {
	userID := c.Param("id")
	
	log.Printf("Admin creating document for user: %s", userID)

	var req struct {
		DocumentType    string                 `json:"document_type"`
		Title           string                 `json:"title"`
		Fields          map[string]interface{} `json:"fields"`
		AllowedServices []string               `json:"allowed_services"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}

	if req.DocumentType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Тип документа обязателен"})
		return
	}
	
	if req.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Название документа обязательно"})
		return
	}

	if len(req.AllowedServices) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Выберите хотя бы один сервис для использования документа"})
		return
	}

	// Convert userID string to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Printf("Error converting user ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID пользователя"})
		return
	}

	// Create new document
	newDoc := models.UserDocument{
		DocumentType:    req.DocumentType,
		Title:           req.Title,
		Fields:          req.Fields,
		AllowedServices: req.AllowedServices,
		Status:          "draft",
		Attachments:     []models.DocumentAttachment{},
	}
	
	// Add document to user
	if err := models.AddUserDocumentNew(userObjectID, newDoc); err != nil {
		log.Printf("Error adding document: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при создании документа"})
		return
	}

	log.Printf("Document created successfully by admin for user %s: %s", userID, req.Title)
	c.JSON(http.StatusCreated, gin.H{
		"message": "Документ успешно создан",
		"document_type": req.DocumentType,
		"title": req.Title,
	})
}

// getUserDocumentHandlerAdmin returns a specific document for a user (admin use)
func getUserDocumentHandlerAdmin(c *gin.Context) {
	userID := c.Param("id")
	docID := c.Param("docId")
	
	log.Printf("Admin getting document %s for user %s", docID, userID)

	// Get user 
	user, err := models.GetUserByID(userID)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}
	
	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}
	
	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}
	
	document := user.Documents[docIndex]
	
	log.Printf("Document %s retrieved successfully for user %s", docID, userID)
	c.JSON(http.StatusOK, gin.H{
		"document_type": document.DocumentType,
		"title":         document.Title,
		"fields":        document.Fields,
		"status":        document.Status,
		"attachments":   document.Attachments,
		"created_at":    document.CreatedAt,
		"updated_at":    document.UpdatedAt,
	})
}

// updateUserDocumentHandlerAdmin updates a document for a user (admin use)
func updateUserDocumentHandlerAdmin(c *gin.Context) {
	userID := c.Param("id")
	docID := c.Param("docId")
	
	log.Printf("Admin updating document %s for user %s", docID, userID)

	var req struct {
		DocumentType string                 `json:"document_type"`
		Title        string                 `json:"title"`
		Fields       map[string]interface{} `json:"fields"`
		Status       string                 `json:"status"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}

	// Convert userID string to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Printf("Error converting user ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID пользователя"})
		return
	}

	// Get user 
	user, err := models.GetUserByID(userID)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}
	
	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Update document
	if req.DocumentType != "" {
		user.Documents[docIndex].DocumentType = req.DocumentType
	}
	if req.Title != "" {
		user.Documents[docIndex].Title = req.Title
	}
	if req.Fields != nil {
		user.Documents[docIndex].Fields = req.Fields
	}
	if req.Status != "" {
		user.Documents[docIndex].Status = req.Status
	}
	user.Documents[docIndex].UpdatedAt = time.Now()
	
	if err := models.UpdateUserDocuments(userObjectID, user.Documents); err != nil {
		log.Printf("Error updating document: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при обновлении документа"})
		return
	}

	log.Printf("Document %s updated successfully by admin for user %s", docID, userID)
	c.JSON(http.StatusOK, gin.H{
		"message": "Документ успешно обновлен",
		"document_type": req.DocumentType,
		"title": req.Title,
	})
}

// deleteUserDocumentHandlerAdmin deletes a document for a user (admin use)
func deleteUserDocumentHandlerAdmin(c *gin.Context) {
	userID := c.Param("id")
	docID := c.Param("docId")
	
	log.Printf("Admin deleting document %s for user %s", docID, userID)
	
	// Get user 
	user, err := models.GetUserByID(userID)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}
	
	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}
	
	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}
	
	// Remove document from user
	user.Documents = append(user.Documents[:docIndex], user.Documents[docIndex+1:]...)
	
	// Convert userID string to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Printf("Error converting user ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID пользователя"})
		return
	}
	
	// Update user in database
	if err := models.UpdateUserDocuments(userObjectID, user.Documents); err != nil {
		log.Printf("Error updating user documents: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при удалении документа"})
		return
	}
	
	log.Printf("Document %s deleted successfully for user %s", docID, userID)
	c.JSON(http.StatusOK, gin.H{"message": "Документ успешно удален"})
}

// addDocumentAttachmentHandlerAdmin adds an attachment to a document (admin use)
func addDocumentAttachmentHandlerAdmin(c *gin.Context) {
	userID := c.Param("id")
	docID := c.Param("docId")
	
	log.Printf("Admin adding attachment to document %s for user %s", docID, userID)

	// Parse multipart form
	err := c.Request.ParseMultipartForm(99 << 20) // 99 MB max
	if err != nil {
		log.Printf("Error parsing multipart form: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка обработки формы"})
		return
	}

	// Get uploaded file
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		log.Printf("Error getting file: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Файл не найден"})
		return
	}
	defer file.Close()

	// Get user 
	user, err := models.GetUserByID(userID)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}
	
	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}
	
	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Create attachment
	attachment := models.DocumentAttachment{
		ID:           primitive.NewObjectID(),
		FileName:     header.Filename,
		OriginalName: header.Filename,
		ContentType:  header.Header.Get("Content-Type"),
		Size:         header.Size,
		UploadedAt:   time.Now(),
	}

	// Add attachment to document
	user.Documents[docIndex].Attachments = append(user.Documents[docIndex].Attachments, attachment)

	// Convert userID string to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Printf("Error converting user ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID пользователя"})
		return
	}

	// Update user in database
	if err := models.UpdateUserDocuments(userObjectID, user.Documents); err != nil {
		log.Printf("Error updating user documents: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при добавлении файла"})
		return
	}

	log.Printf("Attachment %s added successfully to document %s for user %s", header.Filename, docID, userID)
	c.JSON(http.StatusCreated, gin.H{
		"message": "Файл успешно добавлен",
		"filename": header.Filename,
		"size": header.Size,
	})
}

// removeDocumentAttachmentHandlerAdmin removes an attachment from a document (admin use)
func removeDocumentAttachmentHandlerAdmin(c *gin.Context) {
	userID := c.Param("id")
	docID := c.Param("docId")
	attachmentID := c.Param("attachmentId")
	
	log.Printf("Admin removing attachment %s from document %s for user %s", attachmentID, docID, userID)

	// Get user 
	user, err := models.GetUserByID(userID)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}
	
	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}
	
	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Convert attachment ID to ObjectID
	attachmentObjectID, err := primitive.ObjectIDFromHex(attachmentID)
	if err != nil {
		log.Printf("Error converting attachment ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID файла"})
		return
	}

	// Find and remove attachment
	attachments := user.Documents[docIndex].Attachments
	found := false
	for i, attachment := range attachments {
		if attachment.ID == attachmentObjectID {
			user.Documents[docIndex].Attachments = append(attachments[:i], attachments[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Файл не найден"})
		return
	}

	// Convert userID string to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Printf("Error converting user ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID пользователя"})
		return
	}

	// Update user in database
	if err := models.UpdateUserDocuments(userObjectID, user.Documents); err != nil {
		log.Printf("Error updating user documents: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при удалении файла"})
		return
	}

	log.Printf("Attachment %s removed successfully from document %s for user %s", attachmentID, docID, userID)
	c.JSON(http.StatusOK, gin.H{"message": "Файл успешно удален"})
}

// downloadDocumentAttachmentHandlerAdmin downloads an attachment (admin use)
func downloadDocumentAttachmentHandlerAdmin(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		userID = c.Param("userId") // Support both :id and :userId
	}
	docID := c.Param("docId")
	attachmentID := c.Param("attachmentId")
	
	log.Printf("Admin downloading attachment %s from document %s for user %s", attachmentID, docID, userID)

	// Get user 
	user, err := models.GetUserByID(userID)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}
	
	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}
	
	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Convert attachment ID to ObjectID
	attachmentObjectID, err := primitive.ObjectIDFromHex(attachmentID)
	if err != nil {
		log.Printf("Error converting attachment ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID файла"})
		return
	}

	// Find attachment
	var attachment *models.DocumentAttachment
	doc := user.Documents[docIndex]
	
	for i := range doc.Attachments {
		if doc.Attachments[i].ID == attachmentObjectID {
			attachment = &doc.Attachments[i]
			break
		}
	}

	if attachment == nil {
		log.Printf("Attachment not found: %s", attachmentID)
		c.JSON(http.StatusNotFound, gin.H{"error": "Файл не найден"})
		return
	}

	// DEBUG: Log attachment details for download
	log.Printf("Found attachment: ID=%s, FileName=%s, OriginalName=%s, FilePath=%s", 
		attachment.ID.Hex(), attachment.FileName, attachment.OriginalName, attachment.FilePath)

	// Check if FilePath is empty
	if attachment.FilePath == "" {
		log.Printf("FilePath is empty for attachment %s", attachmentID)
		c.JSON(http.StatusNotFound, gin.H{"error": "Файл не был загружен на сервер"})
		return
	}

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
			dataPath := filepath.Join("./data", userID, "documents", doc.DocumentType, attachment.FileName)
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
	log.Printf("Serving file: %s", attachment.FilePath)
	c.File(attachment.FilePath)
}

// previewDocumentAttachmentHandlerAdmin previews an attachment (admin use)
func previewDocumentAttachmentHandlerAdmin(c *gin.Context) {
	userID := c.Param("id")
	docID := c.Param("docId")
	attachmentID := c.Param("attachmentId")
	
	log.Printf("Admin previewing attachment %s from document %s for user %s", attachmentID, docID, userID)

	// Get user 
	user, err := models.GetUserByID(userID)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}
	
	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}
	
	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Convert attachment ID to ObjectID
	attachmentObjectID, err := primitive.ObjectIDFromHex(attachmentID)
	if err != nil {
		log.Printf("Error converting attachment ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID файла"})
		return
	}

	// Find attachment
	var attachment *models.DocumentAttachment
	for _, att := range user.Documents[docIndex].Attachments {
		if att.ID == attachmentObjectID {
			attachment = &att
			break
		}
	}

	if attachment == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Файл не найден"})
		return
	}

	log.Printf("Attachment %s preview info retrieved successfully for user %s", attachmentID, userID)
	c.JSON(http.StatusOK, gin.H{
		"id":         attachment.ID.Hex(),
		"filename":   attachment.FileName,
		"size":       attachment.Size,
		"mime_type":  attachment.ContentType,
		"uploaded_at": attachment.UploadedAt,
		"preview_url": fmt.Sprintf("/api/users/%s/documents/%s/attachments/%s/download", userID, docID, attachmentID),
	})
}
