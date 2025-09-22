package routes

import (
	"auth-service/models"
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
	serviceRoles := c.PostFormArray("service_roles") // Format: "serviceKey:roleName"

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
		roleNames = []string{"admin"} // Set admin role if system admin is checked
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
		parts := strings.Split(serviceRole, ":")
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

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"message":  "Пользователь успешно создан",
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
	serviceRoles := c.PostFormArray("service_roles") // Format: "serviceKey:roleName"

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
		roleNames = []string{"admin"} // Set admin role if system admin is checked
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
	// First, deactivate all existing service roles for this user
	err = models.DeactivateUserServiceRoles(objectID)
	if err != nil {
		log.Printf("Warning: Failed to deactivate existing service roles for user %s: %v", objectID.Hex(), err)
	}

	// Then assign new service roles
	for _, serviceRole := range serviceRoles {
		parts := strings.Split(serviceRole, ":")
		if len(parts) == 2 {
			serviceKey := parts[0]
			roleName := parts[1]
			
			userServiceRole := models.UserServiceRole{
				UserID:     objectID,
				ServiceKey: serviceKey,
				RoleName:   roleName,
				AssignedAt: time.Now(),
				AssignedBy: currentUser.ID,
				IsActive:   true,
			}
			
			if err := models.CreateUserServiceRole(userServiceRole); err != nil {
				log.Printf("Warning: Failed to assign service role %s:%s to user %s: %v", 
					serviceKey, roleName, objectID.Hex(), err)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Пользователь успешно обновлен",
		"redirect": "/users/" + objectID.Hex(),
	})
}

// deleteUserHandler deletes a user
func deleteUserHandler(c *gin.Context) {
	userID := c.Param("id")
	
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный формат ID пользователя"})
		return
	}

	err = models.DeleteUser(objectID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось удалить пользователя: " + err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, "/users")
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
	c.JSON(http.StatusNotImplemented, gin.H{"error": "User import functionality not implemented yet"})
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
	err = models.SendEmailNotification(user.Email, emailSubject, emailBody)
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
	users, err := models.GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователей"})
		return
	}

	// Prepare users with their service roles for export
	type UserExportData struct {
		Username   string
		LastName   string
		FirstName  string
		MiddleName string
		Suffix     string
		Email      string
		Phone      string
		Roles      string
	}

	var exportData []UserExportData
	for _, user := range users {
		serviceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
		if err != nil {
			log.Printf("Warning: Failed to get service roles for user %s: %v", user.ID.Hex(), err)
			serviceRoles = []models.UserServiceRole{}
		}

		// Combine system roles and service roles
		allRoles := make([]string, len(user.Roles))
		copy(allRoles, user.Roles)
		
		for _, serviceRole := range serviceRoles {
			if serviceRole.IsActive {
				allRoles = append(allRoles, fmt.Sprintf("%s:%s", serviceRole.ServiceKey, serviceRole.RoleName))
			}
		}

		exportData = append(exportData, UserExportData{
			Username:   user.Username,
			LastName:   user.LastName,
			FirstName:  user.FirstName,
			MiddleName: user.MiddleName,
			Suffix:     user.Suffix,
			Email:      user.Email,
			Phone:      user.Phone,
			Roles:      strings.Join(allRoles, ", "),
		})
	}

	// Convert to interface{} slice
	interfaceData := make([]interface{}, len(exportData))
	for i, v := range exportData {
		interfaceData[i] = v
	}
	
	filename, err := models.ExportUsersToExcel(interfaceData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при создании файла экспорта"})
		return
	}

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.File(filename)

	// Clean up temporary file
	go func() {
		time.Sleep(5 * time.Second)
		os.Remove(filename)
	}()
}

// downloadUsersTemplateHandler downloads Excel template for user import
func downloadUsersTemplateHandler(c *gin.Context) {
	filename, err := models.GenerateUsersImportTemplate()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при создании шаблона"})
		return
	}

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", "attachment; filename=users_import_template.xlsx")
	c.File(filename)

	// Clean up temporary file
	go func() {
		time.Sleep(5 * time.Second)
		os.Remove(filename)
	}()
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

		// Check if user is system admin (has "admin" role)
		isSystemAdmin := false
		for _, role := range user.Roles {
			if role == "admin" {
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
			if role == "admin" {
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
		DocumentType string                 `json:"document_type"`
		Title        string                 `json:"title"`
		Fields       map[string]interface{} `json:"fields"`
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

	// Convert userID string to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Printf("Error converting user ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID пользователя"})
		return
	}

	// Create new document
	newDoc := models.UserDocument{
		DocumentType: req.DocumentType,
		Title:        req.Title,
		Fields:       req.Fields,
		Status:       "draft",
		Attachments:  []models.DocumentAttachment{},
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

	log.Printf("Attachment %s info retrieved successfully for user %s", attachmentID, userID)
	c.JSON(http.StatusOK, gin.H{
		"id":       attachment.ID.Hex(),
		"filename": attachment.FileName,
		"size":     attachment.Size,
		"mime_type": attachment.ContentType,
		"uploaded_at": attachment.UploadedAt,
	})
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
