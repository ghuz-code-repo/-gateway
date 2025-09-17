package routes

import (
	"auth-service/models"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
	roleNames := c.PostFormArray("roles")
	serviceRoles := c.PostFormArray("service_roles") // Format: "serviceKey:roleName"

	if username == "" || email == "" || password == "" || lastName == "" || firstName == "" {
		roles, _ := models.GetSystemRoles()
		services, _ := models.GetAllServicesWithRolesForTemplate()
		c.HTML(http.StatusBadRequest, "user_form.html", gin.H{
			"title":          "Создать пользователя",
			"error":          "Имя пользователя, email, пароль, фамилия и имя обязательны для заполнения",
			"username_val":   username,
			"email_val":      email,
			"last_name":      lastName,
			"first_name":     firstName,
			"middle_name":    middleName,
			"suffix":         suffix,
			"selected_roles": roleNames,
			"roles":          roles,
			"services":       services,
			"username":       user.Username,
			"full_name":      user.GetFullName(),
			"short_name":     user.GetShortName(),
			"user":           user,
		})
		return
	}

	userID, err := models.CreateUserWithNames(username, email, password, lastName, firstName, middleName, suffix, roleNames)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось создать пользователя: " + err.Error(),
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
				AssignedBy: userID,
				IsActive:   true,
			}
			
			if err := models.CreateUserServiceRole(userServiceRole); err != nil {
				log.Printf("Warning: Failed to assign service role %s:%s to user %s: %v", 
					serviceKey, roleName, userID.Hex(), err)
			}
		}
	}

	c.Redirect(http.StatusFound, "/users")
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
	// TODO: Fix UpdateUser call to match model signature
	// userID := c.Param("id")
	// objectID, err := primitive.ObjectIDFromHex(userID)
	// username := c.PostForm("username")
	// email := c.PostForm("email")
	// fullName := c.PostForm("full_name")
	// password := c.PostForm("password")
	// err = models.UpdateUser(objectID, username, email, fullName, password, []string{})
	// For now, return not implemented
	c.JSON(http.StatusNotImplemented, gin.H{"error": "User update not fully implemented yet"})
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

	c.HTML(http.StatusOK, "users_management.html", gin.H{
		"title":          "Управление пользователями",
		"usersWithRoles": usersWithRoles,
		"user":           c.MustGet("user").(*models.User),
	})
}

// getUserPasswordHandler returns user password (admin only)
func getUserPasswordHandler(c *gin.Context) {
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Неверный ID пользователя"})
		return
	}

	_, err = models.GetUserByID(objectID.Hex())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Пользователь не найден"})
		return
	}

	// For security reasons, we'll generate a new temporary password
	// In a real system, you might want to implement a different approach
	tempPassword, err := models.ResetUserPassword(objectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Ошибка при сбросе пароля"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"password": tempPassword,
		"message":  "Пароль был сброшен на временный",
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
	userID := c.Param("id")
	
	if userID != "" {
		// Edit mode
		objectID, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"error": "Неверный ID пользователя",
			})
			return
		}

		user, err := models.GetUserByID(objectID.Hex())
		if err != nil {
			c.HTML(http.StatusNotFound, "error.html", gin.H{
				"error": "Пользователь не найден",
			})
			return
		}

		c.HTML(http.StatusOK, "user_form_enhanced.html", gin.H{
			"title": "Редактирование пользователя",
			"user":  &user,
		})
	} else {
		// Create mode
		c.HTML(http.StatusOK, "user_form_enhanced.html", gin.H{
			"title": "Создание нового пользователя",
		})
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
