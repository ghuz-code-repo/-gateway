package routes

import (
	"auth-service/handlers"
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

// userWithServiceRoles binds a user with their service role assignments (for templates)
type userWithServiceRoles struct {
	User         models.User
	ServiceRoles []models.UserServiceRole
}

// buildUsersWithRoles enriches a list of users with their service roles
// Uses batch loading to avoid N+1 queries
func buildUsersWithRoles(users []models.User) []userWithServiceRoles {
	// Load all user-service-role assignments in one query
	allRolesGrouped, err := models.GetAllUserServiceRolesGrouped()
	if err != nil {
		log.Printf("Warning: Failed to batch-load service roles, falling back to per-user: %v", err)
		// Fallback to per-user loading if batch fails
		return buildUsersWithRolesFallback(users)
	}

	result := make([]userWithServiceRoles, 0, len(users))
	for _, user := range users {
		serviceRoles := allRolesGrouped[user.ID]
		if serviceRoles == nil {
			serviceRoles = []models.UserServiceRole{}
		}
		result = append(result, userWithServiceRoles{
			User:         user,
			ServiceRoles: serviceRoles,
		})
	}
	return result
}

// buildUsersWithRolesFallback is the N+1 fallback used only if batch loading fails
func buildUsersWithRolesFallback(users []models.User) []userWithServiceRoles {
	result := make([]userWithServiceRoles, 0, len(users))
	for _, user := range users {
		serviceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
		if err != nil {
			log.Printf("Warning: Failed to get service roles for user %s: %v", user.ID.Hex(), err)
			serviceRoles = []models.UserServiceRole{}
		}
		result = append(result, userWithServiceRoles{
			User:         user,
			ServiceRoles: serviceRoles,
		})
	}
	return result
}

// listUsersHandler displays all users (legacy)
func listUsersHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	users, err := models.GetAllUsers()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "РќРµ СѓРґР°Р»РѕСЃСЊ РїРѕР»СѓС‡РёС‚СЊ РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№",
		})
		return
	}

	// Prepare users with their service roles
	usersWithRoles := buildUsersWithRoles(users)

	// Get 'imported' query parameter
	importedCount := c.Query("imported")

	c.HTML(http.StatusOK, "users_list.html", gin.H{
		"title":          "РЈРїСЂР°РІР»РµРЅРёРµ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏРјРё",
		"usersWithRoles": usersWithRoles,
		"username":       user.Username,
		"full_name":      user.GetFullName(),
		"short_name":     user.GetShortName(),
		"user":           user,
		"imported":       importedCount,
	})
}

// showUserFormHandler shows the form to create a new user
func showUserFormHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	roles, err := models.GetSystemRoles()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "РќРµ СѓРґР°Р»РѕСЃСЊ РїРѕР»СѓС‡РёС‚СЊ СЂРѕР»Рё",
		})
		return
	}

	// Get all services with their roles
	services, err := models.GetAllServicesWithRolesForTemplate()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "РќРµ СѓРґР°Р»РѕСЃСЊ РїРѕР»СѓС‡РёС‚СЊ СЃРµСЂРІРёСЃС‹ Рё РёС… СЂРѕР»Рё",
		})
		return
	}

	c.HTML(http.StatusOK, "user_form.html", gin.H{
		"title":      "РЎРѕР·РґР°С‚СЊ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ",
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

	// SECURITY: Check permission to create users
	if !hasAuthPermission(user, "auth.users.create") && !hasAuthPermission(user, "auth.*") {
		if c.Request.Method == "GET" {
			c.Redirect(http.StatusFound, "/access-denied")
			return
		}
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "РќРµС‚ РїСЂР°РІ РґР»СЏ СЃРѕР·РґР°РЅРёСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№"})
		return
	}

	if c.Request.Method == "GET" {
		roles, _ := models.GetSystemRoles()
		c.HTML(http.StatusOK, "user_form.html", gin.H{
			"title":      "РЎРѕР·РґР°С‚СЊ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ",
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
	serviceRoles := c.PostFormArray("roles")  // Format: "serviceKey-roleName" from template

	// Validate required fields
	if username == "" || email == "" || password == "" || lastName == "" || firstName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "РРјСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ, email, РїР°СЂРѕР»СЊ, С„Р°РјРёР»РёСЏ Рё РёРјСЏ РѕР±СЏР·Р°С‚РµР»СЊРЅС‹ РґР»СЏ Р·Р°РїРѕР»РЅРµРЅРёСЏ",
		})
		return
	}

	// Create user with extended fields (no legacy Roles field)
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
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "РћС€РёР±РєР° РїСЂРё С…РµС€РёСЂРѕРІР°РЅРёРё РїР°СЂРѕР»СЏ",
		})
		return
	}
	newUser.Password = string(hashedPassword)

	// Create user in database
	userID, err := models.CreateUserFromStruct(newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "РќРµ СѓРґР°Р»РѕСЃСЊ СЃРѕР·РґР°С‚СЊ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ: " + err.Error(),
		})
		return
	}

	// Assign service roles
	// First, assign system admin role if needed
	// SECURITY: Only system admins can grant system admin
	if systemAdmin == "true" {
		if !models.IsSystemAdmin(user.ID) {
			log.Printf("SECURITY: User %s attempted to grant system admin to new user %s without permission", user.Username, userID.Hex())
		} else {
			adminRole := models.UserServiceRole{
				UserID:     userID,
				ServiceKey: "auth",
				RoleName:   "admin",
				AssignedAt: time.Now(),
				AssignedBy: user.ID,
				IsActive:   true,
			}
			if err := models.CreateUserServiceRole(adminRole); err != nil {
				log.Printf("Warning: Failed to assign admin role to user %s: %v", userID.Hex(), err)
			}
		}
	}

	// SECURITY: Check permission to assign roles
	canAssignRoles := hasAuthPermission(user, "auth.users.assign_roles") || hasAuthPermission(user, "auth.*")

	// Then assign selected service roles
	for _, serviceRole := range serviceRoles {
		// Parse "serviceKey:roleName" format (colon separator is safe for keys with dashes)
		var serviceKey, roleName string
		if strings.Contains(serviceRole, ":") {
			parts := strings.SplitN(serviceRole, ":", 2)
			if len(parts) == 2 {
				serviceKey = parts[0]
				roleName = parts[1]
			}
		} else {
			log.Printf("WARNING: Legacy dash-separated role format: %s вЂ” skipping (use colon separator)", serviceRole)
			continue
		}

		if serviceKey == "" || roleName == "" {
			log.Printf("WARNING: Invalid service role format: %s", serviceRole)
			continue
		}

		// SECURITY: Check per-service role assignment permission
		if !canAssignRoles {
			if serviceKey == "auth" {
				log.Printf("SECURITY: User %s cannot assign auth roles without auth.users.assign_roles", user.Username)
				continue
			}
			if !hasAuthPermission(user, "auth."+serviceKey+".roles.assign") && !hasAuthPermission(user, "auth."+serviceKey+".*") {
				log.Printf("SECURITY: User %s cannot assign roles for service %s", user.Username, serviceKey)
				continue
			}
		}

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

	// Send email notification to new user (CRITICAL)
	emailSubject := "Р’Р°С€ Р°РєРєР°СѓРЅС‚ СЃРѕР·РґР°РЅ РІ СЃРёСЃС‚РµРјРµ Golden House"
	emailBody := fmt.Sprintf(`Р—РґСЂР°РІСЃС‚РІСѓР№С‚Рµ!

Р”Р»СЏ РІР°СЃ Р±С‹Р» СЃРѕР·РґР°РЅ Р°РєРєР°СѓРЅС‚ РІ СЃРёСЃС‚РµРјРµ Golden House.

Р”Р°РЅРЅС‹Рµ РґР»СЏ РІС…РѕРґР°:
- Email: %s
- РџР°СЂРѕР»СЊ: %s

Р РµРєРѕРјРµРЅРґСѓРµРј СЃРјРµРЅРёС‚СЊ РїР°СЂРѕР»СЊ РїРѕСЃР»Рµ РїРµСЂРІРѕРіРѕ РІС…РѕРґР°.

РЎСЃС‹Р»РєР° РґР»СЏ РІС…РѕРґР°: https://analytics.gh.uz/login

РЎ СѓРІР°Р¶РµРЅРёРµРј,
РљРѕРјР°РЅРґР° Golden House`, email, password)

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

		fallbackSubject := "РљР РРўРР§РќРћ: РќРµ СѓРґР°Р»РѕСЃСЊ РѕС‚РїСЂР°РІРёС‚СЊ email РЅРѕРІРѕРјСѓ РїРѕР»СЊР·РѕРІР°С‚РµР»СЋ"
		fallbackBody := fmt.Sprintf(`Р’РќРРњРђРќРР•! РљСЂРёС‚РёС‡РµСЃРєР°СЏ РѕС€РёР±РєР° РїСЂРё СЃРѕР·РґР°РЅРёРё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ.

РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ СЃРѕР·РґР°РЅ, РЅРѕ РќР• РїРѕР»СѓС‡РёР» email СЃ РґР°РЅРЅС‹РјРё РґР»СЏ РІС…РѕРґР°:
- Email: %s
- Username: %s
- РџР°СЂРѕР»СЊ: %s

РћС€РёР±РєР° РѕС‚РїСЂР°РІРєРё: %v

РўР Р•Р‘РЈР•РўРЎРЇ Р РЈР§РќРђРЇ РћРўРџР РђР’РљРђ Р”РђРќРќР«РҐ РџРћР›Р¬Р—РћР’РђРўР•Р›Р®!`, email, username, password, lastError)

		adminErr := models.SendEmailNotificationNew(adminEmail, fallbackSubject, fallbackBody)
		if adminErr != nil {
			log.Printf("CRITICAL: Failed to send admin notification: %v", adminErr)
		}

		// Return error - user creation should fail if email can't be sent
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ СЃРѕР·РґР°РЅ, РЅРѕ РЅРµ СѓРґР°Р»РѕСЃСЊ РѕС‚РїСЂР°РІРёС‚СЊ email СѓРІРµРґРѕРјР»РµРЅРёРµ. РђРґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂ СѓРІРµРґРѕРјР»РµРЅ.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"message":  "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ СѓСЃРїРµС€РЅРѕ СЃРѕР·РґР°РЅ Рё СѓРІРµРґРѕРјР»РµРЅ РїРѕ email",
		"redirect": "/users/" + userID.Hex(),
	})
}

// getUserHandler shows the form to edit an existing user
func getUserHandler(c *gin.Context) {
	currentUser := c.MustGet("user").(*models.User)
	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ С„РѕСЂРјР°С‚ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	user, err := models.GetUserByObjectID(objectID)
	if err != nil {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	c.HTML(http.StatusOK, "user_edit.html", gin.H{
		"title":      "Р РµРґР°РєС‚РёСЂРѕРІР°С‚СЊ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ",
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
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "РќРµРІРµСЂРЅС‹Р№ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	// Get current user for logging
	currentUser := c.MustGet("user").(*models.User)

	// SECURITY: Check permission to edit users
	if !hasAuthPermission(currentUser, "auth.users.edit") && !hasAuthPermission(currentUser, "auth.*") {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "РќРµС‚ РїСЂР°РІ РґР»СЏ СЂРµРґР°РєС‚РёСЂРѕРІР°РЅРёСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№"})
		return
	}

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
	serviceRoles := c.PostFormArray("roles")  // Format: "serviceKey-roleName" from template

	// DEBUG: Log received roles
	debugLog("DEBUG updateUserHandler: userID=%s, systemAdmin=%s, serviceRoles=%v", userID, systemAdmin, serviceRoles)

	// Get existing user
	existingUser, err := models.GetUserByID(objectID.Hex())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Validate required fields
	if username == "" || email == "" || lastName == "" || firstName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "РРјСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ, email, С„Р°РјРёР»РёСЏ Рё РёРјСЏ РѕР±СЏР·Р°С‚РµР»СЊРЅС‹ РґР»СЏ Р·Р°РїРѕР»РЅРµРЅРёСЏ"})
		return
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
	updatedUser.UpdatedAt = time.Now()

	// Update password if provided
	if password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "РћС€РёР±РєР° РїСЂРё С…РµС€РёСЂРѕРІР°РЅРёРё РїР°СЂРѕР»СЏ"})
			return
		}
		updatedUser.Password = string(hashedPassword)
	}

	// Save updated user
	err = models.UpdateUserComplete(*updatedUser)
	if err != nil {
		log.Printf("Error updating user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "РќРµ СѓРґР°Р»РѕСЃСЊ РѕР±РЅРѕРІРёС‚СЊ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ: " + err.Error()})
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
				debugLog("DEBUG: Synced avatar path in database: %s", relativeAvatarPath)
			}
		}
	}

	// Update service roles
	debugLog("DEBUG: Starting service roles update for user %s", objectID.Hex())
	debugLog("DEBUG: Received %d service roles: %v", len(serviceRoles), serviceRoles)

	// First, deactivate all existing service roles for this user
	err = models.DeactivateUserServiceRoles(objectID)
	if err != nil {
		log.Printf("Warning: Failed to deactivate existing service roles for user %s: %v", objectID.Hex(), err)
	} else {
		debugLog("DEBUG: Deactivated existing service roles for user %s", objectID.Hex())
	}

	// Then assign new service roles
	assignedCount := 0

	// Assign system admin role via user_service_roles if needed
	// SECURITY: Only system admins (GOD/admin) can grant system admin
	if systemAdmin == "true" {
		if !models.IsSystemAdmin(currentUser.ID) {
			log.Printf("SECURITY: User %s attempted to grant system admin to user %s without permission", currentUser.Username, objectID.Hex())
		} else {
			adminRole := models.UserServiceRole{
				UserID:     objectID,
				ServiceKey: "auth",
				RoleName:   "admin",
				AssignedAt: time.Now(),
				AssignedBy: currentUser.ID,
				IsActive:   true,
			}
			if err := models.CreateUserServiceRole(adminRole); err != nil {
				log.Printf("Warning: Failed to assign admin role to user %s: %v", objectID.Hex(), err)
			} else {
				assignedCount++
			}
		}
	}

	// SECURITY: Check permission to assign roles
	canAssignRoles := hasAuthPermission(currentUser, "auth.users.assign_roles") || hasAuthPermission(currentUser, "auth.*")

	for _, serviceRole := range serviceRoles {
		debugLog("DEBUG: Processing service role: %s", serviceRole)
		// Support both formats: "serviceKey:roleName" (new) and "serviceKey-roleName" (legacy, broken for keys with dashes)
		var serviceKey, roleName string
		if strings.Contains(serviceRole, ":") {
			parts := strings.SplitN(serviceRole, ":", 2)
			if len(parts) == 2 {
				serviceKey = parts[0]
				roleName = parts[1]
			}
		} else {
			log.Printf("WARNING: Legacy dash-separated role format: %s вЂ” may be broken for service keys with dashes", serviceRole)
			// Legacy format with dash - use SplitN (broken for keys like "client-service")
			parts := strings.SplitN(serviceRole, "-", 2)
			if len(parts) == 2 {
				serviceKey = parts[0]
				roleName = parts[1]
			}
		}

		if serviceKey != "" && roleName != "" {
			// SECURITY: Check per-service role assignment permission
			if !canAssignRoles {
				// For non-global role assigners, check service-specific permission
				if serviceKey == "auth" {
					log.Printf("SECURITY: User %s cannot assign auth roles without auth.users.assign_roles", currentUser.Username)
					continue
				}
				if !hasAuthPermission(currentUser, "auth."+serviceKey+".roles.assign") && !hasAuthPermission(currentUser, "auth."+serviceKey+".*") {
					log.Printf("SECURITY: User %s cannot assign roles for service %s", currentUser.Username, serviceKey)
					continue
				}
			}

			debugLog("DEBUG: Assigning role %s:%s to user %s", serviceKey, roleName, objectID.Hex())

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
				debugLog("DEBUG: Successfully assigned role %s:%s to user %s", serviceKey, roleName, objectID.Hex())
				assignedCount++
			}
		} else {
			log.Printf("WARNING: Invalid service role format: %s (expected format: serviceKey-roleName)", serviceRole)
		}
	}
	debugLog("DEBUG: Assigned %d service roles to user %s", assignedCount, objectID.Hex())

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
		emailSubject := "Р’Р°С€ Р°РєРєР°СѓРЅС‚ РѕР±РЅРѕРІР»РµРЅ РІ СЃРёСЃС‚РµРјРµ Golden House"
		emailBody := fmt.Sprintf(`Р—РґСЂР°РІСЃС‚РІСѓР№С‚Рµ!

Р’Р°С€ Р°РєРєР°СѓРЅС‚ РІ СЃРёСЃС‚РµРјРµ Golden House Р±С‹Р» РѕР±РЅРѕРІР»РµРЅ.

Email: %s`, updatedUser.Email)

		if passwordChanged {
			emailBody += fmt.Sprintf(`

РќРѕРІС‹Р№ РїР°СЂРѕР»СЊ: %s

Р РµРєРѕРјРµРЅРґСѓРµРј СЃРјРµРЅРёС‚СЊ РїР°СЂРѕР»СЊ РїРѕСЃР»Рµ РІС…РѕРґР°.`, password)
		}

		emailBody += `

РЎСЃС‹Р»РєР° РґР»СЏ РІС…РѕРґР°: https://analytics.gh.uz/login

РЎ СѓРІР°Р¶РµРЅРёРµРј,
РљРѕРјР°РЅРґР° Golden House`

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

			fallbackSubject := "РљР РРўРР§РќРћ: РќРµ СѓРґР°Р»РѕСЃСЊ РѕС‚РїСЂР°РІРёС‚СЊ email РїСЂРё РѕР±РЅРѕРІР»РµРЅРёРё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"
			fallbackBody := fmt.Sprintf(`Р’РќРРњРђРќРР•! РљСЂРёС‚РёС‡РµСЃРєР°СЏ РѕС€РёР±РєР° РїСЂРё РѕР±РЅРѕРІР»РµРЅРёРё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ.

РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ РѕР±РЅРѕРІР»РµРЅ, РЅРѕ РќР• РїРѕР»СѓС‡РёР» email СѓРІРµРґРѕРјР»РµРЅРёРµ:
- Email: %s
- Username: %s`, updatedUser.Email, updatedUser.Username)

			if passwordChanged {
				fallbackBody += fmt.Sprintf(`
- РќРѕРІС‹Р№ РїР°СЂРѕР»СЊ: %s`, password)
			}

			fallbackBody += fmt.Sprintf(`

РћС€РёР±РєР° РѕС‚РїСЂР°РІРєРё: %v

РўР Р•Р‘РЈР•РўРЎРЇ Р РЈР§РќРћР• РЈР’Р•Р”РћРњР›Р•РќРР• РџРћР›Р¬Р—РћР’РђРўР•Р›РЇ!`, lastError)

			adminErr := models.SendEmailNotificationNew(adminEmail, fallbackSubject, fallbackBody)
			if adminErr != nil {
				log.Printf("CRITICAL: Failed to send admin notification for update: %v", adminErr)
			}

			// Return error - update should fail if email can't be sent and data/password changed
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ РѕР±РЅРѕРІР»РµРЅ, РЅРѕ РЅРµ СѓРґР°Р»РѕСЃСЊ РѕС‚РїСЂР°РІРёС‚СЊ email СѓРІРµРґРѕРјР»РµРЅРёРµ. РђРґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂ СѓРІРµРґРѕРјР»РµРЅ.",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success":  true,
			"message":  "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ СѓСЃРїРµС€РЅРѕ РѕР±РЅРѕРІР»РµРЅ Рё СѓРІРµРґРѕРјР»РµРЅ РїРѕ email",
			"redirect": "/users/" + objectID.Hex(),
		})
	} else {
		// No significant changes, no email needed
		c.JSON(http.StatusOK, gin.H{
			"success":  true,
			"message":  "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ СѓСЃРїРµС€РЅРѕ РѕР±РЅРѕРІР»РµРЅ",
			"redirect": "/users/" + objectID.Hex(),
		})
	}
}

// deleteUserHandler deletes a user
func deleteUserHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	// Check permission to delete users
	if !hasAuthPermission(user, "auth.users.delete") && !hasAuthPermission(user, "auth.*") {
		if c.GetHeader("Content-Type") == "application/json" || c.GetHeader("Accept") == "application/json" {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "РЈ РІР°СЃ РЅРµС‚ РїСЂР°РІ РґР»СЏ СѓРґР°Р»РµРЅРёСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№"})
		} else {
			c.HTML(http.StatusForbidden, "error.html", gin.H{"error": "РЈ РІР°СЃ РЅРµС‚ РїСЂР°РІ РґР»СЏ СѓРґР°Р»РµРЅРёСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№"})
		}
		return
	}

	userID := c.Param("id")

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		// Check if this is an AJAX request
		if c.GetHeader("Content-Type") == "application/json" || c.GetHeader("Accept") == "application/json" {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "РќРµРІРµСЂРЅС‹Р№ С„РѕСЂРјР°С‚ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		} else {
			c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ С„РѕСЂРјР°С‚ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		}
		return
	}

	err = models.DeleteUser(objectID)
	if err != nil {
		// Check if this is an AJAX request
		if c.GetHeader("Content-Type") == "application/json" || c.GetHeader("Accept") == "application/json" {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "РќРµ СѓРґР°Р»РѕСЃСЊ СѓРґР°Р»РёС‚СЊ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ: " + err.Error()})
		} else {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"error": "РќРµ СѓРґР°Р»РѕСЃСЊ СѓРґР°Р»РёС‚СЊ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ: " + err.Error(),
			})
		}
		return
	}

	// Check if this is an AJAX request
	if c.GetHeader("Content-Type") == "application/json" || c.GetHeader("Accept") == "application/json" {
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ СѓСЃРїРµС€РЅРѕ СѓРґР°Р»РµРЅ"})
	} else {
		c.Redirect(http.StatusFound, "/users")
	}
}

// Placeholder for user import functionality
func showUserImportFormHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	c.HTML(http.StatusOK, "user_import.html", gin.H{
		"title":      "РРјРїРѕСЂС‚ РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№",
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
		"title":        "РћР±РЅРѕРІР»РµРЅРёРµ Email РџРѕР»СЊР·РѕРІР°С‚РµР»СЏ",
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
			"error":        "РРјСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ Рё email РѕР±СЏР·Р°С‚РµР»СЊРЅС‹ РґР»СЏ Р·Р°РїРѕР»РЅРµРЅРёСЏ",
			"username_val": username,
			"email_val":    email,
		})
		return
	}

	// Find user by username
	targetUser, err := models.GetUserByEmailOrUsername(username)
	if err != nil || targetUser == nil {
		c.HTML(http.StatusNotFound, "update-user-email.html", gin.H{
			"error":        "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ РЅРµ РЅР°Р№РґРµРЅ",
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
			"error":        "РћС€РёР±РєР° РїСЂРё РѕР±РЅРѕРІР»РµРЅРёРё email",
			"username_val": username,
			"email_val":    email,
		})
		return
	}

	c.HTML(http.StatusOK, "update-user-email.html", gin.H{
		"success":      "Email РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ СѓСЃРїРµС€РЅРѕ РѕР±РЅРѕРІР»РµРЅ",
		"username_val": username,
		"email_val":    email,
	})
}

// usersManagementHandler displays enhanced users management page
func usersManagementHandler(c *gin.Context) {
	users, err := models.GetAllUsers()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "РќРµ СѓРґР°Р»РѕСЃСЊ РїРѕР»СѓС‡РёС‚СЊ РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№",
		})
		return
	}

	// Prepare users with their service roles
	usersWithRoles := buildUsersWithRoles(users)

	user := c.MustGet("user").(*models.User)

	// Debug log permissions
	userPerms, _ := models.GetUserAuthPermissions(user.ID)
	debugLog("DEBUG usersManagementHandler: user=%s has permissions: %v", user.Username, userPerms)

	// Check user permissions for UI visibility
	canDeleteUsers := hasAuthPermission(user, "auth.users.delete") || hasAuthPermission(user, "auth.*")
	canBanUsers := hasAuthPermission(user, "auth.users.ban") || hasAuthPermission(user, "auth.*")
	canResetPassword := hasAuthPermission(user, "auth.users.reset_password") || hasAuthPermission(user, "auth.*")
	canEditUsers := hasAuthPermission(user, "auth.users.edit") || hasAuthPermission(user, "auth.*")
	canCreateUsers := hasAuthPermission(user, "auth.users.create") || hasAuthPermission(user, "auth.*")

	debugLog("DEBUG usersManagementHandler: canDelete=%v canBan=%v canReset=%v canEdit=%v canCreate=%v",
		canDeleteUsers, canBanUsers, canResetPassword, canEditUsers, canCreateUsers)

	c.HTML(http.StatusOK, "users_management.html", gin.H{
		"title":            "РЈРїСЂР°РІР»РµРЅРёРµ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏРјРё",
		"usersWithRoles":   usersWithRoles,
		"user":             user,
		"canDeleteUsers":   canDeleteUsers,
		"canBanUsers":      canBanUsers,
		"canResetPassword": canResetPassword,
		"canEditUsers":     canEditUsers,
		"canCreateUsers":   canCreateUsers,
		// Add data needed for header
		"username":   user.Username,
		"full_name":  user.GetFullName(),
		"short_name": user.GetShortName(),
	})
}

// sendPasswordResetHandler sends password reset token to user's email (admin only)
func sendPasswordResetHandler(c *gin.Context) {
	// SECURITY: Check permission to reset passwords
	currentUser := c.MustGet("user").(*models.User)
	if !hasAuthPermission(currentUser, "auth.users.reset_password") && !hasAuthPermission(currentUser, "auth.*") {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "РќРµС‚ РїСЂР°РІ РґР»СЏ СЃР±СЂРѕСЃР° РїР°СЂРѕР»СЏ"})
		return
	}

	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "РќРµРІРµСЂРЅС‹Р№ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	user, err := models.GetUserByID(objectID.Hex())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	if user.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "РЈ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ РЅРµ СѓРєР°Р·Р°РЅ email РґР»СЏ РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёСЏ РїР°СЂРѕР»СЏ"})
		return
	}

	// Create password reset token using existing logic (same as in forgotPasswordHandler)
	token, err := models.CreatePasswordResetToken(user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "РћС€РёР±РєР° РїСЂРё СЃРѕР·РґР°РЅРёРё С‚РѕРєРµРЅР° РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёСЏ"})
		return
	}

	// Generate reset link
	resetLink := fmt.Sprintf("http://%s/reset-password?token=%s", c.Request.Host, token.Token)

	// Send email using existing template system
	emailSubject, emailBody := models.GetPasswordResetEmail(user.GetFullName(), resetLink)
	err = models.SendEmailNotificationNew(user.Email, emailSubject, emailBody)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "РћС€РёР±РєР° РїСЂРё РѕС‚РїСЂР°РІРєРµ email: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "РўРѕРєРµРЅ РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёСЏ РїР°СЂРѕР»СЏ РѕС‚РїСЂР°РІР»РµРЅ РЅР° email " + user.Email,
	})
}

// banUserHandler bans a user
func banUserHandler(c *gin.Context) {
	// Check permission
	user := c.MustGet("user").(*models.User)
	if !hasAuthPermission(user, "auth.users.ban") && !hasAuthPermission(user, "auth.*") {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "РќРµС‚ РїСЂР°РІ РґР»СЏ Р±Р»РѕРєРёСЂРѕРІРєРё РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№"})
		return
	}

	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "РќРµРІРµСЂРЅС‹Р№ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "РќРµРІРµСЂРЅС‹Рµ РґР°РЅРЅС‹Рµ Р·Р°РїСЂРѕСЃР°"})
		return
	}

	err = models.BanUser(objectID, req.Reason)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "РћС€РёР±РєР° РїСЂРё Р±Р»РѕРєРёСЂРѕРІРєРµ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅ"})
}

// unbanUserHandler unbans a user
func unbanUserHandler(c *gin.Context) {
	// Check permission
	user := c.MustGet("user").(*models.User)
	if !hasAuthPermission(user, "auth.users.ban") && !hasAuthPermission(user, "auth.*") {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "РќРµС‚ РїСЂР°РІ РґР»СЏ СЂР°Р·Р±Р»РѕРєРёСЂРѕРІРєРё РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№"})
		return
	}

	userID := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "РќРµРІРµСЂРЅС‹Р№ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	err = models.UnbanUser(objectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "РћС€РёР±РєР° РїСЂРё СЂР°Р·Р±Р»РѕРєРёСЂРѕРІРєРµ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ СЂР°Р·Р±Р»РѕРєРёСЂРѕРІР°РЅ"})
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
	_ = c.MustGet("user").(*models.User)

	// NEW: Verify user has permission to view users
	if !requireAuthPermission(c, "auth.users.view") {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Access denied: insufficient permissions to view service logs",
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

// showEnhancedUserFormHandler shows the enhanced user creation/edit form with tabbed interface
func showEnhancedUserFormHandler(c *gin.Context) {
	// Get current logged in user for header
	currentUser := c.MustGet("user").(*models.User)

	userID := c.Param("id")
	debugLog("DEBUG: showEnhancedUserFormHandler called with userID: %s", userID)

	// Check if current user is a system admin (has god-like permissions)
	isGodUser := models.IsSystemAdmin(currentUser.ID)

	// Basic permission checks for user management
	canViewBasicInfo := isGodUser || hasAuthPermission(currentUser, "auth.users.view") || hasAuthPermission(currentUser, "auth.users.edit")
	canEditBasicInfo := isGodUser || hasAuthPermission(currentUser, "auth.users.edit")
	canViewDocuments := isGodUser || hasAuthPermission(currentUser, "auth.users.view") || hasAuthPermission(currentUser, "auth.documents.view")
	canManageDocuments := isGodUser || hasAuthPermission(currentUser, "auth.documents.manage")
	canViewRoles := isGodUser || hasAuthPermission(currentUser, "auth.users.view") || hasAuthPermission(currentUser, "auth.users.assign_roles")
	canManageRoles := isGodUser || hasAuthPermission(currentUser, "auth.users.assign_roles")
	canManageSystemAdmin := isGodUser // Only god can manage system admin status

	// Get all services for external roles
	allServices, err := models.GetAllServicesWithRolesForTemplate()
	if err != nil {
		log.Printf("Warning: Failed to get services: %v", err)
		allServices = []models.ServiceWithRoles{}
	}
	debugLog("DEBUG: Got %d services", len(allServices))

	// Separate auth-service internal roles from working services
	// Auth service key in DB is "auth", not "auth-service"
	var authServiceRoles []models.Role
	var workingServices []models.ServiceWithRolesGrouped

	// Collect external roles from auth service grouped by managed_service
	externalRolesByManagedService := make(map[string][]models.Role)
	for _, svc := range allServices {
		if svc.Key == "auth" {
			for _, role := range svc.Roles {
				if role.IsExternal() && role.ManagedService != "" {
					externalRolesByManagedService[role.ManagedService] = append(
						externalRolesByManagedService[role.ManagedService], role)
				} else {
					authServiceRoles = append(authServiceRoles, role)
				}
			}
		}
	}

	// Build working services (non-auth) with their internal roles + external roles from auth
	for _, svc := range allServices {
		if svc.Key == "auth" {
			continue
		}
		grouped := models.ServiceWithRolesGrouped{
			Service:       svc.Service,
			InternalRoles: svc.Roles,
			ExternalRoles: externalRolesByManagedService[svc.Key],
		}
		if grouped.InternalRoles == nil {
			grouped.InternalRoles = []models.Role{}
		}
		if grouped.ExternalRoles == nil {
			grouped.ExternalRoles = []models.Role{}
		}
		workingServices = append(workingServices, grouped)
	}

	// Build per-service permission map for working services
	servicePermissions := make(map[string]map[string]bool)
	for _, svc := range workingServices {
		perms := make(map[string]bool)
		// Check if user can view/manage roles for this specific service
		canViewServiceRoles := isGodUser ||
			hasAuthPermission(currentUser, fmt.Sprintf("auth.%s.roles.view", svc.Key)) ||
			hasAuthPermission(currentUser, fmt.Sprintf("auth.%s.roles.manage", svc.Key))
		canManageServiceRoles := isGodUser ||
			hasAuthPermission(currentUser, fmt.Sprintf("auth.%s.roles.manage", svc.Key)) ||
			hasAuthPermission(currentUser, fmt.Sprintf("auth.%s.roles.assign", svc.Key))

		// If user has global assign_roles permission, they can manage all services
		if hasAuthPermission(currentUser, "auth.users.assign_roles") {
			canViewServiceRoles = true
			canManageServiceRoles = true
		}

		perms["CanView"] = canViewServiceRoles
		perms["CanManage"] = canManageServiceRoles
		servicePermissions[svc.Key] = perms
	}

	// For system admin - we'll use a simple toggle instead of multiple roles
	var allRoles []models.Role // Empty slice - not using multiple system roles

	if userID != "" {
		// Edit mode
		debugLog("DEBUG: Edit mode for user ID: %s", userID)
		objectID, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			log.Printf("ERROR: Invalid user ID: %v", err)
			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"error": "РќРµРІРµСЂРЅС‹Р№ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ",
			})
			return
		}

		user, err := models.GetUserByID(objectID.Hex())
		if err != nil {
			log.Printf("ERROR: User not found: %v", err)
			c.HTML(http.StatusNotFound, "error.html", gin.H{
				"error": "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ РЅРµ РЅР°Р№РґРµРЅ",
			})
			return
		}
		debugLog("DEBUG: Found user: %s (%s)", user.Username, user.Email)

		// Get user's current service roles
		userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
		if err != nil {
			log.Printf("Warning: Failed to get user service roles: %v", err)
			userServiceRoles = []models.UserServiceRole{}
		}
		debugLog("DEBUG: User has %d service roles", len(userServiceRoles))

		// Check if user is system admin via user_service_roles
		isSystemAdmin := models.IsSystemAdmin(user.ID)
		debugLog("DEBUG: User is system admin: %t", isSystemAdmin)

		// Count documents and roles for badges
		documentCount := len(user.Documents)
		roleCount := len(userServiceRoles)

		templateData := gin.H{
			"title":         "Р РµРґР°РєС‚РёСЂРѕРІР°РЅРёРµ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ",
			"editingUser":   &user,
			"allRoles":      allRoles,
			"allServices":   allServices,
			"services":      allServices,
			"userRoles":     userServiceRoles,
			"isSystemAdmin": isSystemAdmin,
			"timestamp":     time.Now().Unix(),
			// Permission flags for tabbed UI
			"canViewBasicInfo":     canViewBasicInfo,
			"canEditBasicInfo":     canEditBasicInfo,
			"canViewDocuments":     canViewDocuments,
			"canManageDocuments":   canManageDocuments,
			"canViewRoles":         canViewRoles,
			"canManageRoles":       canManageRoles,
			"canManageSystemAdmin": canManageSystemAdmin,
			// Service-specific data
			"authServiceRoles":   authServiceRoles,
			"workingServices":    workingServices,
			"servicePermissions": servicePermissions,
			// Counts for badges
			"documentCount": documentCount,
			"roleCount":     roleCount,
			// Current user data for header
			"username":   currentUser.Username,
			"full_name":  currentUser.GetFullName(),
			"short_name": currentUser.GetShortName(),
			"user":       currentUser,
		}
		debugLog("DEBUG: Rendering user_edit_tabbed.html with template data")
		debugLog("DEBUG: currentUser.Username = %s", currentUser.Username)
		debugLog("DEBUG: currentUser.GetShortName() = %s", currentUser.GetShortName())
		c.HTML(http.StatusOK, "user_edit_tabbed.html", templateData)
	} else {
		// Create mode
		debugLog("DEBUG: Create mode")
		templateData := gin.H{
			"title":         "РЎРѕР·РґР°РЅРёРµ РЅРѕРІРѕРіРѕ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ",
			"allRoles":      allRoles,
			"allServices":   allServices,
			"userRoles":     []models.UserServiceRole{},
			"isSystemAdmin": false,
			// Permission flags for tabbed UI
			"canViewBasicInfo":     canViewBasicInfo,
			"canEditBasicInfo":     canEditBasicInfo,
			"canViewDocuments":     canViewDocuments,
			"canManageDocuments":   canManageDocuments,
			"canViewRoles":         canViewRoles,
			"canManageRoles":       canManageRoles,
			"canManageSystemAdmin": canManageSystemAdmin,
			// Service-specific data
			"authServiceRoles":   authServiceRoles,
			"workingServices":    workingServices,
			"servicePermissions": servicePermissions,
			// Counts for badges
			"documentCount": 0,
			"roleCount":     0,
			// Current user data for header
			"username":   currentUser.Username,
			"full_name":  currentUser.GetFullName(),
			"short_name": currentUser.GetShortName(),
			"user":       currentUser,
		}
		debugLog("DEBUG: Rendering user_edit_tabbed.html for new user")
		debugLog("DEBUG: CREATE MODE - currentUser.Username = %s", currentUser.Username)
		debugLog("DEBUG: CREATE MODE - currentUser.GetShortName() = %s", currentUser.GetShortName())
		c.HTML(http.StatusOK, "user_edit_tabbed.html", templateData)
	}
}

// debugUserRolesHandler shows debug information about user roles
func debugUserRolesHandler(c *gin.Context) {
	userID := c.Param("id")
	debugLog("DEBUG: debugUserRolesHandler called with userID: %s", userID)

	var allRoles []models.Role

	allServices, err := models.GetAllServicesWithRolesForTemplate()
	if err != nil {
		log.Printf("Warning: Failed to get services: %v", err)
		allServices = []models.ServiceWithRoles{}
	}
	debugLog("DEBUG: Got %d services", len(allServices))

	if userID != "" && userID != "new" {
		// Edit mode
		debugLog("DEBUG: Debug mode for user ID: %s", userID)
		objectID, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			log.Printf("ERROR: Invalid user ID: %v", err)
			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"error": "РќРµРІРµСЂРЅС‹Р№ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ",
			})
			return
		}

		user, err := models.GetUserByID(objectID.Hex())
		if err != nil {
			log.Printf("ERROR: User not found: %v", err)
			c.HTML(http.StatusNotFound, "error.html", gin.H{
				"error": "РџРѕР»СЊР·РѕРІР°С‚РµР»СЊ РЅРµ РЅР°Р№РґРµРЅ",
			})
			return
		}
		debugLog("DEBUG: Found user: %s (%s)", user.Username, user.Email)

		userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
		if err != nil {
			log.Printf("Warning: Failed to get user service roles: %v", err)
			userServiceRoles = []models.UserServiceRole{}
		}
		debugLog("DEBUG: User has %d service roles", len(userServiceRoles))

		isSystemAdmin := models.IsSystemAdmin(user.ID)

		templateData := gin.H{
			"title":         "Debug: Р РѕР»Рё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ",
			"user":          &user,
			"allRoles":      allRoles,
			"allServices":   allServices,
			"userRoles":     userServiceRoles,
			"isSystemAdmin": isSystemAdmin,
		}
		debugLog("DEBUG: Rendering debug_user_roles.html with template data")
		c.HTML(http.StatusOK, "debug_user_roles.html", templateData)
	} else {
		// Create mode
		debugLog("DEBUG: Create mode")
		templateData := gin.H{
			"title":         "РЎРѕР·РґР°РЅРёРµ РЅРѕРІРѕРіРѕ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ",
			"allRoles":      allRoles,
			"allServices":   allServices,
			"userRoles":     []models.UserServiceRole{}, // Empty roles for new user
			"isSystemAdmin": false,                      // Default for new users
		}
		debugLog("DEBUG: Rendering user_form.html for new user")
		c.HTML(http.StatusOK, "user_form.html", templateData)
	}
}

// usersManagementTestHandler displays test debug page
func usersManagementTestHandler(c *gin.Context) {
	users, err := models.GetAllUsers()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "РќРµ СѓРґР°Р»РѕСЃСЊ РїРѕР»СѓС‡РёС‚СЊ РїРѕР»СЊР·РѕРІР°С‚РµР»РµР№",
		})
		return
	}

	// Prepare users with their service roles
	usersWithRoles := buildUsersWithRoles(users)

	c.HTML(http.StatusOK, "users_management_test.html", gin.H{
		"title":          "РўР•РЎРўРћР’РђРЇ СЃС‚СЂР°РЅРёС†Р° СѓРїСЂР°РІР»РµРЅРёСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏРјРё",
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё РїРѕР»СѓС‡РµРЅРёРё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё РїРѕР»СѓС‡РµРЅРёРё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(documentID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID РґРѕРєСѓРјРµРЅС‚Р°"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Р”РѕРєСѓРјРµРЅС‚ РЅРµ РЅР°Р№РґРµРЅ"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ С„РѕСЂРјР°С‚ РґР°РЅРЅС‹С…"})
		return
	}

	if req.DocumentType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РўРёРї РґРѕРєСѓРјРµРЅС‚Р° РѕР±СЏР·Р°С‚РµР»РµРЅ"})
		return
	}

	if req.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќР°Р·РІР°РЅРёРµ РґРѕРєСѓРјРµРЅС‚Р° РѕР±СЏР·Р°С‚РµР»СЊРЅРѕ"})
		return
	}

	if len(req.AllowedServices) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Р’С‹Р±РµСЂРёС‚Рµ С…РѕС‚СЏ Р±С‹ РѕРґРёРЅ СЃРµСЂРІРёСЃ РґР»СЏ РёСЃРїРѕР»СЊР·РѕРІР°РЅРёСЏ РґРѕРєСѓРјРµРЅС‚Р°"})
		return
	}

	// Convert userID string to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Printf("Error converting user ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё СЃРѕР·РґР°РЅРёРё РґРѕРєСѓРјРµРЅС‚Р°"})
		return
	}

	log.Printf("Document created successfully by admin for user %s: %s", userID, req.Title)
	c.JSON(http.StatusCreated, gin.H{
		"message":       "Р”РѕРєСѓРјРµРЅС‚ СѓСЃРїРµС€РЅРѕ СЃРѕР·РґР°РЅ",
		"document_type": req.DocumentType,
		"title":         req.Title,
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё РїРѕР»СѓС‡РµРЅРёРё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID РґРѕРєСѓРјРµРЅС‚Р°"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Р”РѕРєСѓРјРµРЅС‚ РЅРµ РЅР°Р№РґРµРЅ"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ С„РѕСЂРјР°С‚ РґР°РЅРЅС‹С…"})
		return
	}

	// Convert userID string to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Printf("Error converting user ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	// Get user
	user, err := models.GetUserByID(userID)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё РїРѕР»СѓС‡РµРЅРёРё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID РґРѕРєСѓРјРµРЅС‚Р°"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Р”РѕРєСѓРјРµРЅС‚ РЅРµ РЅР°Р№РґРµРЅ"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё РѕР±РЅРѕРІР»РµРЅРёРё РґРѕРєСѓРјРµРЅС‚Р°"})
		return
	}

	log.Printf("Document %s updated successfully by admin for user %s", docID, userID)
	c.JSON(http.StatusOK, gin.H{
		"message":       "Р”РѕРєСѓРјРµРЅС‚ СѓСЃРїРµС€РЅРѕ РѕР±РЅРѕРІР»РµРЅ",
		"document_type": req.DocumentType,
		"title":         req.Title,
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё РїРѕР»СѓС‡РµРЅРёРё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID РґРѕРєСѓРјРµРЅС‚Р°"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Р”РѕРєСѓРјРµРЅС‚ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Remove document from user
	user.Documents = append(user.Documents[:docIndex], user.Documents[docIndex+1:]...)

	// Convert userID string to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Printf("Error converting user ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	// Update user in database
	if err := models.UpdateUserDocuments(userObjectID, user.Documents); err != nil {
		log.Printf("Error updating user documents: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё СѓРґР°Р»РµРЅРёРё РґРѕРєСѓРјРµРЅС‚Р°"})
		return
	}

	log.Printf("Document %s deleted successfully for user %s", docID, userID)
	c.JSON(http.StatusOK, gin.H{"message": "Р”РѕРєСѓРјРµРЅС‚ СѓСЃРїРµС€РЅРѕ СѓРґР°Р»РµРЅ"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "РћС€РёР±РєР° РѕР±СЂР°Р±РѕС‚РєРё С„РѕСЂРјС‹"})
		return
	}

	// Get uploaded file
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		log.Printf("Error getting file: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Р¤Р°Р№Р» РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}
	defer file.Close()

	// Get user
	user, err := models.GetUserByID(userID)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё РїРѕР»СѓС‡РµРЅРёРё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID РґРѕРєСѓРјРµРЅС‚Р°"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Р”РѕРєСѓРјРµРЅС‚ РЅРµ РЅР°Р№РґРµРЅ"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	// Update user in database
	if err := models.UpdateUserDocuments(userObjectID, user.Documents); err != nil {
		log.Printf("Error updating user documents: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё РґРѕР±Р°РІР»РµРЅРёРё С„Р°Р№Р»Р°"})
		return
	}

	log.Printf("Attachment %s added successfully to document %s for user %s", header.Filename, docID, userID)
	c.JSON(http.StatusCreated, gin.H{
		"message":  "Р¤Р°Р№Р» СѓСЃРїРµС€РЅРѕ РґРѕР±Р°РІР»РµРЅ",
		"filename": header.Filename,
		"size":     header.Size,
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё РїРѕР»СѓС‡РµРЅРёРё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID РґРѕРєСѓРјРµРЅС‚Р°"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Р”РѕРєСѓРјРµРЅС‚ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Convert attachment ID to ObjectID
	attachmentObjectID, err := primitive.ObjectIDFromHex(attachmentID)
	if err != nil {
		log.Printf("Error converting attachment ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID С„Р°Р№Р»Р°"})
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
		c.JSON(http.StatusNotFound, gin.H{"error": "Р¤Р°Р№Р» РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Convert userID string to ObjectID
	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Printf("Error converting user ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	// Update user in database
	if err := models.UpdateUserDocuments(userObjectID, user.Documents); err != nil {
		log.Printf("Error updating user documents: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё СѓРґР°Р»РµРЅРёРё С„Р°Р№Р»Р°"})
		return
	}

	log.Printf("Attachment %s removed successfully from document %s for user %s", attachmentID, docID, userID)
	c.JSON(http.StatusOK, gin.H{"message": "Р¤Р°Р№Р» СѓСЃРїРµС€РЅРѕ СѓРґР°Р»РµРЅ"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё РїРѕР»СѓС‡РµРЅРёРё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID РґРѕРєСѓРјРµРЅС‚Р°"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Р”РѕРєСѓРјРµРЅС‚ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Convert attachment ID to ObjectID
	attachmentObjectID, err := primitive.ObjectIDFromHex(attachmentID)
	if err != nil {
		log.Printf("Error converting attachment ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID С„Р°Р№Р»Р°"})
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
		c.JSON(http.StatusNotFound, gin.H{"error": "Р¤Р°Р№Р» РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// DEBUG: Log attachment details for download
	log.Printf("Found attachment: ID=%s, FileName=%s, OriginalName=%s, FilePath=%s",
		attachment.ID.Hex(), attachment.FileName, attachment.OriginalName, attachment.FilePath)

	// Check if FilePath is empty
	if attachment.FilePath == "" {
		log.Printf("FilePath is empty for attachment %s", attachmentID)
		c.JSON(http.StatusNotFound, gin.H{"error": "Р¤Р°Р№Р» РЅРµ Р±С‹Р» Р·Р°РіСЂСѓР¶РµРЅ РЅР° СЃРµСЂРІРµСЂ"})
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
				c.JSON(http.StatusNotFound, gin.H{"error": "Р¤Р°Р№Р» РЅРµ РЅР°Р№РґРµРЅ РЅР° РґРёСЃРєРµ"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "РћС€РёР±РєР° РїСЂРё РїРѕР»СѓС‡РµРЅРёРё РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ"})
		return
	}

	// Parse document index
	var docIndex int
	if _, err := fmt.Sscanf(docID, "%d", &docIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID РґРѕРєСѓРјРµРЅС‚Р°"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(user.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Р”РѕРєСѓРјРµРЅС‚ РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	// Convert attachment ID to ObjectID
	attachmentObjectID, err := primitive.ObjectIDFromHex(attachmentID)
	if err != nil {
		log.Printf("Error converting attachment ID to ObjectID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "РќРµРІРµСЂРЅС‹Р№ ID С„Р°Р№Р»Р°"})
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
		c.JSON(http.StatusNotFound, gin.H{"error": "Р¤Р°Р№Р» РЅРµ РЅР°Р№РґРµРЅ"})
		return
	}

	log.Printf("Attachment %s preview info retrieved successfully for user %s", attachmentID, userID)
	c.JSON(http.StatusOK, gin.H{
		"id":          attachment.ID.Hex(),
		"filename":    attachment.FileName,
		"size":        attachment.Size,
		"mime_type":   attachment.ContentType,
		"uploaded_at": attachment.UploadedAt,
		"preview_url": fmt.Sprintf("/api/users/%s/documents/%s/attachments/%s/download", userID, docID, attachmentID),
	})
}
