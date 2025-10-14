package routes

import (
	"auth-service/models"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// loginPageHandler serves the login page
func loginPageHandler(c *gin.Context) {
	message := c.Query("message")
	var successMessage string
	
	if message == "password_reset_success" {
		successMessage = "Пароль успешно изменен! Теперь вы можете войти с новым паролем."
	}
	
	c.HTML(http.StatusOK, "login_clean.html", gin.H{
		"redirect": c.Query("redirect"),
		"success":  successMessage,
	})
}

// loginHandler handles user login
func loginHandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	redirect := c.PostForm("redirect")

	user, valid := models.ValidateUser(username, password)
	if !valid {
		// Record failed login attempt
		RecordFailedLogin(c.ClientIP())
		c.HTML(http.StatusUnauthorized, "login_clean.html", gin.H{
			"error":    "Invalid username or password",
			"redirect": redirect,
		})
		return
	}

	// Check if user is banned
	if user.IsBanned {
		banMessage := "Ваш аккаунт заблокирован"
		if user.BanReason != "" {
			banMessage += ". Причина: " + user.BanReason
		}
		banMessage += ". Обратитесь к администратору для разблокировки."
		
		// Record failed login attempt for banned users
		RecordFailedLogin(c.ClientIP())
		c.HTML(http.StatusForbidden, "login_clean.html", gin.H{
			"error":    banMessage,
			"redirect": redirect,
		})
		return
	}

	// Generate token
	tokenString, err := models.GenerateToken(user)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "login_clean.html", gin.H{
			"error":    "Failed to generate token",
			"redirect": redirect,
		})
		return
	}

	// Set token in cookie with security flags
	// Secure flag: true for production (requires HTTPS)
	isProduction := os.Getenv("ENVIRONMENT") == "production"
	c.SetSameSite(http.SameSiteLaxMode) // Protection against CSRF
	c.SetCookie("token", tokenString, 86400, "/", "", isProduction, true) // 24 hours, httpOnly, secure in production

	// Reset rate limit on successful login
	ResetLoginAttempts(c.ClientIP())

	// Redirect to requested page or menu
	if redirect == "" {
		redirect = "/menu"
	}
	c.Redirect(http.StatusFound, redirect)
}

// logoutHandler handles user logout
func logoutHandler(c *gin.Context) {
	isProduction := os.Getenv("ENVIRONMENT") == "production"
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("token", "", -1, "/", "", isProduction, true) // Delete cookie
	c.Redirect(http.StatusFound, "/login")
}

// verifyAdminHandler checks if a request is from system administrator
func verifyAdminHandler(c *gin.Context) {
	cookie, err := c.Cookie("token")
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Parse and validate token
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(cookie, claims, func(token *jwt.Token) (interface{}, error) {
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			jwtSecret = "default_jwt_secret_change_in_production"
		}
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Get user info
	user, err := models.GetUserByID(claims.UserID)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Check if user is system admin
	if !hasAdminRole(user) {
		log.Printf("Access denied: user '%s' is not a system admin", user.Username)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// User is admin, return 200 OK
	c.Status(http.StatusOK)
}

// verifyHandler checks if a request is authenticated and has permission for the requested service
func verifyHandler(c *gin.Context) {
	log.Printf("DEBUG verifyHandler: incoming request from %s", c.ClientIP())
	cookie, err := c.Cookie("token")
	if err != nil {
		log.Printf("DEBUG verifyHandler: no token cookie found: %v", err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	log.Printf("DEBUG verifyHandler: found token cookie, length: %d", len(cookie))

	// Parse and validate token
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(cookie, claims, func(token *jwt.Token) (interface{}, error) {
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			jwtSecret = "default_jwt_secret_change_in_production"
		}
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Extract service name from request path
	path := c.Request.Header.Get("X-Original-URI")
	if path == "" {
		path = c.Request.URL.Path
	}

	log.Printf("DEBUG verifyHandler: X-Original-URI='%s', path='%s'", c.Request.Header.Get("X-Original-URI"), path)

	pathParts := strings.Split(path, "/")
	if len(pathParts) < 2 {
		log.Printf("DEBUG verifyHandler: pathParts too short: %v", pathParts)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// Get the first non-empty part which is the service name
	var service string
	for _, part := range pathParts {
		if part != "" {
			service = part
			break
		}
	}

	log.Printf("DEBUG verifyHandler: determined service='%s' from pathParts=%v", service, pathParts)

	// Get user info
	user, err := models.GetUserByID(claims.UserID)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Get user's roles and permissions for this service according to ADR-001
	serviceRoles, err := models.GetUserServiceRolesFromCollection(claims.UserID, service)
	if err != nil {
		log.Printf("DEBUG verifyHandler: error getting service roles: %v", err)
		serviceRoles = []string{} // Default to empty if error
	}

	servicePermissions, err := models.GetUserServicePermissions(claims.UserID, service)
	if err != nil {
		log.Printf("DEBUG verifyHandler: error getting service permissions: %v", err)
		servicePermissions = []string{} // Default to empty if error
	}

	log.Printf("DEBUG verifyHandler: user '%s', service '%s', serviceRoles: %v, servicePermissions: %v", user.Username, service, serviceRoles, servicePermissions)

	// Check if user has any access to this service
	if len(serviceRoles) == 0 && len(servicePermissions) == 0 {
		// Admin role always has access to all services (legacy support)
		if hasAdminRole(user) {
			serviceRoles = []string{"admin"}
			// For admin, get all available permissions for the service
			adminPermissions, _ := models.GetUserServicePermissions(claims.UserID, service)
			servicePermissions = adminPermissions
		} else if service == "referal" {
			// Temporary: Allow all authenticated users to access referal service
			serviceRoles = []string{"user"}
			servicePermissions = []string{"referal.profile.view", "referal.profile.edit"}
		} else {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
	}

	// Set user information in response headers according to ADR-001
	c.Header("X-User-Name", user.Username)
	c.Header("X-User-ID", claims.UserID)

	// Base64 encode the full name to preserve non-ASCII characters
	fullName := user.GetFullName()
	log.Printf("DEBUG verifyHandler: user.FullName='%s', user.LastName='%s', user.FirstName='%s', user.MiddleName='%s', calculated fullName='%s'", 
		user.FullName, user.LastName, user.FirstName, user.MiddleName, fullName)
	encodedFullName := base64.StdEncoding.EncodeToString([]byte(fullName))
	c.Header("X-User-Full-Name", encodedFullName)
	c.Header("X-User-Full-Name-Encoding", "base64") // Add flag to indicate encoding

	// Add avatar path header
	if user.AvatarPath != "" {
		c.Header("X-User-Avatar", user.AvatarPath)
	}

	// Add email header
	if user.Email != "" {
		c.Header("X-User-Email", user.Email)
		log.Printf("DEBUG verifyHandler: Setting X-User-Email header: '%s'", user.Email)
	} else {
		log.Printf("DEBUG verifyHandler: User email is empty, not setting X-User-Email header")
	}

	// Add phone header
	if user.Phone != "" {
		c.Header("X-User-Phone", user.Phone)
	}

	// Extract document data and add headers
	log.Printf("DEBUG verifyHandler: Starting document data extraction for user '%s'", user.Username)
	passportData := extractDocumentFields(user, "passport")
	pinflData := extractDocumentFields(user, "pinfl")
	bankData := extractDocumentFields(user, "bank_details")
	log.Printf("DEBUG verifyHandler: Document extraction complete: passport=%d fields, pinfl=%d fields, bank=%d fields", len(passportData), len(pinflData), len(bankData))

	// Add passport data headers
	if user.PassportNumber != "" {
		c.Header("X-User-Passport-Number", user.PassportNumber)
		log.Printf("DEBUG verifyHandler: Set X-User-Passport-Number from user.PassportNumber: '%s'", user.PassportNumber)
	} else if passportData["passport_number"] != nil {
		headerValue := fmt.Sprintf("%v", passportData["passport_number"])
		c.Header("X-User-Passport-Number", headerValue)
		log.Printf("DEBUG verifyHandler: Set X-User-Passport-Number from document: '%s'", headerValue)
	}
	
	if user.PassportIssuedBy != "" {
		c.Header("X-User-Passport-Giver", user.PassportIssuedBy)
		log.Printf("DEBUG verifyHandler: Set X-User-Passport-Giver from user.PassportIssuedBy: '%s'", user.PassportIssuedBy)
	} else if passportData["passport_giver"] != nil {
		headerValue := fmt.Sprintf("%v", passportData["passport_giver"])
		c.Header("X-User-Passport-Giver", headerValue)
		log.Printf("DEBUG verifyHandler: Set X-User-Passport-Giver from document: '%s'", headerValue)
	}
	
	if user.PassportIssuedDate != nil {
		headerValue := user.PassportIssuedDate.Format("2006-01-02")
		c.Header("X-User-Passport-Date", headerValue)
		log.Printf("DEBUG verifyHandler: Set X-User-Passport-Date from user.PassportIssuedDate: '%s'", headerValue)
	} else if passportData["passport_date"] != nil {
		headerValue := fmt.Sprintf("%v", passportData["passport_date"])
		c.Header("X-User-Passport-Date", headerValue)
		log.Printf("DEBUG verifyHandler: Set X-User-Passport-Date from document: '%s'", headerValue)
	}
	
	if user.Address != "" {
		c.Header("X-User-Passport-Address", user.Address)
		log.Printf("DEBUG verifyHandler: Set X-User-Passport-Address from user.Address: '%s'", user.Address)
	} else if passportData["passport_address"] != nil {
		headerValue := fmt.Sprintf("%v", passportData["passport_address"])
		c.Header("X-User-Passport-Address", headerValue)
		log.Printf("DEBUG verifyHandler: Set X-User-Passport-Address from document: '%s'", headerValue)
	}

	// Add PINFL header
	if pinflData["pinfl"] != nil {
		headerValue := fmt.Sprintf("%v", pinflData["pinfl"])
		c.Header("X-User-PINFL", headerValue)
		log.Printf("DEBUG verifyHandler: Set X-User-PINFL from document: '%s'", headerValue)
	}

	// Add bank data headers
	if bankData["bank_name"] != nil {
		headerValue := fmt.Sprintf("%v", bankData["bank_name"])
		c.Header("X-User-Bank-Name", headerValue)
		log.Printf("DEBUG verifyHandler: Set X-User-Bank-Name from document: '%s'", headerValue)
	}
	if bankData["card_number"] != nil {
		headerValue := fmt.Sprintf("%v", bankData["card_number"])
		c.Header("X-User-Bank-Card", headerValue)
		log.Printf("DEBUG verifyHandler: Set X-User-Bank-Card from document: '%s'", headerValue)
	}
	if bankData["mfo"] != nil {
		headerValue := fmt.Sprintf("%v", bankData["mfo"])
		c.Header("X-User-Bank-MFO", headerValue)
		log.Printf("DEBUG verifyHandler: Set X-User-Bank-MFO from document: '%s'", headerValue)
	}
	if bankData["trans_schet"] != nil {
		headerValue := fmt.Sprintf("%v", bankData["trans_schet"])
		c.Header("X-User-Bank-Account", headerValue)
		log.Printf("DEBUG verifyHandler: Set X-User-Bank-Account from document: '%s'", headerValue)
	}

	// ADR-001: New service-scoped headers
	c.Header("X-User-Service-Roles", strings.Join(serviceRoles, ","))
	c.Header("X-User-Service-Permissions", strings.Join(servicePermissions, ","))

	// Legacy headers for backward compatibility
	c.Header("X-User-Roles", strings.Join(user.Roles, ","))
	if hasAdminRole(user) {
		c.Header("X-User-Admin", "true")
	}

	log.Printf("DEBUG verifyHandler: FINAL HEADERS - X-User-Full-Name: '%s', X-User-Avatar: '%s', X-User-Email: '%s', X-User-Service-Roles: '%s', X-User-Service-Permissions: '%s'", 
		encodedFullName, user.AvatarPath, user.Email, strings.Join(serviceRoles, ","), strings.Join(servicePermissions, ","))

	c.Status(http.StatusOK)
}

// forgotPasswordPageHandler shows the forgot password page
func forgotPasswordPageHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "forgot-password.html", gin.H{})
}

// forgotPasswordHandler handles forgot password form submission
func forgotPasswordHandler(c *gin.Context) {
	identifier := c.PostForm("identifier")
	log.Printf("DEBUG: Forgot password request for identifier: %s", identifier)
	
	if identifier == "" {
		c.HTML(http.StatusBadRequest, "forgot-password.html", gin.H{
			"error": "Email или имя пользователя обязательны",
		})
		return
	}

	// Check if user exists by email or username
	log.Printf("DEBUG: Looking up user by identifier: %s", identifier)
	user, err := models.GetUserByEmailOrUsername(identifier)
	if err != nil || user == nil {
		// Don't reveal if user exists or not for security
		log.Printf("DEBUG: User not found for identifier: %s (err: %v)", identifier, err)
		c.HTML(http.StatusOK, "forgot-password-result.html", gin.H{
			"success": "Если учетная запись с таким email или именем пользователя существует, мы отправили ссылку для восстановления пароля",
		})
		return
	}

	log.Printf("DEBUG: User found: %s (email: %s)", user.Username, user.Email)

	// Check if user has a valid email address
	if user.Email == "" {
		log.Printf("User %s does not have an email address configured", user.Username)
		c.HTML(http.StatusBadRequest, "forgot-password-result.html", gin.H{
			"error": "У данной учетной записи не настроен email адрес. Обратитесь к администратору для настройки email или восстановления пароля.",
			"support_email": os.Getenv("SUPPORT_EMAIL"),
			"support_telegram": os.Getenv("SUPPORT_TELEGRAM"),
		})
		return
	}

	// Create password reset token using user's email
	log.Printf("DEBUG: Creating password reset token for email: %s", user.Email)
	token, err := models.CreatePasswordResetToken(user.Email)
	if err != nil {
		log.Printf("Error creating password reset token: %v", err)
		c.HTML(http.StatusInternalServerError, "forgot-password-result.html", gin.H{
			"error": fmt.Sprintf("Произошла ошибка при создании токена восстановления: %v", err),
		})
		return
	}
	// Security: Don't log tokens in production
	if os.Getenv("ENVIRONMENT") != "production" {
		log.Printf("DEBUG: Password reset token created for email: %s", user.Email)
	} else {
		log.Printf("Password reset token created for user: %s", user.Username)
	}

	// Get base URL from environment or use default
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost" // Default for development
	}
	
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", baseURL, token.Token)
	log.Printf("DEBUG: Reset link generated: %s", resetLink)
	
	// Send email with reset link using template
	emailSubject, emailBody := models.GetPasswordResetEmail(user.FullName, resetLink)
	log.Printf("DEBUG: Email template prepared, subject: %s", emailSubject)
	
	// Try to send email
	log.Printf("DEBUG: Calling SendEmailNotificationNew for: %s", user.Email)
	err = models.SendEmailNotificationNew(user.Email, emailSubject, emailBody)
	if err != nil {
		log.Printf("Failed to send password reset email to %s: %v", user.Email, err)
		c.HTML(http.StatusInternalServerError, "forgot-password-result.html", gin.H{
			"error": fmt.Sprintf("%v", err),
		})
		return
	}
	
	log.Printf("Password reset email sent successfully to %s", user.Email)

	c.HTML(http.StatusOK, "forgot-password-result.html", gin.H{
		"success": "Ссылка для восстановления пароля отправлена на ваш email. Проверьте почту и папку спам.",
	})
}

// resetPasswordPageHandler shows the reset password page
func resetPasswordPageHandler(c *gin.Context) {
	token := c.Query("token")
	
	if token == "" {
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error": "Токен восстановления не указан",
			"show_form": false,
		})
		return
	}

	// Validate token
	_, err := models.ValidatePasswordResetToken(token)
	if err != nil {
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error": "Недействительный или истекший токен восстановления",
			"show_form": false,
		})
		return
	}

	c.HTML(http.StatusOK, "reset-password.html", gin.H{
		"token": token,
		"show_form": true,
	})
}

// resetPasswordHandler handles password reset form submission
func resetPasswordHandler(c *gin.Context) {
	token := c.PostForm("token")
	newPassword := c.PostForm("new_password")
	confirmPassword := c.PostForm("confirm_password")

	if token == "" {
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error": "Токен восстановления не указан",
			"token": token,
			"show_form": false,
		})
		return
	}

	// Validate token before processing form
	_, err := models.ValidatePasswordResetToken(token)
	if err != nil {
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error": "Недействительный или истекший токен восстановления",
			"show_form": false,
		})
		return
	}

	if newPassword == "" || confirmPassword == "" {
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error": "Все поля обязательны для заполнения",
			"token": token,
			"show_form": true,
		})
		return
	}

	if newPassword != confirmPassword {
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error": "Пароли не совпадают",
			"token": token,
			"show_form": true,
		})
		return
	}

	if len(newPassword) < 6 {
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error": "Пароль должен содержать не менее 6 символов",
			"token": token,
			"show_form": true,
		})
		return
	}

	// Use the token to reset password
	err = models.UsePasswordResetToken(token, newPassword)
	if err != nil {
		log.Printf("Error using password reset token: %v", err)
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error": "Не удалось сбросить пароль. Токен может быть недействительным или истекшим",
			"show_form": false,
		})
		return
	}

	// Redirect to login page with success message
	c.Redirect(http.StatusFound, "/login?message=password_reset_success")
}

// extractDocumentFields extracts fields from user documents by document type
func extractDocumentFields(user *models.User, documentType string) map[string]interface{} {
	result := make(map[string]interface{})
	
	log.Printf("DEBUG extractDocumentFields: Looking for documentType='%s', user has %d documents", documentType, len(user.Documents))
	
	var candidateDocuments []models.UserDocument
	
	// Collect all documents of the required type
	for _, doc := range user.Documents {
		log.Printf("DEBUG extractDocumentFields: Found document type='%s', allowed_services=%v", doc.DocumentType, doc.AllowedServices)
		if doc.DocumentType == documentType || 
		   strings.HasPrefix(doc.DocumentType, documentType + "_") {
			candidateDocuments = append(candidateDocuments, doc)
		}
	}
	
	if len(candidateDocuments) == 0 {
		log.Printf("DEBUG extractDocumentFields: No documents found for type '%s'", documentType)
		return result
	}
	
	// Sort documents by priority:
	// 1. Documents with completed status
	// 2. Most recently updated
	sort.Slice(candidateDocuments, func(i, j int) bool {
		docA, docB := candidateDocuments[i], candidateDocuments[j]
		
		// Completed documents have higher priority
		if docA.Status != docB.Status {
			if docA.Status == "completed" { return true }
			if docB.Status == "completed" { return false }
		}
		
		// More recent documents have higher priority
		return docA.UpdatedAt.After(docB.UpdatedAt)
	})
	
	// Take the document with highest priority
	bestDoc := candidateDocuments[0]
	
	log.Printf("DEBUG extractDocumentFields: Selected best document: type=%s, status=%s, allowed_services=%v", 
			   bestDoc.DocumentType, bestDoc.Status, bestDoc.AllowedServices)
	
	// Extract fields from the best document
	for key, value := range bestDoc.Fields {
		result[strings.ToLower(key)] = value
		log.Printf("DEBUG extractDocumentFields: Added field '%s'='%v'", strings.ToLower(key), value)
	}
	
	log.Printf("DEBUG extractDocumentFields: Returning %d fields for type '%s': %v", len(result), documentType, result)
	return result
}
