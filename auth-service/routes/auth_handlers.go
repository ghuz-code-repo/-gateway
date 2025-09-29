package routes

import (
	"auth-service/models"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
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

	// Set token in cookie
	c.SetCookie("token", tokenString, 86400, "/", "", false, true) // 24 hours, http only

	// Redirect to requested page or menu
	if redirect == "" {
		redirect = "/menu"
	}
	c.Redirect(http.StatusFound, redirect)
}

// logoutHandler handles user logout
func logoutHandler(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "", false, true) // Delete cookie
	c.Redirect(http.StatusFound, "/login")
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

	// ADR-001: New service-scoped headers
	c.Header("X-User-Service-Roles", strings.Join(serviceRoles, ","))
	c.Header("X-User-Service-Permissions", strings.Join(servicePermissions, ","))

	// Legacy headers for backward compatibility
	c.Header("X-User-Roles", strings.Join(user.Roles, ","))
	if hasAdminRole(user) {
		c.Header("X-User-Admin", "true")
	}

	log.Printf("DEBUG verifyHandler: FINAL HEADERS - X-User-Full-Name: '%s', X-User-Avatar: '%s', X-User-Service-Roles: '%s'", 
		encodedFullName, user.AvatarPath, strings.Join(serviceRoles, ","))

	c.Status(http.StatusOK)
}

// forgotPasswordPageHandler shows the forgot password page
func forgotPasswordPageHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "forgot-password.html", gin.H{})
}

// forgotPasswordHandler handles forgot password form submission
func forgotPasswordHandler(c *gin.Context) {
	identifier := c.PostForm("identifier")
	
	if identifier == "" {
		c.HTML(http.StatusBadRequest, "forgot-password.html", gin.H{
			"error": "Email или имя пользователя обязательны",
		})
		return
	}

	// Check if user exists by email or username
	user, err := models.GetUserByEmailOrUsername(identifier)
	if err != nil || user == nil {
		// Don't reveal if user exists or not for security
		c.HTML(http.StatusOK, "forgot-password-result.html", gin.H{
			"success": "Если учетная запись с таким email или именем пользователя существует, мы отправили ссылку для восстановления пароля",
		})
		return
	}

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
	token, err := models.CreatePasswordResetToken(user.Email)
	if err != nil {
		log.Printf("Error creating password reset token: %v", err)
		c.HTML(http.StatusInternalServerError, "forgot-password-result.html", gin.H{
			"error": fmt.Sprintf("Произошла ошибка при создании токена восстановления: %v", err),
		})
		return
	}

	// Get base URL from environment or use default
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost" // Default for development
	}
	
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", baseURL, token.Token)
	
	// Send email with reset link using template
	emailSubject, emailBody := models.GetPasswordResetEmail(user.FullName, resetLink)
	
	// Try to send email
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
