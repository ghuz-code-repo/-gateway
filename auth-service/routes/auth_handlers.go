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

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// isDebugMode is set once at init вЂ” DEBUG logs are suppressed in production
var isDebugMode = os.Getenv("ENVIRONMENT") != "production"

// debugLog logs only when not in production (avoids PII leaks in logs)
func debugLog(format string, args ...interface{}) {
	if isDebugMode {
		log.Printf(format, args...)
	}
}

// loginPageHandler serves the login page
func loginPageHandler(c *gin.Context) {
	message := c.Query("message")
	var successMessage string

	if message == "password_reset_success" {
		successMessage = "РџР°СЂРѕР»СЊ СѓСЃРїРµС€РЅРѕ РёР·РјРµРЅРµРЅ! РўРµРїРµСЂСЊ РІС‹ РјРѕР¶РµС‚Рµ РІРѕР№С‚Рё СЃ РЅРѕРІС‹Рј РїР°СЂРѕР»РµРј."
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
		banMessage := "Р’Р°С€ Р°РєРєР°СѓРЅС‚ Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅ"
		if user.BanReason != "" {
			banMessage += ". РџСЂРёС‡РёРЅР°: " + user.BanReason
		}
		banMessage += ". РћР±СЂР°С‚РёС‚РµСЃСЊ Рє Р°РґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂСѓ РґР»СЏ СЂР°Р·Р±Р»РѕРєРёСЂРѕРІРєРё."

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
	c.SetSameSite(http.SameSiteLaxMode)                                   // Protection against CSRF
	c.SetCookie("token", tokenString, 28800, "/", "", isProduction, true) // 8 hours, httpOnly, secure in production

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
	// Use validateToken for consistent blacklist checking
	claims, valid := validateToken(cookie)
	if !valid {
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
	debugLog("DEBUG verifyHandler: incoming request from %s", c.ClientIP())
	cookie, err := c.Cookie("token")
	if err != nil {
		debugLog("DEBUG verifyHandler: no token cookie found: %v", err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	debugLog("DEBUG verifyHandler: found token cookie, length: %d", len(cookie))

	// Parse and validate token
	// Use validateToken for consistent blacklist checking
	claims, valid := validateToken(cookie)
	if !valid {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Extract service name from request path
	path := c.Request.Header.Get("X-Original-URI")
	if path == "" {
		path = c.Request.URL.Path
	}

	debugLog("DEBUG verifyHandler: X-Original-URI='%s', path='%s'", c.Request.Header.Get("X-Original-URI"), path)

	pathParts := strings.Split(path, "/")
	if len(pathParts) < 2 {
		debugLog("DEBUG verifyHandler: pathParts too short: %v", pathParts)
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

	debugLog("DEBUG verifyHandler: determined service='%s' from pathParts=%v", service, pathParts)

	// Get user info
	user, err := models.GetUserByID(claims.UserID)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Get user's roles and permissions for this service according to ADR-001
	serviceRoles, err := models.GetUserServiceRolesFromCollection(claims.UserID, service)
	if err != nil {
		debugLog("DEBUG verifyHandler: error getting service roles: %v", err)
		serviceRoles = []string{} // Default to empty if error
	}

	servicePermissions, err := models.GetUserServicePermissions(claims.UserID, service)
	if err != nil {
		debugLog("DEBUG verifyHandler: error getting service permissions: %v", err)
		servicePermissions = []string{} // Default to empty if error
	}

	debugLog("DEBUG verifyHandler: user '%s', service '%s', serviceRoles: %v, servicePermissions: %v", user.Username, service, serviceRoles, servicePermissions)

	// Check if user has any access to this service
	if len(serviceRoles) == 0 && len(servicePermissions) == 0 {
		// Admin role always has access to all services (legacy support)
		// Use pre-fetched roles to check admin status (avoid extra DB query)
		allRoles := fetchUserRoles(user)
		if hasAdminRoleWithRoles(allRoles, user.Username) {
			serviceRoles = []string{"admin"}
			// For admin, get all available permissions for the service
			adminPermissions, _ := models.GetUserServicePermissions(claims.UserID, service)
			servicePermissions = adminPermissions
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
	debugLog("DEBUG verifyHandler: user.FullName='%s', user.LastName='%s', user.FirstName='%s', user.MiddleName='%s', calculated fullName='%s'",
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
		debugLog("DEBUG verifyHandler: Setting X-User-Email header: '%s'", user.Email)
	} else {
		debugLog("DEBUG verifyHandler: User email is empty, not setting X-User-Email header")
	}

	// Add phone header
	if user.Phone != "" {
		c.Header("X-User-Phone", user.Phone)
	}

	// Extract document data and add headers
	debugLog("DEBUG verifyHandler: Starting document data extraction for user '%s'", user.Username)
	passportData := extractDocumentFields(user, "passport")
	pinflData := extractDocumentFields(user, "pinfl")
	bankData := extractDocumentFields(user, "bank_details")
	debugLog("DEBUG verifyHandler: Document extraction complete: passport=%d fields, pinfl=%d fields, bank=%d fields", len(passportData), len(pinflData), len(bankData))

	// Add passport data headers
	if user.PassportNumber != "" {
		c.Header("X-User-Passport-Number", user.PassportNumber)
		debugLog("DEBUG verifyHandler: Set X-User-Passport-Number from user.PassportNumber: '%s'", user.PassportNumber)
	} else if passportData["passport_number"] != nil {
		headerValue := fmt.Sprintf("%v", passportData["passport_number"])
		c.Header("X-User-Passport-Number", headerValue)
		debugLog("DEBUG verifyHandler: Set X-User-Passport-Number from document: '%s'", headerValue)
	}

	if user.PassportIssuedBy != "" {
		c.Header("X-User-Passport-Giver", user.PassportIssuedBy)
		debugLog("DEBUG verifyHandler: Set X-User-Passport-Giver from user.PassportIssuedBy: '%s'", user.PassportIssuedBy)
	} else if passportData["passport_giver"] != nil {
		headerValue := fmt.Sprintf("%v", passportData["passport_giver"])
		c.Header("X-User-Passport-Giver", headerValue)
		debugLog("DEBUG verifyHandler: Set X-User-Passport-Giver from document: '%s'", headerValue)
	}

	if user.PassportIssuedDate != nil {
		headerValue := user.PassportIssuedDate.Format("2006-01-02")
		c.Header("X-User-Passport-Date", headerValue)
		debugLog("DEBUG verifyHandler: Set X-User-Passport-Date from user.PassportIssuedDate: '%s'", headerValue)
	} else if passportData["passport_date"] != nil {
		headerValue := fmt.Sprintf("%v", passportData["passport_date"])
		c.Header("X-User-Passport-Date", headerValue)
		debugLog("DEBUG verifyHandler: Set X-User-Passport-Date from document: '%s'", headerValue)
	}

	if user.Address != "" {
		c.Header("X-User-Passport-Address", user.Address)
		debugLog("DEBUG verifyHandler: Set X-User-Passport-Address from user.Address: '%s'", user.Address)
	} else if passportData["passport_address"] != nil {
		headerValue := fmt.Sprintf("%v", passportData["passport_address"])
		c.Header("X-User-Passport-Address", headerValue)
		debugLog("DEBUG verifyHandler: Set X-User-Passport-Address from document: '%s'", headerValue)
	}

	// Add PINFL header
	if pinflData["pinfl"] != nil {
		headerValue := fmt.Sprintf("%v", pinflData["pinfl"])
		c.Header("X-User-PINFL", headerValue)
		debugLog("DEBUG verifyHandler: Set X-User-PINFL from document: '%s'", headerValue)
	}

	// Add bank data headers
	if bankData["bank_name"] != nil {
		headerValue := fmt.Sprintf("%v", bankData["bank_name"])
		c.Header("X-User-Bank-Name", headerValue)
		debugLog("DEBUG verifyHandler: Set X-User-Bank-Name from document: '%s'", headerValue)
	}
	if bankData["card_number"] != nil {
		headerValue := fmt.Sprintf("%v", bankData["card_number"])
		c.Header("X-User-Bank-Card", headerValue)
		debugLog("DEBUG verifyHandler: Set X-User-Bank-Card from document: '%s'", headerValue)
	}
	if bankData["mfo"] != nil {
		headerValue := fmt.Sprintf("%v", bankData["mfo"])
		c.Header("X-User-Bank-MFO", headerValue)
		debugLog("DEBUG verifyHandler: Set X-User-Bank-MFO from document: '%s'", headerValue)
	}
	if bankData["trans_schet"] != nil {
		headerValue := fmt.Sprintf("%v", bankData["trans_schet"])
		c.Header("X-User-Bank-Account", headerValue)
		debugLog("DEBUG verifyHandler: Set X-User-Bank-Account from document: '%s'", headerValue)
	}

	// ADR-001: New service-scoped headers
	c.Header("X-User-Service-Roles", strings.Join(serviceRoles, ","))
	c.Header("X-User-Service-Permissions", strings.Join(servicePermissions, ","))

	// Legacy header populated from user_service_roles for backward compatibility
	c.Header("X-User-Roles", strings.Join(serviceRoles, ","))
	if hasAdminRole(user) {
		c.Header("X-User-Admin", "true")
	}

	debugLog("DEBUG verifyHandler: FINAL HEADERS - X-User-Full-Name: '%s', X-User-Avatar: '%s', X-User-Email: '%s', X-User-Service-Roles: '%s', X-User-Service-Permissions: '%s'",
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
	debugLog("DEBUG: Forgot password request for identifier: %s", identifier)

	if identifier == "" {
		c.HTML(http.StatusBadRequest, "forgot-password.html", gin.H{
			"error": "Email РёР»Рё РёРјСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ РѕР±СЏР·Р°С‚РµР»СЊРЅС‹",
		})
		return
	}

	// Check if user exists by email or username
	debugLog("DEBUG: Looking up user by identifier: %s", identifier)
	user, err := models.GetUserByEmailOrUsername(identifier)
	if err != nil || user == nil {
		// Don't reveal if user exists or not for security
		debugLog("DEBUG: User not found for identifier: %s (err: %v)", identifier, err)
		c.HTML(http.StatusOK, "forgot-password-result.html", gin.H{
			"success": "Р•СЃР»Рё СѓС‡РµС‚РЅР°СЏ Р·Р°РїРёСЃСЊ СЃ С‚Р°РєРёРј email РёР»Рё РёРјРµРЅРµРј РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ СЃСѓС‰РµСЃС‚РІСѓРµС‚, РјС‹ РѕС‚РїСЂР°РІРёР»Рё СЃСЃС‹Р»РєСѓ РґР»СЏ РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёСЏ РїР°СЂРѕР»СЏ",
		})
		return
	}

	debugLog("DEBUG: User found: %s (email: %s)", user.Username, user.Email)

	// Check if user has a valid email address
	if user.Email == "" {
		log.Printf("User %s does not have an email address configured", user.Username)
		c.HTML(http.StatusBadRequest, "forgot-password-result.html", gin.H{
			"error":            "РЈ РґР°РЅРЅРѕР№ СѓС‡РµС‚РЅРѕР№ Р·Р°РїРёСЃРё РЅРµ РЅР°СЃС‚СЂРѕРµРЅ email Р°РґСЂРµСЃ. РћР±СЂР°С‚РёС‚РµСЃСЊ Рє Р°РґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂСѓ РґР»СЏ РЅР°СЃС‚СЂРѕР№РєРё email РёР»Рё РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёСЏ РїР°СЂРѕР»СЏ.",
			"support_email":    os.Getenv("SUPPORT_EMAIL"),
			"support_telegram": os.Getenv("SUPPORT_TELEGRAM"),
		})
		return
	}

	// Create password reset token using user's email
	debugLog("DEBUG: Creating password reset token for email: %s", user.Email)
	token, err := models.CreatePasswordResetToken(user.Email)
	if err != nil {
		log.Printf("Error creating password reset token: %v", err)
		c.HTML(http.StatusInternalServerError, "forgot-password-result.html", gin.H{
			"error": fmt.Sprintf("РџСЂРѕРёР·РѕС€Р»Р° РѕС€РёР±РєР° РїСЂРё СЃРѕР·РґР°РЅРёРё С‚РѕРєРµРЅР° РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёСЏ: %v", err),
		})
		return
	}
	// Security: Don't log tokens in production
	if os.Getenv("ENVIRONMENT") != "production" {
		debugLog("DEBUG: Password reset token created for email: %s", user.Email)
	} else {
		log.Printf("Password reset token created for user: %s", user.Username)
	}

	// Get base URL from environment or use default
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost" // Default for development
	}

	resetLink := fmt.Sprintf("%s/reset-password?token=%s", baseURL, token.Token)
	debugLog("DEBUG: Reset link generated: %s", resetLink)

	// Send email with reset link using template
	emailSubject, emailBody := models.GetPasswordResetEmail(user.FullName, resetLink)
	debugLog("DEBUG: Email template prepared, subject: %s", emailSubject)

	// Try to send email
	debugLog("DEBUG: Calling SendEmailNotificationNew for: %s", user.Email)
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
		"success": "РЎСЃС‹Р»РєР° РґР»СЏ РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёСЏ РїР°СЂРѕР»СЏ РѕС‚РїСЂР°РІР»РµРЅР° РЅР° РІР°С€ email. РџСЂРѕРІРµСЂСЊС‚Рµ РїРѕС‡С‚Сѓ Рё РїР°РїРєСѓ СЃРїР°Рј.",
	})
}

// resetPasswordPageHandler shows the reset password page
func resetPasswordPageHandler(c *gin.Context) {
	token := c.Query("token")

	if token == "" {
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error":     "РўРѕРєРµРЅ РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёСЏ РЅРµ СѓРєР°Р·Р°РЅ",
			"show_form": false,
		})
		return
	}

	// Validate token
	_, err := models.ValidatePasswordResetToken(token)
	if err != nil {
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error":     "РќРµРґРµР№СЃС‚РІРёС‚РµР»СЊРЅС‹Р№ РёР»Рё РёСЃС‚РµРєС€РёР№ С‚РѕРєРµРЅ РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёСЏ",
			"show_form": false,
		})
		return
	}

	c.HTML(http.StatusOK, "reset-password.html", gin.H{
		"token":     token,
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
			"error":     "РўРѕРєРµРЅ РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёСЏ РЅРµ СѓРєР°Р·Р°РЅ",
			"token":     token,
			"show_form": false,
		})
		return
	}

	// Validate token before processing form
	_, err := models.ValidatePasswordResetToken(token)
	if err != nil {
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error":     "РќРµРґРµР№СЃС‚РІРёС‚РµР»СЊРЅС‹Р№ РёР»Рё РёСЃС‚РµРєС€РёР№ С‚РѕРєРµРЅ РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёСЏ",
			"show_form": false,
		})
		return
	}

	if newPassword == "" || confirmPassword == "" {
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error":     "Р’СЃРµ РїРѕР»СЏ РѕР±СЏР·Р°С‚РµР»СЊРЅС‹ РґР»СЏ Р·Р°РїРѕР»РЅРµРЅРёСЏ",
			"token":     token,
			"show_form": true,
		})
		return
	}

	if newPassword != confirmPassword {
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error":     "РџР°СЂРѕР»Рё РЅРµ СЃРѕРІРїР°РґР°СЋС‚",
			"token":     token,
			"show_form": true,
		})
		return
	}

	if err := models.ValidatePassword(newPassword); err != nil {
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error":     err.Error(),
			"token":     token,
			"show_form": true,
		})
		return
	}

	// Use the token to reset password
	err = models.UsePasswordResetToken(token, newPassword)
	if err != nil {
		log.Printf("Error using password reset token: %v", err)
		c.HTML(http.StatusBadRequest, "reset-password.html", gin.H{
			"error":     "РќРµ СѓРґР°Р»РѕСЃСЊ СЃР±СЂРѕСЃРёС‚СЊ РїР°СЂРѕР»СЊ. РўРѕРєРµРЅ РјРѕР¶РµС‚ Р±С‹С‚СЊ РЅРµРґРµР№СЃС‚РІРёС‚РµР»СЊРЅС‹Рј РёР»Рё РёСЃС‚РµРєС€РёРј",
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

	debugLog("DEBUG extractDocumentFields: Looking for documentType='%s', user has %d documents", documentType, len(user.Documents))

	var candidateDocuments []models.UserDocument

	// Collect all documents of the required type
	for _, doc := range user.Documents {
		debugLog("DEBUG extractDocumentFields: Found document type='%s', allowed_services=%v", doc.DocumentType, doc.AllowedServices)
		if doc.DocumentType == documentType ||
			strings.HasPrefix(doc.DocumentType, documentType+"_") {
			candidateDocuments = append(candidateDocuments, doc)
		}
	}

	if len(candidateDocuments) == 0 {
		debugLog("DEBUG extractDocumentFields: No documents found for type '%s'", documentType)
		return result
	}

	// Sort documents by priority:
	// 1. Documents with completed status
	// 2. Most recently updated
	sort.Slice(candidateDocuments, func(i, j int) bool {
		docA, docB := candidateDocuments[i], candidateDocuments[j]

		// Completed documents have higher priority
		if docA.Status != docB.Status {
			if docA.Status == "completed" {
				return true
			}
			if docB.Status == "completed" {
				return false
			}
		}

		// More recent documents have higher priority
		return docA.UpdatedAt.After(docB.UpdatedAt)
	})

	// Take the document with highest priority
	bestDoc := candidateDocuments[0]

	debugLog("DEBUG extractDocumentFields: Selected best document: type=%s, status=%s, allowed_services=%v",
		bestDoc.DocumentType, bestDoc.Status, bestDoc.AllowedServices)

	// Extract fields from the best document
	for key, value := range bestDoc.Fields {
		result[strings.ToLower(key)] = value
		debugLog("DEBUG extractDocumentFields: Added field '%s'='%v'", strings.ToLower(key), value)
	}

	debugLog("DEBUG extractDocumentFields: Returning %d fields for type '%s': %v", len(result), documentType, result)
	return result
}

// verifyLogsAccessHandler checks if user has permission to view logs for specific service
// Returns headers for Dozzle forward-proxy authentication
func verifyLogsAccessHandler(c *gin.Context) {
	serviceKey := c.Query("service")

	cookie, err := c.Cookie("token")
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Parse and validate token
	// Use validateToken for consistent blacklist checking
	claims, valid := validateToken(cookie)
	if !valid {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Get user info
	user, err := models.GetUserByID(claims.UserID)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	isAdmin := hasAdminRole(user)

	// If serviceKey is specified, always apply filter (even for admins on service-specific page)
	if serviceKey != "" {
		// Check permission for non-admins
		if !isAdmin {
			isServiceMgr := hasServiceManagerRole(user, serviceKey)
			if !isServiceMgr {
				// Check all possible logs permissions:
				// - auth.logs.system.view (auth service system logs)
				// - auth.logs.view (global logs permission)
				// - auth.<serviceKey>.logs.view (per-service logs permission)
				var hasPermission bool
				if serviceKey == "auth" {
					hasPermission = models.HasAuthPermission(user.ID, "auth.logs.system.view")
				} else {
					servicePermPrefix := fmt.Sprintf("auth.%s.", serviceKey)
					hasPermission = models.HasAuthPermission(user.ID, "auth.logs.view") ||
						models.HasAuthPermission(user.ID, servicePermPrefix+"logs.view")
				}

				if !hasPermission {
					log.Printf("Access denied: user '%s' does not have logs permission for service '%s'", user.Username, serviceKey)
					c.AbortWithStatus(http.StatusForbidden)
					return
				}
			}
		}

		// Build container filter based on service
		containerFilter := getContainerFilterForService(serviceKey)
		log.Printf("[LOGS] Service-specific access: user=%s service=%s filter=%s", user.Username, serviceKey, containerFilter)

		c.Header("Remote-User", user.Username)
		c.Header("Remote-Email", user.Email)
		c.Header("Remote-Name", user.GetFullName())
		c.Header("Remote-Filter", containerFilter)
		c.Status(http.StatusOK)
		return
	}

	// No serviceKey - this is either /logs page or internal Dozzle request
	// For admins, allow everything without filter
	if isAdmin {
		c.Header("Remote-User", user.Username)
		c.Header("Remote-Email", user.Email)
		c.Header("Remote-Name", user.GetFullName())
		log.Printf("[LOGS] Admin access: user=%s (no filter)", user.Username)
		c.Status(http.StatusOK)
		return
	}

	// For non-admins, check if they have logs.view permission for ANY service
	// and build a combined filter that will be applied to ALL requests
	allowedServices := getAllowedLogsServices(user.ID)
	if len(allowedServices) == 0 {
		log.Printf("Access denied: user '%s' has no logs.view permissions for any service", user.Username)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// Build combined filter for all allowed services
	var filters []string
	for _, svc := range allowedServices {
		filters = append(filters, getContainerFilterForService(svc))
	}
	combinedFilter := strings.Join(filters, ",")
	log.Printf("[LOGS] Non-admin access: user=%s allowedServices=%v filter=%s", user.Username, allowedServices, combinedFilter)

	c.Header("Remote-User", user.Username)
	c.Header("Remote-Email", user.Email)
	c.Header("Remote-Name", user.GetFullName())
	c.Header("Remote-Filter", combinedFilter)
	c.Status(http.StatusOK)
}

// getAllowedLogsServices returns list of services user has logs.view permission for
func getAllowedLogsServices(userID primitive.ObjectID) []string {
	// All external services (everything except auth)
	externalServices := []string{"referal", "client-service", "notification", "monitoring"}
	var allowed []string

	// auth.logs.view gives access to ALL external services (not auth)
	if models.HasAuthPermission(userID, "auth.logs.view") {
		allowed = append(allowed, externalServices...)
	} else {
		// Check per-service logs permissions
		for _, svc := range externalServices {
			if models.HasAuthPermission(userID, fmt.Sprintf("auth.%s.logs.view", svc)) {
				allowed = append(allowed, svc)
			}
		}
	}

	// auth.logs.system.view gives access to auth-service logs specifically
	if models.HasAuthPermission(userID, "auth.logs.system.view") {
		allowed = append(allowed, "auth")
	}

	return allowed
}

// getContainerFilterForService returns container name filter for a service
func getContainerFilterForService(serviceKey string) string {
	// Map service keys to container name patterns
	// Dozzle uses Docker label filters or name filters
	containerPatterns := map[string]string{
		"referal":        "name=referal*",
		"client-service": "name=client*",
		"notification":   "name=notification*",
		"monitoring":     "name=monitoring*",
		"auth":           "name=gateway-auth*,name=gateway-mongo*",
	}

	if pattern, ok := containerPatterns[serviceKey]; ok {
		return pattern
	}

	// Default: filter by service key prefix
	return fmt.Sprintf("name=%s*", serviceKey)
}
