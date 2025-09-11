package routes

import (
	"auth-service/models"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// SetupAuthRoutes configures all the routes for authentication
func SetupAuthRoutes(router *gin.Engine) {
	// Auth routes
	router.GET("/", homeHandler)
	router.GET("/menu", menuHandler) // New menu handler
	router.GET("/login", loginPageHandler)
	router.POST("/login", loginHandler)
	router.GET("/logout", logoutHandler)
	router.GET("/verify", verifyHandler)

	// New document system routes
	router.GET("/document-types", authRequired(), getDocumentTypesHandler)

	// Set up admin routes using the function from admin.go
	SetupAdminRoutes(router)
	
	// Set up profile routes
	SetupProfileRoutes(router)
}

// homeHandler handles the home page
func homeHandler(c *gin.Context) {
	c.Redirect(http.StatusFound, "/menu")
}

// getServiceDisplayName returns a user-friendly name for a service
func getServiceDisplayName(serviceKey string) string {
	// Try to get the display name from services collection
	service, err := models.GetServiceByKey(serviceKey)
	if err == nil && service != nil && service.Name != "" {
		return service.Name
	}

	// Fallback to permissions collection for backward compatibility
	permission, err := models.GetPermissionByService(serviceKey)
	if err == nil && permission.DisplayName != "" {
		return permission.DisplayName
	}

	// Default to the original service key if not found
	return serviceKey
}

// menuHandler shows the list of accessible services
func menuHandler(c *gin.Context) {
	// Check if user is authenticated
	cookie, err := c.Cookie("token")
	if err != nil {
		c.Redirect(http.StatusFound, "/login?redirect=/menu")
		return
	}

	// Validate token
	claims := &models.Claims{}
	token, err := jwt.ParseWithClaims(cookie, claims, func(token *jwt.Token) (interface{}, error) {
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			jwtSecret = "default_jwt_secret_change_in_production"
		}
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		c.Redirect(http.StatusFound, "/login?redirect=/menu")
		return
	}

	// Get user info
	user, err := models.GetUserByID(claims.UserID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "Не удалось получить данные пользователя",
		})
		return
	}

	// Get user's accessible services based on their service roles
	accessibleServices := []string{}

	// Check if user is admin (has admin role in old system or system service)
	isAdmin := hasAdminRole(user)
	
	if isAdmin {
		fmt.Println("Пользователь является администратором. Добавление всех сервисов.")
		// Admin users can access all services
		services, err := models.GetAllServices()
		if err != nil {
			fmt.Printf("Ошибка получения сервисов для админа: %v\n", err)
		} else {
			for _, service := range services {
				accessibleServices = append(accessibleServices, service.Key)
			}
		}
	} else {
		// For regular users, get services where they have roles
		userAccessibleServices, err := models.GetUserAccessibleServices(user.ID)
		if err != nil {
			fmt.Printf("Ошибка получения доступных сервисов для пользователя %s: %v\n", user.Username, err)
		} else {
			accessibleServices = userAccessibleServices
		}
		
		// Also include services from old role system for backward compatibility
		roles, err := models.GetAllRoles()
		if err == nil {
			for _, userRole := range user.Roles {
				for _, role := range roles {
					if role.Name == userRole && role.ServiceKey != "" {
						if !contains(accessibleServices, role.ServiceKey) {
							accessibleServices = append(accessibleServices, role.ServiceKey)
						}
					}
				}
			}
		}
	}

	// Debug output
	fmt.Printf("Доступные сервисы для пользователя %s: %v\n", user.Username, accessibleServices)
	fmt.Printf("Пользователь %s является админом: %v\n", user.Username, isAdmin)

	// Create a slice of service infos with display names
	serviceInfos := []gin.H{}
	for _, serviceKey := range accessibleServices {
		serviceInfo := gin.H{
			"id":          serviceKey,
			"displayName": getServiceDisplayName(serviceKey),
			"icon":        getIconForService(serviceKey),
		}
		
		// Check if user can manage this service (system admin OR service admin)
		canManageService := isAdmin || hasServiceAdminRole(user, serviceKey)
		serviceInfo["canManage"] = canManageService
		
		if canManageService {
			service, err := models.GetServiceByKey(serviceKey)
			if err == nil && service != nil {
				serviceInfo["serviceId"] = service.ID.Hex()
				fmt.Printf("Добавлен serviceId для %s: %s (isSystemAdmin: %v, isServiceAdmin: %v)\n", 
					serviceKey, service.ID.Hex(), isAdmin, hasServiceAdminRole(user, serviceKey))
			} else {
				fmt.Printf("Ошибка получения сервиса для %s: %v\n", serviceKey, err)
			}
		}
		
		serviceInfos = append(serviceInfos, serviceInfo)
	}

	c.HTML(http.StatusOK, "menu.html", gin.H{
		"username":     user.Username,
		"full_name":    user.FullName,
		"services":     accessibleServices, // Keep for backward compatibility
		"serviceInfos": serviceInfos,       // New structure with display names
		"isAdmin":      hasAdminRole(user),
		"role":         user.Roles,
	})
}

// Helper function to check if a slice contains a string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// loginPageHandler serves the login page
func loginPageHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"redirect": c.Query("redirect"),
	})
}

// loginHandler handles user login
func loginHandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	redirect := c.PostForm("redirect")

	user, valid := models.ValidateUser(username, password)
	if !valid {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"error":    "Invalid username or password",
			"redirect": redirect,
		})
		return
	}

	// Generate token
	tokenString, err := models.GenerateToken(user)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{
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

	// Extract service name from request path
	path := c.Request.Header.Get("X-Original-URI")
	if path == "" {
		path = c.Request.URL.Path
	}

	pathParts := strings.Split(path, "/")
	if len(pathParts) < 2 {
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

	// Get user info
	user, err := models.GetUserByID(claims.UserID)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Get user's roles and permissions for this service according to ADR-001
	serviceRoles, err := models.GetUserServiceRoles(claims.UserID, service)
	if err != nil {
		serviceRoles = []string{} // Default to empty if error
	}

	servicePermissions, err := models.GetUserServicePermissions(claims.UserID, service)
	if err != nil {
		servicePermissions = []string{} // Default to empty if error
	}

	// Check if user has any access to this service
	if len(serviceRoles) == 0 && len(servicePermissions) == 0 {
		// Admin role always has access to all services (legacy support)
		if hasAdminRole(user) {
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
	encodedFullName := base64.StdEncoding.EncodeToString([]byte(user.FullName))
	c.Header("X-User-Full-Name", encodedFullName)
	c.Header("X-User-Full-Name-Encoding", "base64") // Add flag to indicate encoding

	// ADR-001: New service-scoped headers
	c.Header("X-User-Service-Roles", strings.Join(serviceRoles, ","))
	c.Header("X-User-Service-Permissions", strings.Join(servicePermissions, ","))

	// Legacy headers for backward compatibility
	c.Header("X-User-Roles", strings.Join(user.Roles, ","))
	if hasAdminRole(user) {
		c.Header("X-User-Admin", "true")
	}

	c.Status(http.StatusOK)
}

// adminMiddleware checks if the user has admin role
func adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie("token")
		if err != nil {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
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
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Get user info
		user, err := models.GetUserByID(claims.UserID)
		if err != nil {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Check if user has admin role
		if !hasAdminRole(user) {
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"error": "Access denied. Admin role required.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// hasAdminRole checks if a user is a system administrator
func hasAdminRole(user *models.User) bool {
	// Only the 'administrator' user is a true system admin
	// who can manage all services and access admin panel
	return user.Username == "administrator"
}

// hasServiceAdminRole checks if a user has admin role in a specific service
func hasServiceAdminRole(user *models.User, serviceKey string) bool {
	// Get user's service roles using ADR-001 system
	userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
	if err != nil {
		fmt.Printf("Ошибка получения ролей для пользователя %s: %v\n", user.Username, err)
		return false
	}
	
	// Check if user has 'admin' role in this specific service
	for _, role := range userServiceRoles {
		if role.ServiceKey == serviceKey && role.RoleName == "admin" && role.IsActive {
			fmt.Printf("Пользователь %s является админом сервиса %s\n", user.Username, serviceKey)
			return true
		}
	}
	
	fmt.Printf("Пользователь %s НЕ является админом сервиса %s\n", user.Username, serviceKey)
	return false
}

// getIconForService returns an appropriate Font Awesome icon for each service
func getIconForService(service string) string {
	// Get icon from database if available
	permission, err := models.GetPermissionByService(service)
	if err == nil && permission.Icon != "" {
		return permission.Icon
	}

	// Default icon if no specific icon is defined
	return "link"
}

// authRequired middleware checks if user is authenticated
func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie("token")
		if err != nil {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Parse and validate token
		claims, valid := validateToken(cookie)
		if !valid {
			c.Redirect(http.StatusFound, "/login?redirect="+c.Request.URL.Path)
			c.Abort()
			return
		}

		// Get user info
		user, err := models.GetUserByID(claims.UserID)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"error": "Не удалось получить данные пользователя",
			})
			c.Abort()
			return
		}

		// Store user info for handlers
		c.Set("user", user)
		c.Set("username", user.Username)
		c.Set("full_name", user.FullName)
		c.Next()
	}
}

// profileHandler shows the user profile page
func profileHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	
	// Get user's service roles
	userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
	if err != nil {
		userServiceRoles = []models.UserServiceRole{}
	}

	// Group roles by service
	serviceRolesMap := make(map[string][]string)
	for _, usr := range userServiceRoles {
		if usr.IsActive {
			serviceRolesMap[usr.ServiceKey] = append(serviceRolesMap[usr.ServiceKey], usr.RoleName)
		}
	}

	// Get service display names
	services, _ := models.GetAllServices()
	serviceNames := make(map[string]string)
	for _, service := range services {
		serviceNames[service.Key] = service.Name
	}

	// Prepare user roles for template
	var userRoles []map[string]interface{}
	for serviceKey, roles := range serviceRolesMap {
		serviceName := serviceNames[serviceKey]
		if serviceName == "" {
			serviceName = serviceKey
		}
		userRoles = append(userRoles, map[string]interface{}{
			"ServiceKey":  serviceKey,
			"ServiceName": serviceName,
			"Roles":       roles,
		})
	}

	c.HTML(http.StatusOK, "profile.html", gin.H{
		"title":         "Личный кабинет",
		"username":      user.Username,
		"full_name":     user.FullName,
		"user":          user,
		"userRoles":     userRoles,
		"serviceRoles":  serviceRolesMap,
		"serviceNames":  serviceNames,
	})
}

// updateProfileHandler updates user profile information
func updateProfileHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	email := c.PostForm("email")
	fullName := c.PostForm("full_name")
	phone := c.PostForm("phone")
	position := c.PostForm("position")
	department := c.PostForm("department")

	err := models.UpdateUserProfile(user.ID, email, fullName, phone, position, department)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить профиль"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Профиль успешно обновлен"})
}

// createUserDirectoryStructure creates the directory structure for a user
func createUserDirectoryStructure(userID primitive.ObjectID) (string, error) {
	userDir := filepath.Join("/data", userID.Hex())
	documentsDir := filepath.Join(userDir, "documents")
	
	// Create user directory
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create user directory: %v", err)
	}
	
	// Create documents directory
	if err := os.MkdirAll(documentsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create documents directory: %v", err)
	}
	
	return userDir, nil
}

// createDocumentTypeDirectory creates a directory for a specific document type
func createDocumentTypeDirectory(userID primitive.ObjectID, documentType string) (string, error) {
	userDir := filepath.Join("/data", userID.Hex())
	documentsDir := filepath.Join(userDir, "documents")
	typeDir := filepath.Join(documentsDir, documentType)
	
	// Create the document type directory
	if err := os.MkdirAll(typeDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create document type directory: %v", err)
	}
	
	return typeDir, nil
}

// sanitizeFilename удаляет небезопасные символы из имени файла
func sanitizeFilename(filename string) string {
	// Убираем расширение
	ext := filepath.Ext(filename)
	name := filename[:len(filename)-len(ext)]
	
	// Заменяем небезопасные символы на подчеркивания
	reg := regexp.MustCompile(`[<>:"/\\|?*\s]+`)
	name = reg.ReplaceAllString(name, "_")
	
	// Убираем лишние подчеркивания
	reg = regexp.MustCompile(`_+`)
	name = reg.ReplaceAllString(name, "_")
	
	// Убираем подчеркивания в начале и конце
	name = strings.Trim(name, "_")
	
	// Ограничиваем длину
	if len(name) > 50 {
		name = name[:50]
	}
	
	if name == "" {
		name = "file"
	}
	
	return name + ext
}

// uploadAvatarHandler handles avatar upload with crop coordinates
func uploadAvatarHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	// Check if this is a crop update or new upload
	cropUpdate := c.PostForm("crop_update") == "true"
	
	if cropUpdate {
		// Handle crop coordinate update for existing image
		handleCropUpdate(c, user)
		return
	}

	// Handle new file upload
	file, err := c.FormFile("avatar")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не удалось получить файл"})
		return
	}

	// Check file type
	if !strings.HasPrefix(file.Header.Get("Content-Type"), "image/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Файл должен быть изображением"})
		return
	}

	// Check file size (max 5MB)
	if file.Size > 5*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Размер файла не должен превышать 5MB"})
		return
	}

	// Create user directory structure
	userDir, err := createUserDirectoryStructure(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать директорию пользователя"})
		return
	}
	
	// Generate filenames - теперь просто avatar.jpg и original.jpg
	ext := filepath.Ext(file.Filename)
	if ext == "" {
		ext = ".jpg" // default extension
	}
	
	originalPath := filepath.Join(userDir, "original"+ext)
	croppedPath := filepath.Join(userDir, "avatar"+ext)

	// Save original file
	if err := c.SaveUploadedFile(file, originalPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сохранить оригинальный файл"})
		return
	}

	// Get crop coordinates from form data
	cropX, _ := strconv.ParseFloat(c.PostForm("crop_x"), 64)
	cropY, _ := strconv.ParseFloat(c.PostForm("crop_y"), 64)
	cropWidth, _ := strconv.ParseFloat(c.PostForm("crop_width"), 64)
	cropHeight, _ := strconv.ParseFloat(c.PostForm("crop_height"), 64)

	// Create cropped version using the provided crop data
	croppedImageData := c.PostForm("cropped_image")
	if croppedImageData != "" {
		// Decode base64 image data
		if err := saveBase64Image(croppedImageData, croppedPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сохранить кропнутое изображение"})
			return
		}
	} else {
		// If no cropped data provided, copy original as cropped
		if err := copyFile(originalPath, croppedPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать кропнутую версию"})
			return
		}
	}

	// Prepare crop coordinates
	var cropCoords *models.CropCoords
	if cropWidth > 0 && cropHeight > 0 {
		cropCoords = &models.CropCoords{
			X:      cropX,
			Y:      cropY,
			Width:  cropWidth,
			Height: cropHeight,
		}
	}

	// Update user avatar paths and crop coordinates - использем новые пути
	fullOriginalPath := filepath.Join("/data", user.ID.Hex(), "original"+ext)
	fullCroppedPath := filepath.Join("/data", user.ID.Hex(), "avatar"+ext)
	
	err = models.UpdateUserAvatarWithCrop(user.ID, fullCroppedPath, fullOriginalPath, cropCoords)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить аватар"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Аватар успешно загружен", 
		"avatar_path": fullCroppedPath,
		"original_avatar_path": fullOriginalPath,
		"crop_coordinates": cropCoords,
	})
}

// handleCropUpdate handles updating crop coordinates for existing image
func handleCropUpdate(c *gin.Context, user *models.User) {
	fmt.Printf("handleCropUpdate called for user %s\n", user.ID.Hex())
	fmt.Printf("Current AvatarPath: %s\n", user.AvatarPath)
	fmt.Printf("Current OriginalAvatarPath: %s\n", user.OriginalAvatarPath)
	
	if user.OriginalAvatarPath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "У пользователя нет оригинального изображения"})
		return
	}

	// Get crop coordinates from form data
	cropX, _ := strconv.ParseFloat(c.PostForm("crop_x"), 64)
	cropY, _ := strconv.ParseFloat(c.PostForm("crop_y"), 64)
	cropWidth, _ := strconv.ParseFloat(c.PostForm("crop_width"), 64)
	cropHeight, _ := strconv.ParseFloat(c.PostForm("crop_height"), 64)

	// Get cropped image data
	croppedImageData := c.PostForm("cropped_image")
	if croppedImageData == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Отсутствуют данные кропнутого изображения"})
		return
	}

	// Generate new filename for updated cropped version
	var ext string
	if user.AvatarPath != "" {
		ext = filepath.Ext(user.AvatarPath)
	} else {
		// If no avatar path, get extension from original
		ext = filepath.Ext(user.OriginalAvatarPath)
	}
	
	// Fallback to .jpg if no extension found
	if ext == "" {
		ext = ".jpg"
	}
	
	// Create user directory if it doesn't exist
	userDir, err := createUserDirectoryStructure(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать директорию пользователя"})
		return
	}
	
	newCroppedPath := filepath.Join(userDir, "avatar"+ext)

	fmt.Printf("Generated new cropped path: %s\n", newCroppedPath)
	fmt.Printf("New cropped path: %s\n", newCroppedPath)
	fmt.Printf("Cropped image data length: %d\n", len(croppedImageData))

	// FIRST: Remove old cropped file if it exists (before creating new one)
	oldAvatarPath := user.AvatarPath
	if oldAvatarPath != "" && oldAvatarPath != user.OriginalAvatarPath {
		// Convert DB path to actual filesystem path
		var oldCroppedPath string
		
		if strings.HasPrefix(oldAvatarPath, "/data/avatars/") {
			// Legacy path format - convert to new format
			oldCroppedPath = filepath.Join(userDir, "avatar"+ext)
		} else if strings.HasPrefix(oldAvatarPath, "/data/") {
			// New path format - use as is
			oldCroppedPath = oldAvatarPath
		} else {
			// Fallback - assume it's already a filesystem path
			oldCroppedPath = oldAvatarPath
		}
		
		fmt.Printf("Removing old cropped file BEFORE creating new one: %s\n", oldCroppedPath)
		if _, err := os.Stat(oldCroppedPath); err == nil {
			if removeErr := os.Remove(oldCroppedPath); removeErr != nil {
				fmt.Printf("Warning: Could not remove old cropped file %s: %v\n", oldCroppedPath, removeErr)
			} else {
				fmt.Printf("Successfully removed old cropped file: %s\n", oldCroppedPath)
			}
		} else {
			fmt.Printf("Old cropped file does not exist: %s (error: %v)\n", oldCroppedPath, err)
		}
	}

	// SECOND: Save new cropped image
	if err := saveBase64Image(croppedImageData, newCroppedPath); err != nil {
		fmt.Printf("Error saving base64 image: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сохранить кропнутое изображение"})
		return
	}

	fmt.Printf("Successfully saved new cropped image to: %s\n", newCroppedPath)

	// Verify the file was created
	if _, err := os.Stat(newCroppedPath); err != nil {
		fmt.Printf("ERROR: File was not created at path: %s, error: %v\n", newCroppedPath, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Файл не был создан"})
		return
	} else {
		fmt.Printf("File verification successful: %s exists\n", newCroppedPath)
	}

	// Prepare crop coordinates
	cropCoords := &models.CropCoords{
		X:      cropX,
		Y:      cropY,
		Width:  cropWidth,
		Height: cropHeight,
	}

	// Update user with new cropped avatar and coordinates - используем новый путь
	fullCroppedPath := filepath.Join("/data", user.ID.Hex(), "avatar"+ext)
	err = models.UpdateUserAvatarWithCrop(user.ID, fullCroppedPath, user.OriginalAvatarPath, cropCoords)
	if err != nil {
		// If update failed, remove the newly created file
		os.Remove(newCroppedPath)
		fmt.Printf("Database update failed, removed new file: %s\n", newCroppedPath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить аватар"})
		return
	}

	fmt.Printf("Avatar crop update completed successfully\n")

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Кроп аватара успешно обновлен",
		"avatar_path": fullCroppedPath,
		"crop_coordinates": cropCoords,
	})
}

// saveBase64Image saves base64 encoded image data to file
func saveBase64Image(base64Data, filePath string) error {
	// Remove data:image/jpeg;base64, prefix if present
	if strings.Contains(base64Data, ",") {
		base64Data = strings.Split(base64Data, ",")[1]
	}

	// Decode base64 data
	imageData, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return err
	}

	// Write to file
	return ioutil.WriteFile(filePath, imageData, 0644)
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// removeAvatarHandler handles avatar removal
func removeAvatarHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	// Check if user has an avatar
	if user.AvatarPath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "У пользователя нет аватара"})
		return
	}

	// Remove cropped avatar file from disk if it exists
	if user.AvatarPath != "" {
		// Convert DB path to filesystem path
		croppedPath := user.AvatarPath
		if strings.HasPrefix(croppedPath, "/data/avatars/") {
			filename := strings.TrimPrefix(croppedPath, "/data/avatars/")
			croppedPath = filepath.Join("/data/avatars", filename)
		}
		
		if _, err := os.Stat(croppedPath); err == nil {
			if err := os.Remove(croppedPath); err != nil {
				fmt.Printf("Warning: Could not remove avatar file %s: %v\n", croppedPath, err)
			}
		}
	}

	// Remove original avatar file from disk if it exists
	if user.OriginalAvatarPath != "" {
		// Convert DB path to filesystem path  
		originalPath := user.OriginalAvatarPath
		if strings.HasPrefix(originalPath, "/data/avatars/") {
			filename := strings.TrimPrefix(originalPath, "/data/avatars/")
			originalPath = filepath.Join("/data/avatars", filename)
		}
		
		if _, err := os.Stat(originalPath); err == nil {
			if err := os.Remove(originalPath); err != nil {
				fmt.Printf("Warning: Could not remove original avatar file %s: %v\n", originalPath, err)
			}
		}
	}

	// Update user avatar paths to empty and remove crop coordinates
	err := models.UpdateUserAvatarWithCrop(user.ID, "", "", nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить профиль пользователя"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Аватар успешно удален",
	})
}

// getOriginalAvatarHandler returns original avatar info with crop coordinates  
func getOriginalAvatarHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	if user.OriginalAvatarPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "У пользователя нет оригинального аватара"})
		return
	}

	// Check if original file exists
	if _, err := os.Stat(user.OriginalAvatarPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Оригинальный файл аватара не найден"})
		return
	}

	response := gin.H{
		"original_avatar_path": user.OriginalAvatarPath,
		"crop_coordinates":     user.CropCoordinates,
	}

	c.JSON(http.StatusOK, response)
}

// changePasswordHandler handles password change
func changePasswordHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	currentPassword := c.PostForm("current_password")
	newPassword := c.PostForm("new_password")
	confirmPassword := c.PostForm("confirm_password")

	// Verify current password
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный текущий пароль"})
		return
	}

	// Check if new passwords match
	if newPassword != confirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Новые пароли не совпадают"})
		return
	}

	// Validate new password
	if len(newPassword) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Пароль должен содержать не менее 6 символов"})
		return
	}

	// Update password
	err = models.ChangeUserPassword(user.ID, newPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось изменить пароль"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Пароль успешно изменен"})
}

// uploadDocumentHandler handles document upload
func uploadDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	file, err := c.FormFile("document")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не удалось получить файл"})
		return
	}

	// Check file type (only text files)
	allowedTypes := []string{"text/plain", "application/pdf", "application/msword", 
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
	fileType := file.Header.Get("Content-Type")
	
	allowed := false
	for _, t := range allowedTypes {
		if fileType == t {
			allowed = true
			break
		}
	}
	
	if !allowed {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Разрешены только текстовые документы (txt, pdf, doc, docx)"})
		return
	}

	// Check file size (max 10MB)
	if file.Size > 10*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Размер файла не должен превышать 10MB"})
		return
	}

	// Generate unique filename
	ext := filepath.Ext(file.Filename)
	filename := fmt.Sprintf("doc_%s_%d%s", user.ID.Hex(), time.Now().Unix(), ext)
	filePath := filepath.Join("/data/documents", filename)

	// Create directory if it doesn't exist
	os.MkdirAll("/data/documents", 0755)

	// Save file
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сохранить файл"})
		return
	}

	// Create document record
	doc := models.Document{
		FileName:     filename,
		OriginalName: file.Filename,
		FilePath:     filePath,
		ContentType:  fileType,
		Size:         file.Size,
	}

	// Add document to user
	err = models.AddUserDocument(user.ID, doc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось добавить документ"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Документ успешно загружен", "document": doc})
}

// deleteDocumentHandler handles document deletion
func deleteDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	docIDStr := c.PostForm("document_id")
	docID, err := primitive.ObjectIDFromHex(docIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Find and remove document file
	for _, doc := range user.LegacyDocs {
		if doc.ID == docID {
			os.Remove(doc.FilePath)
			break
		}
	}

	// Remove document from user
	err = models.RemoveUserDocument(user.ID, docID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось удалить документ"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Документ успешно удален"})
}

// downloadDocumentHandler handles document download
func downloadDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	docIDStr := c.Param("id")
	docID, err := primitive.ObjectIDFromHex(docIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Find document
	var doc *models.Document
	for _, d := range user.LegacyDocs {
		if d.ID == docID {
			doc = &d
			break
		}
	}

	if doc == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Check if file exists
	if _, err := os.Stat(doc.FilePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Файл не найден"})
		return
	}

	// Serve file
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", "attachment; filename="+doc.OriginalName)
	c.File(doc.FilePath)
}

// === New Document System Handlers ===

// getDocumentTypesHandler returns all available document types
func getDocumentTypesHandler(c *gin.Context) {
	log.Println("Fetching document types...")
	documentTypes, err := models.GetAllDocumentTypes()
	if err != nil {
		log.Printf("Error fetching document types: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить типы документов"})
		return
	}

	log.Printf("Found %d document types", len(documentTypes))
	for i, dt := range documentTypes {
		log.Printf("Document type %d: ID=%s, Name=%s, Fields=%d", i, dt.ID, dt.Name, len(dt.Fields))
	}
	c.JSON(http.StatusOK, documentTypes)
}

// getUserDocumentsHandler returns all documents for the current user
func getUserDocumentsHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	log.Printf("Getting documents for user: %s", user.ID.Hex())

	// Get updated user data to get documents
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	// Convert UserDocument to response format
	var documents []map[string]interface{}
	for i, doc := range updatedUser.Documents {
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

	log.Printf("Found %d documents for user %s", len(documents), user.ID.Hex())
	c.JSON(http.StatusOK, documents)
}

// getUserDocumentHandler returns a specific document by ID for the current user
func getUserDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	docIdStr := c.Param("id")
	
	log.Printf("Getting document %s for user: %s", docIdStr, user.ID.Hex())

	// Parse document index
	docIndex, err := strconv.Atoi(docIdStr)
	if err != nil {
		log.Printf("Invalid document ID: %s", docIdStr)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Get updated user data to get documents
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		log.Printf("Document %d not found for user %s", docIndex, user.ID.Hex())
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	doc := updatedUser.Documents[docIndex]
	docResponse := map[string]interface{}{
		"id":            docIdStr,
		"document_type": doc.DocumentType,
		"title":         doc.Title,
		"data":          doc.Fields, // Use 'data' instead of 'fields' for frontend compatibility
		"status":        doc.Status,
		"created_at":    doc.CreatedAt,
		"updated_at":    doc.UpdatedAt,
	}

	log.Printf("Found document %s: type=%s, title=%s", docIdStr, doc.DocumentType, doc.Title)
	c.JSON(http.StatusOK, docResponse)
}

// createUserDocumentHandler creates a new user document
func createUserDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	log.Printf("Creating document for user: %s", user.ID.Hex())

	var requestData struct {
		DocumentType string                 `json:"document_type" binding:"required"`
		Title        string                 `json:"title" binding:"required"`
		Fields       map[string]interface{} `json:"fields" binding:"required"`
	}

	if err := c.ShouldBindJSON(&requestData); err != nil {
		log.Printf("Error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные запроса"})
		return
	}
	
	log.Printf("Request data: %+v", requestData)

	// Validate that document type exists
	docType, err := models.GetDocumentTypeByID(requestData.DocumentType)
	if err != nil || docType == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный тип документа"})
		return
	}

	// Create new document
	userDoc := models.UserDocument{
		DocumentType: requestData.DocumentType,
		Title:        requestData.Title,
		Fields:       requestData.Fields,
		Attachments:  []models.DocumentAttachment{},
		Status:       "draft",
	}

	err = models.AddUserDocumentNew(user.ID, userDoc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать документ"})
		return
	}

	// Return document with ID for frontend
	// Find the document index (it's the last one added)
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err == nil && len(updatedUser.Documents) > 0 {
		lastIndex := len(updatedUser.Documents) - 1
		c.JSON(http.StatusOK, gin.H{
			"success":     true,
			"message":     "Документ успешно создан",
			"document_id": fmt.Sprintf("%d", lastIndex),
			"document":    userDoc,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Документ успешно создан",
			"document": userDoc,
		})
	}
}

// updateUserDocumentHandler updates an existing user document
func updateUserDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	docIdStr := c.Param("id")
	
	log.Printf("Updating document %s for user: %s", docIdStr, user.ID.Hex())

	// Parse document index
	docIndex, err := strconv.Atoi(docIdStr)
	if err != nil {
		log.Printf("Invalid document ID: %s", docIdStr)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	var requestData struct {
		Data map[string]interface{} `json:"data"`
	}

	if err := c.ShouldBindJSON(&requestData); err != nil {
		log.Printf("Error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные запроса"})
		return
	}
	
	log.Printf("Request data: %+v", requestData)

	// Get updated user data to get documents
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		log.Printf("Document %d not found for user %s", docIndex, user.ID.Hex())
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	// Update document data in the user's documents array
	err = models.UpdateUserDocumentByIndex(user.ID, docIndex, requestData.Data)
	if err != nil {
		log.Printf("Error updating document: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить документ"})
		return
	}

	log.Printf("Document %d updated successfully for user %s", docIndex, user.ID.Hex())
	c.JSON(http.StatusOK, gin.H{"message": "Документ успешно обновлен"})
}

// getDocumentAttachmentsHandler returns attachments for a document by index
func getDocumentAttachmentsHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	// Get document index from URL parameter
	docIndexStr := c.Param("id")
	docIndex, err := strconv.Atoi(docIndexStr)
	if err != nil {
		log.Printf("Invalid document index: %s", docIndexStr)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный индекс документа"})
		return
	}

	// Validate document index
	if docIndex < 0 || docIndex >= len(user.Documents) {
		log.Printf("Document index out of bounds: %d, user has %d documents", docIndex, len(user.Documents))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Документ не найден"})
		return
	}

	document := user.Documents[docIndex]
	log.Printf("Getting attachments for document %d: %d attachments found", docIndex, len(document.Attachments))

	// Convert attachments to response format (matching JavaScript expectations)
	attachments := make([]gin.H, 0, len(document.Attachments))
	for _, attachment := range document.Attachments {
		attachments = append(attachments, gin.H{
			"id":            attachment.ID.Hex(),
			"filename":      attachment.OriginalName, // JavaScript expects 'filename', use original name for display
			"file_name":     attachment.FileName,     // Keep for backward compatibility
			"original_name": attachment.OriginalName,
			"file_path":     attachment.FilePath,
			"content_type":  attachment.ContentType,
			"size":          attachment.Size,
			"uploaded_at":   attachment.UploadedAt,
		})
	}

	c.JSON(http.StatusOK, attachments)
}

// deleteUserDocumentHandler deletes a user document
func deleteUserDocumentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	docIDStr := c.Param("id")
	docID, err := primitive.ObjectIDFromHex(docIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID документа"})
		return
	}

	// Find document to remove attached files
	for _, doc := range user.Documents {
		if doc.ID == docID {
			// Remove all attached files
			for _, attachment := range doc.Attachments {
				os.Remove(attachment.FilePath)
			}
			break
		}
	}

	err = models.RemoveUserDocumentNew(user.ID, docID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось удалить документ"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Документ успешно удален"})
}

// addDocumentAttachmentHandler adds an attachment to a document
func addDocumentAttachmentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	// Get document index from URL parameter
	docIndexStr := c.Param("id")
	docIndex, err := strconv.Atoi(docIndexStr)
	if err != nil {
		log.Printf("Invalid document index: %s", docIndexStr)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный индекс документа"})
		return
	}

	// Validate document index
	if docIndex < 0 || docIndex >= len(user.Documents) {
		log.Printf("Document index out of bounds: %d, user has %d documents", docIndex, len(user.Documents))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Документ не найден"})
		return
	}

	log.Printf("Adding attachment to document %d for user: %s", docIndex, user.ID.Hex())

	file, err := c.FormFile("attachment")
	if err != nil {
		log.Printf("Failed to get file: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не удалось получить файл"})
		return
	}

	log.Printf("Processing file: %s, size: %d, type: %s", file.Filename, file.Size, file.Header.Get("Content-Type"))

	// Check file type (documents and images)
	allowedTypes := []string{
		"text/plain", "application/pdf", "application/msword",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"image/jpeg", "image/jpg", "image/png", "image/gif",
	}
	fileType := file.Header.Get("Content-Type")

	allowed := false
	for _, t := range allowedTypes {
		if fileType == t {
			allowed = true
			break
		}
	}

	if !allowed {
		log.Printf("File type not allowed: %s", fileType)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Разрешены только документы и изображения"})
		return
	}

	// Check file size (max 10MB)
	if file.Size > 10*1024*1024 {
		log.Printf("File too large: %d bytes", file.Size)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Размер файла не должен превышать 10MB"})
		return
	}

	// Get document type for directory structure
	documentType := user.Documents[docIndex].DocumentType
	log.Printf("Document type: %s", documentType)
	
	// Create document type directory
	typeDir, err := createDocumentTypeDirectory(user.ID, documentType)
	if err != nil {
		log.Printf("Failed to create document type directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать директорию документа"})
		return
	}

	// Generate safe filename
	timestamp := time.Now().Unix()
	sanitizedName := sanitizeFilename(file.Filename)
	ext := filepath.Ext(sanitizedName)
	name := sanitizedName[:len(sanitizedName)-len(ext)]
	filename := fmt.Sprintf("%s_%d%s", name, timestamp, ext)
	filePath := filepath.Join(typeDir, filename)

	log.Printf("Saving file to: %s", filePath)

	// Save file
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		log.Printf("Failed to save file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сохранить файл"})
		return
	}

	// Create attachment record
	attachment := models.DocumentAttachment{
		FileName:     filename,
		OriginalName: file.Filename,
		FilePath:     filePath,
		ContentType:  fileType,
		Size:         file.Size,
	}

	log.Printf("Adding attachment to database: %+v", attachment)

	err = models.AddDocumentAttachmentByIndex(user.ID, docIndex, attachment)
	if err != nil {
		log.Printf("Failed to add attachment to database: %v", err)
		// Remove uploaded file if database operation failed
		os.Remove(filePath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось добавить вложение"})
		return
	}

	log.Printf("Attachment added successfully")

	c.JSON(http.StatusOK, gin.H{
		"message":    "Вложение успешно добавлено",
		"attachment": attachment,
	})
}

// removeDocumentAttachmentHandler removes an attachment from a document by index
func removeDocumentAttachmentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	// Get document index from URL parameter
	docIndexStr := c.Param("id")
	docIndex, err := strconv.Atoi(docIndexStr)
	if err != nil {
		log.Printf("Invalid document index: %s", docIndexStr)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный индекс документа"})
		return
	}

	// Validate document index
	if docIndex < 0 || docIndex >= len(user.Documents) {
		log.Printf("Document index out of bounds: %d, user has %d documents", docIndex, len(user.Documents))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Документ не найден"})
		return
	}

	attachmentIDStr := c.Param("attachmentId")
	attachmentID, err := primitive.ObjectIDFromHex(attachmentIDStr)
	if err != nil {
		log.Printf("Invalid attachment ID: %s", attachmentIDStr)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID вложения"})
		return
	}

	document := user.Documents[docIndex]
	log.Printf("Removing attachment %s from document %d for user: %s", attachmentID.Hex(), docIndex, user.ID.Hex())

	// Find attachment to remove file from filesystem
	var attachmentPath string
	for _, attachment := range document.Attachments {
		if attachment.ID == attachmentID {
			attachmentPath = attachment.FilePath
			break
		}
	}

	if attachmentPath == "" {
		log.Printf("Attachment not found: %s in document %d", attachmentID.Hex(), docIndex)
		c.JSON(http.StatusNotFound, gin.H{"error": "Вложение не найдено"})
		return
	}

	// Remove attachment from database first
	err = models.RemoveDocumentAttachmentByIndex(user.ID, docIndex, attachmentID)
	if err != nil {
		log.Printf("Failed to remove attachment from database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось удалить вложение из базы данных"})
		return
	}

	// Remove file from filesystem after successful database operation
	if err := os.Remove(attachmentPath); err != nil {
		log.Printf("Warning: Could not remove attachment file %s: %v", attachmentPath, err)
		// Don't return error here - database operation succeeded
	} else {
		log.Printf("Successfully removed attachment file: %s", attachmentPath)
	}

	log.Printf("Attachment %s successfully removed from document %d", attachmentID.Hex(), docIndex)
	c.JSON(http.StatusOK, gin.H{"message": "Вложение успешно удалено"})
}

// downloadDocumentAttachmentHandler handles downloading a specific attachment
func downloadDocumentAttachmentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	
	docIndexStr := c.Param("id")
	docIndex, err := strconv.Atoi(docIndexStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный индекс документа"})
		return
	}

	attachmentIDStr := c.Param("attachmentId")
	attachmentID, err := primitive.ObjectIDFromHex(attachmentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID вложения"})
		return
	}

	// Get updated user data to get documents
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	document := updatedUser.Documents[docIndex]

	// Find attachment
	var attachment *models.DocumentAttachment
	for i := range document.Attachments {
		if document.Attachments[i].ID == attachmentID {
			attachment = &document.Attachments[i]
			break
		}
	}

	if attachment == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Вложение не найдено"})
		return
	}

	// Check if file exists
	if _, err := os.Stat(attachment.FilePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Файл не найден"})
		return
	}

	// Serve file for download
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", "attachment; filename="+attachment.OriginalName)
	c.File(attachment.FilePath)
}

// previewDocumentAttachmentHandler handles previewing a specific attachment
func previewDocumentAttachmentHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	
	docIndexStr := c.Param("id")
	docIndex, err := strconv.Atoi(docIndexStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный индекс документа"})
		return
	}

	attachmentIDStr := c.Param("attachmentId")
	attachmentID, err := primitive.ObjectIDFromHex(attachmentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID вложения"})
		return
	}

	// Get updated user data to get documents
	updatedUser, err := models.GetUserByID(user.ID.Hex())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователя"})
		return
	}

	// Check if document exists
	if docIndex < 0 || docIndex >= len(updatedUser.Documents) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Документ не найден"})
		return
	}

	document := updatedUser.Documents[docIndex]

	// Find attachment
	var attachment *models.DocumentAttachment
	for i := range document.Attachments {
		if document.Attachments[i].ID == attachmentID {
			attachment = &document.Attachments[i]
			break
		}
	}

	if attachment == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Вложение не найдено"})
		return
	}

	// Check if file exists
	if _, err := os.Stat(attachment.FilePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Файл не найден"})
		return
	}

	// Determine content type based on file extension
	ext := strings.ToLower(filepath.Ext(attachment.OriginalName))
	var contentType string
	switch ext {
	case ".jpg", ".jpeg":
		contentType = "image/jpeg"
	case ".png":
		contentType = "image/png"
	case ".gif":
		contentType = "image/gif"
	case ".pdf":
		contentType = "application/pdf"
	default:
		contentType = "application/octet-stream"
	}

	// Serve file for inline preview
	c.Header("Content-Type", contentType)
	c.Header("Content-Disposition", "inline; filename="+attachment.OriginalName)
	c.File(attachment.FilePath)
}

// SetupProfileRoutes настраивает роуты для профиля (доступные через /profile)
func SetupProfileRoutes(router *gin.Engine) {
	// Эти роуты будут доступны через nginx прокси /profile -> auth-service:8080/profile
	router.GET("/profile", authRequired(), profileHandler)
	router.POST("/profile/update", authRequired(), updateProfileHandler)
	router.POST("/profile/avatar", authRequired(), uploadAvatarHandler)
	router.GET("/profile/avatar/original", authRequired(), getOriginalAvatarHandler)
	router.DELETE("/profile/remove-avatar", authRequired(), removeAvatarHandler)
	router.POST("/profile/password", authRequired(), changePasswordHandler)
	router.POST("/profile/document", authRequired(), uploadDocumentHandler)
	router.POST("/profile/document/delete", authRequired(), deleteDocumentHandler)
	router.GET("/profile/document/:id", authRequired(), downloadDocumentHandler)
	
	// Document system routes for profile
	router.GET("/profile/documents", authRequired(), getUserDocumentsHandler)
	router.GET("/profile/documents/:id", authRequired(), getUserDocumentHandler)
	router.GET("/profile/documents/:id/attachments", authRequired(), getDocumentAttachmentsHandler)
	router.POST("/profile/documents", authRequired(), createUserDocumentHandler)
	router.PUT("/profile/documents/:id", authRequired(), updateUserDocumentHandler)
	router.DELETE("/profile/documents/:id", authRequired(), deleteUserDocumentHandler)
	router.POST("/profile/documents/:id/attachments", authRequired(), addDocumentAttachmentHandler)
	router.DELETE("/profile/documents/:id/attachments/:attachmentId", authRequired(), removeDocumentAttachmentHandler)
	router.GET("/profile/documents/:id/attachments/:attachmentId/download", authRequired(), downloadDocumentAttachmentHandler)
	router.GET("/profile/documents/:id/attachments/:attachmentId/preview", authRequired(), previewDocumentAttachmentHandler)
}
