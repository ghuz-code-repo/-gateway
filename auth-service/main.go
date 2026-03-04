package main

import (
	"auth-service/migrations"
	"auth-service/models"
	"auth-service/routes"
	"auth-service/utils"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Define custom template functions
func setupTemplateFunc() template.FuncMap {
	return template.FuncMap{
		"join": strings.Join, // Add join function that calls strings.Join
		"jsonify": func(v interface{}) (string, error) {
			b, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
		"div": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"subtract": func(a, b int) int {
			return a - b
		},
		"hasAdminRole": func(serviceRoles []models.UserServiceRole) bool {
			for _, sr := range serviceRoles {
				if sr.IsActive && sr.ServiceKey == "system" && sr.RoleName == "admin" {
					return true
				}
			}
			return false
		},
	}
}

// checkAndCleanupAvatars проверяет существование файлов аватарок и очищает недействительные пути
func checkAndCleanupAvatars() {
	log.Println("Проверка файлов аватарок...")

	// Создаем папку для аватарок если её нет
	avatarDir := "./data/avatars"
	if err := os.MkdirAll(avatarDir, 0755); err != nil {
		log.Printf("Ошибка создания папки аватарок: %v", err)
		return
	}

	// Получаем всех пользователей с аватарками
	users, err := models.GetUsersWithAvatars()
	if err != nil {
		log.Printf("Ошибка получения пользователей с аватарками: %v", err)
		return
	}

	cleaned := 0
	for _, user := range users {
		if user.AvatarPath != "" {
			var filePath string

			// Определяем правильный путь к файлу
			if strings.HasPrefix(user.AvatarPath, "/avatar/") {
				// Новый формат: /avatar/userID -> ./data/userID/avatar.jpg
				userID := strings.TrimPrefix(user.AvatarPath, "/avatar/")
				filePath = fmt.Sprintf("./data/%s/avatar.jpg", userID)
			} else {
				// Старый формат: /data/userID/avatar.jpg -> ./data/userID/avatar.jpg
				filePath = "." + user.AvatarPath
			}

			log.Printf("Проверяем файл аватарки: %s для пользователя %s", filePath, user.Email)

			// Проверяем существование файла
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				log.Printf("Файл аватарки не найден: %s для пользователя %s", filePath, user.Email)
				// Очищаем путь к аватарке в базе данных
				if err := models.UpdateUserAvatar(user.ID, ""); err != nil {
					log.Printf("Ошибка очистки пути аватарки для пользователя %s: %v", user.Email, err)
				} else {
					cleaned++
					log.Printf("Очищен путь аватарки для пользователя %s", user.Email)
				}
			}
		}
	}

	if cleaned > 0 {
		log.Printf("Очищено %d недействительных путей к аватаркам", cleaned)
	} else {
		log.Println("Все пути к аватаркам действительны")
	}
}

func main() {
	// MongoDB connection string and db name from env (required)
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		log.Fatal("MONGO_URI environment variable is required. " +
			"Example: mongodb://authservice:password@mongo:27017/authdb?authSource=authdb")
	}
	dbName := os.Getenv("MONGO_DB")
	if dbName == "" {
		dbName = "authdb"
	}

	// Initialize MongoDB
	err := models.InitDB(mongoURI, dbName)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	// Log existing services for debugging
	services, err := models.GetAllServices()
	if err != nil {
		log.Printf("WARNING: Could not retrieve services: %v", err)
	} else {
		log.Printf("STARTUP DEBUG: Found %d services in database:", len(services))
		for i, service := range services {
			log.Printf("STARTUP DEBUG: Service %d - Key: '%s', Name: '%s'", i+1, service.Key, service.Name)
		}
	}

	// Create an admin user if it doesn't exist
	models.EnsureAdminExists()

	// Ensure critical roles (GOD, admin) exist with correct permissions,
	// migrate system/admin → auth/GOD, and fix legacy data formats.
	models.EnsureCriticalRolesIntegrity()

	// ADR-001: Perform migration to new schema
	log.Println("Checking for ADR-001 schema migration...")
	migrationResult, err := models.MigrateToADR001Schema()
	if err != nil {
		log.Printf("Migration failed: %v", err)
		if len(migrationResult.Errors) > 0 {
			log.Println("Migration errors:")
			for _, errMsg := range migrationResult.Errors {
				log.Printf("  - %s", errMsg)
			}
		}
		// Don't fail startup on migration errors, just log them
	} else {
		log.Printf("Migration completed successfully: %d services, %d roles updated",
			migrationResult.ServicesUpdated, migrationResult.RolesUpdated)
	}

	// Validate migration
	if err := models.ValidateMigration(); err != nil {
		log.Printf("Migration validation failed: %v", err)
	} else {
		log.Println("Migration validation passed")
	}

	// Migrate user names from FullName to separate fields
	log.Println("Running user names migration...")
	if err := models.MigrateUserNamesFromFullName(); err != nil {
		log.Printf("User names migration failed: %v", err)
	}

	// Migrate documents to include allowed_services field
	log.Println("Running documents services migration...")
	if err := migrations.MigrateDocumentsToServicesField(models.GetDatabase()); err != nil {
		log.Printf("Documents services migration failed: %v", err)
	}

	// Check and cleanup avatar files
	checkAndCleanupAvatars()

	// Initialize notification service client
	InitNotificationClient()

	// Configure notification service with current SMTP settings
	ConfigureNotificationService()

	// Setup router
	router := gin.Default()

	// CORS middleware configuration
	router.Use(func(c *gin.Context) {
		// Build whitelist of allowed origins from environment
		allowedOrigins := make(map[string]bool)
		if envOrigin := os.Getenv("ALLOWED_ORIGIN"); envOrigin != "" {
			for _, o := range strings.Split(envOrigin, ",") {
				allowedOrigins[strings.TrimSpace(o)] = true
			}
		}
		// Always allow localhost in development
		if os.Getenv("ENVIRONMENT") != "production" {
			allowedOrigins["http://localhost"] = true
			allowedOrigins["http://localhost:80"] = true
			allowedOrigins["https://localhost"] = true
		}

		origin := c.Request.Header.Get("Origin")
		if origin != "" && allowedOrigins[origin] {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-API-Key")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		}

		// Security headers
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Set trusted proxies (nginx and docker internal networks)
	router.SetTrustedProxies([]string{
		"172.16.0.0/12",  // Docker default networks
		"10.0.0.0/8",     // Docker internal networks
		"192.168.0.0/16", // Docker compose networks
		"127.0.0.1",      // localhost
	})

	// Set maximum memory for multipart forms to 10MB
	router.MaxMultipartMemory = 10 << 20 // 10 MB

	// Set up static file serving
	router.Static("/static", "./static")
	// Serve favicon
	router.StaticFile("/vite.svg", "./static/img/vite.svg")
	router.StaticFile("/favicon.ico", "./static/img/favicon.ico")

	// Setup avatar serving with no-cache headers BEFORE general /data route
	router.GET("/avatar/:userID", func(c *gin.Context) {
		userID := c.Param("userID")
		avatarPath := filepath.Join(userID, "avatar.jpg")

		// Set no-cache headers to prevent browser caching
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.Header("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		c.Header("ETag", fmt.Sprintf("\"%d\"", time.Now().Unix()))

		// Serve file with path traversal protection
		if err := utils.SafeServeFile(c, "./data", avatarPath); err != nil {
			log.Printf("Error serving avatar: %v", err)
			c.Status(http.StatusNotFound)
			return
		}
	})

	// Serve other data files normally (documents, etc.)
	router.Static("/data", "./data")

	// Set up custom template functions
	router.SetFuncMap(setupTemplateFunc())

	// Load HTML templates - load all .html files including subdirectories
	// Note: LoadHTMLGlob doesn't support ** pattern in Go, so we collect files from each directory explicitly
	rootTemplates, err := filepath.Glob("templates/*.html")
	if err != nil {
		log.Fatalf("Failed to glob root templates: %v", err)
	}
	roleManagementTemplates, err := filepath.Glob("templates/role_management/*.html")
	if err != nil {
		log.Fatalf("Failed to glob role_management templates: %v", err)
	}
	allTemplates := append(rootTemplates, roleManagementTemplates...)
	log.Printf("Loading %d templates: %d root + %d role_management", len(allTemplates), len(rootTemplates), len(roleManagementTemplates))
	router.LoadHTMLFiles(allTemplates...)

	// Initialize nginx configuration with empty services config
	// This ensures nginx can start even without any registered services
	log.Println("Initializing nginx dynamic configuration...")
	if err := routes.InitializeNginxConfig(); err != nil {
		log.Printf("Warning: Could not initialize nginx config: %v", err)
		log.Println("Continuing anyway - nginx will create it on first service registration")
	}

	// Setup all routes using the new modular structure
	routes.SetupAllRoutes(router)

	log.Println("Starting auth service on port 80")
	if err := router.Run(":80"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
