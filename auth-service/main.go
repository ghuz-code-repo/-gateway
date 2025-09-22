package main

import (
	"auth-service/models"
	"auth-service/routes"
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
		"hasAdminRole": func(roles []string) bool {
			for _, role := range roles {
				if role == "admin" {
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
	// MongoDB connection string and db name from env or default
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://mongo:27017"
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

	// Create an admin user if it doesn't exist
	models.EnsureAdminExists()

	// Ensure referal permission exists
	models.CreateDefaultPermissions()

	// Ensure admin has all permissions
	// models.EnsureAdminHasAllPermissions()

	// After database initialization
	models.InitializeDefaultPermissions()
	models.InitializeDefaultDisplayNames()

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

	// Check and cleanup avatar files
	checkAndCleanupAvatars()

	// Setup router
	router := gin.Default()

	// Set maximum memory for multipart forms to 99MB
	router.MaxMultipartMemory = 99 << 20 // 99 MB

	// Set up static file serving
	router.Static("/static", "./static")
	// Serve favicon
	router.StaticFile("/vite.svg", "./static/img/vite.svg")
	
	// Setup avatar serving with no-cache headers BEFORE general /data route
	router.GET("/avatar/:userID", func(c *gin.Context) {
		userID := c.Param("userID")
		avatarPath := filepath.Join("./data", userID, "avatar.jpg")
		
		// Set no-cache headers to prevent browser caching
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.Header("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		c.Header("ETag", fmt.Sprintf("\"%d\"", time.Now().Unix()))
		
		// Check if file exists
		if _, err := os.Stat(avatarPath); os.IsNotExist(err) {
			c.Status(http.StatusNotFound)
			return
		}
		
		c.File(avatarPath)
	})
	
	// Serve other data files normally (documents, etc.)
	router.Static("/data", "./data")

	// Set up custom template functions
	router.SetFuncMap(setupTemplateFunc())

	// Load HTML templates after setting function map
	router.LoadHTMLGlob("templates/*")

	// Setup all routes using the new modular structure
	routes.SetupAllRoutes(router)

	log.Println("Starting auth service on port 8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
