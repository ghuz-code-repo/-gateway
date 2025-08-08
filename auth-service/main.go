package main

import (
	"auth-service/models"
	"auth-service/routes"
	"html/template"
	"log"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

func setupAuthRoutes(router *gin.Engine) {
	// Health check
	router.GET("/health", routes.HealthCheck)
	
	// Web interface routes
	routes.SetupAuthRoutes(router)
	
	// Setup admin routes and add policy management to the same group
	adminGroup := router.Group("/admin")
	adminGroup.Use(routes.AdminAuthRequired())
	routes.SetupAdminGroupRoutes(adminGroup)
	log.Println("About to call PolicyAdminRoutes...")
	routes.PolicyAdminRoutes(adminGroup)
	log.Println("PolicyAdminRoutes call completed.")
	
	// JWT API
	api := router.Group("/api/v1")
	api.POST("/login", routes.APILoginHandler)
	api.POST("/refresh", routes.RefreshTokenHandler)
	api.GET("/verify", routes.VerifyTokenHandler)
	api.GET("/health", routes.HealthCheck)
}

// Режим работы сервиса (устанавливается при сборке или через переменную окружения)
var serviceMode string

// Define custom template functions
func setupTemplateFunc() template.FuncMap {
	return template.FuncMap{
		"join": strings.Join, // Add join function that calls strings.Join
	}
}

func main() {
	// Определяем режим работы сервиса
	if serviceMode == "" {
		serviceMode = os.Getenv("SERVICE_MODE")
	}
	if serviceMode == "" {
		serviceMode = "auth" // default mode
	}

	log.Printf("Starting service in mode: %s", serviceMode)

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

	// Initialize Policy System with caching (только для policy режима)
	if serviceMode == "policy" || serviceMode == "auth" {
		err = models.InitializePolicySystem()
		if err != nil {
			log.Printf("Warning: Failed to initialize policy system: %v", err)
		} else {
			log.Println("Policy system initialized successfully")
		}
	}

	// Setup router
	router := gin.Default()

	// Set up static file serving
	router.Static("/static", "./static")

	// Set up custom template functions
	router.SetFuncMap(setupTemplateFunc())

	// Load HTML templates after setting function map
	router.LoadHTMLGlob("templates/**/*.html")

	// Configure routes based on service mode
	switch serviceMode {
	case "auth":
		setupAuthRoutes(router)
	case "policy":
		setupPolicyRoutes(router)
	case "users":
		setupUserRoutes(router)
	default:
		log.Fatalf("Unknown service mode: %s", serviceMode)
	}

	// Determine port based on service mode
	port := getServicePort(serviceMode)
	
	log.Printf("Starting %s service on port %s", serviceMode, port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// setupPolicyRoutes настраивает маршруты для policy-сервиса
func setupPolicyRoutes(router *gin.Engine) {
	// Policy API
	api := router.Group("/api/v1")
	api.POST("/evaluate", routes.EvaluatePolicy)
	api.GET("/services/:service/roles", routes.GetServiceRoles)
	api.POST("/services/:service/roles", routes.CreateServiceRole)
	api.PUT("/services/:service/roles/:role_id", routes.UpdateServiceRole)
	api.DELETE("/services/:service/roles/:role_id", routes.DeleteServiceRole)
	api.GET("/services/:service/permissions", routes.GetServicePermissions)
	api.POST("/services/:service/permissions", routes.CreateServicePermission)
	
	// Cache management
	api.GET("/cache/stats", routes.GetCacheStats)
	api.POST("/cache/invalidate/:service", routes.InvalidateServiceCache)
	api.DELETE("/cache/clear", routes.ClearCache)
	api.GET("/health", routes.HealthCheck)
}

// setupUserRoutes настраивает маршруты для user-management-сервиса
func setupUserRoutes(router *gin.Engine) {
	// User management API
	api := router.Group("/api/v1")
	api.GET("/users", routes.ListUsersAPI)
	api.POST("/users", routes.CreateUserAPI)
	api.GET("/users/:id", routes.GetUserAPI)
	api.PUT("/users/:id", routes.UpdateUserAPI)
	api.DELETE("/users/:id", routes.DeleteUserAPI)
	api.GET("/health", routes.HealthCheck)
}

// getServicePort возвращает порт для определенного типа сервиса
func getServicePort(mode string) string {
	switch mode {
	case "auth":
		return "8080"
	case "policy":
		return "8081"
	case "users":
		return "8082"
	default:
		return "8080"
	}
}
