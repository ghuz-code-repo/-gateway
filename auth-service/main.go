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

// Define custom template functions
func setupTemplateFunc() template.FuncMap {
	return template.FuncMap{
		"join": strings.Join, // Add join function that calls strings.Join
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

	// Setup router
	router := gin.Default()

	// Set up static file serving
	router.Static("/static", "./static")

	// Set up custom template functions
	router.SetFuncMap(setupTemplateFunc())

	// Load HTML templates after setting function map
	router.LoadHTMLGlob("templates/*")

	// Setup routes
	routes.SetupAuthRoutes(router)

	log.Println("Starting auth service on port 8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
