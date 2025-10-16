package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

type MonitoringService struct {
	services map[string]*ServiceStatus
}

type ServiceStatus struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Status      string    `json:"status"` // "healthy", "unhealthy", "unknown"
	LastCheck   time.Time `json:"last_check"`
	LastHealthy time.Time `json:"last_healthy"`
	ErrorCount  int       `json:"error_count"`
	LastError   string    `json:"last_error,omitempty"`
}

type NotificationRequest struct {
	Type      string `json:"type"`
	Recipient string `json:"recipient"`
	Subject   string `json:"subject"`
	Content   string `json:"content"`
}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	}

	// Initialize monitoring service
	ms := &MonitoringService{
		services: make(map[string]*ServiceStatus),
	}

	// Load services from environment
	ms.loadServices()

	// Setup Gin
	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	
	r := gin.Default()

	// Serve static files
	r.Static("/static", "./static")
	
	// Main page - monitoring dashboard
	r.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy", "service": "monitoring-service"})
	})

	// API endpoints
	api := r.Group("/api/v1")
	{
		api.GET("/status", ms.getServicesStatus)
		api.GET("/status/:service", ms.getServiceStatus)
		api.POST("/check", ms.forceHealthCheck)
	}

	// Start monitoring goroutine
	go ms.startMonitoring()

	// Start server
	port := getEnvOrDefault("PORT", "80")
	log.Printf("🔍 Starting monitoring service on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func (ms *MonitoringService) loadServices() {
	servicesEnv := getEnvOrDefault("MONITORED_SERVICES", "")
	if servicesEnv == "" {
		log.Println("⚠️ No services to monitor (MONITORED_SERVICES is empty)")
		return
	}

	services := strings.Split(servicesEnv, ",")
	for _, service := range services {
		// Split by first colon only to handle URLs with multiple colons
		parts := strings.SplitN(strings.TrimSpace(service), ":", 2)
		if len(parts) != 2 {
			log.Printf("⚠️ Invalid service format: %s (expected name:url)", service)
			continue
		}

		name := strings.TrimSpace(parts[0])
		url := strings.TrimSpace(parts[1])

		ms.services[name] = &ServiceStatus{
			Name:        name,
			URL:         url,
			Status:      "unknown",
			LastCheck:   time.Time{},
			LastHealthy: time.Time{},
			ErrorCount:  0,
		}

		log.Printf("📋 Added service to monitoring: %s -> %s", name, url)
	}
}

func (ms *MonitoringService) startMonitoring() {
	checkInterval := getEnvAsInt("CHECK_INTERVAL_SECONDS", 30)
	ticker := time.NewTicker(time.Duration(checkInterval) * time.Second)
	defer ticker.Stop()

	log.Printf("🔄 Starting monitoring loop (checking every %d seconds)", checkInterval)

	// Initial check
	ms.checkAllServices()

	for range ticker.C {
		ms.checkAllServices()
	}
}

func (ms *MonitoringService) checkAllServices() {
	for name, service := range ms.services {
		ms.checkService(name, service)
	}
}

func (ms *MonitoringService) checkService(name string, service *ServiceStatus) {
	client := &http.Client{
		Timeout: time.Duration(getEnvAsInt("HEALTH_CHECK_TIMEOUT_SECONDS", 10)) * time.Second,
	}

	resp, err := client.Get(service.URL)
	service.LastCheck = time.Now()

	previousStatus := service.Status

	if err != nil {
		service.Status = "unhealthy"
		service.ErrorCount++
		service.LastError = err.Error()
		log.Printf("❌ %s is unhealthy: %v", name, err)
	} else {
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			service.Status = "healthy"
			service.LastHealthy = time.Now()
			service.ErrorCount = 0
			service.LastError = ""
			log.Printf("✅ %s is healthy", name)
		} else {
			service.Status = "unhealthy"
			service.ErrorCount++
			service.LastError = fmt.Sprintf("HTTP %d", resp.StatusCode)
			log.Printf("❌ %s is unhealthy: HTTP %d", name, resp.StatusCode)
		}
	}

	// Send alert if status changed from healthy to unhealthy
	if previousStatus == "healthy" && service.Status == "unhealthy" {
		ms.sendAlert(name, service, "Service became unhealthy")
	}

	// Send recovery alert if status changed from unhealthy to healthy
	if previousStatus == "unhealthy" && service.Status == "healthy" {
		ms.sendAlert(name, service, "Service recovered")
	}

	// Send persistent alert if service is unhealthy for too long
	persistentAlertThreshold := getEnvAsInt("PERSISTENT_ALERT_THRESHOLD", 5)
	if service.Status == "unhealthy" && service.ErrorCount%persistentAlertThreshold == 0 {
		ms.sendAlert(name, service, fmt.Sprintf("Service still unhealthy after %d checks", service.ErrorCount))
	}
}

func (ms *MonitoringService) sendAlert(serviceName string, service *ServiceStatus, alertType string) {
	notificationServiceURL := getEnvOrDefault("NOTIFICATION_SERVICE_URL", "http://notification-service:80")
	
	// Get notification settings
	systemEmailRecipient := getEnvOrDefault("SYSTEM_EMAIL_RECIPIENT", "")
	systemTelegramUsername := getEnvOrDefault("SYSTEM_TELEGRAM_USERNAME", "")
	sendEmailAlerts := getEnvAsBool("SEND_SYSTEM_EMAIL_NOTIFICATIONS", true)
	sendTelegramAlerts := getEnvAsBool("SEND_SYSTEM_TELEGRAM_NOTIFICATIONS", true)

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	subject := fmt.Sprintf("🚨 Service Monitor Alert: %s", serviceName)
	
	var content string
	if service.Status == "healthy" {
		content = fmt.Sprintf("✅ *Service Recovery*\n\n"+
			"Service: %s\n"+
			"Status: %s\n"+
			"Time: %s\n"+
			"Message: %s\n\n"+
			"The service is now responding normally.", 
			serviceName, service.Status, timestamp, alertType)
	} else {
		content = fmt.Sprintf("❌ *Service Alert*\n\n"+
			"Service: %s\n"+
			"Status: %s\n"+
			"URL: %s\n"+
			"Time: %s\n"+
			"Error Count: %d\n"+
			"Last Error: %s\n"+
			"Message: %s", 
			serviceName, service.Status, service.URL, timestamp, 
			service.ErrorCount, service.LastError, alertType)
	}

	// Send email notification
	if sendEmailAlerts && systemEmailRecipient != "" {
		emailNotification := NotificationRequest{
			Type:      "email",
			Recipient: systemEmailRecipient,
			Subject:   subject,
			Content:   strings.ReplaceAll(content, "*", ""), // Remove markdown for email
		}
		ms.sendNotification(notificationServiceURL, emailNotification, "email")
	}

	// Send Telegram notification
	if sendTelegramAlerts && systemTelegramUsername != "" {
		telegramNotification := NotificationRequest{
			Type:      "telegram_system",
			Recipient: systemTelegramUsername,
			Subject:   subject,
			Content:   content,
		}
		ms.sendNotification(notificationServiceURL, telegramNotification, "telegram")
	}
}

func (ms *MonitoringService) sendNotification(serviceURL string, notification NotificationRequest, notificationType string) {
	jsonData, err := json.Marshal(notification)
	if err != nil {
		log.Printf("❌ Failed to marshal %s notification: %v", notificationType, err)
		return
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Post(
		serviceURL+"/api/v1/notifications",
		"application/json",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		log.Printf("❌ Failed to send %s notification: %v", notificationType, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusAccepted {
		log.Printf("✅ %s notification sent successfully", strings.Title(notificationType))
	} else {
		log.Printf("❌ Failed to send %s notification: HTTP %d", notificationType, resp.StatusCode)
	}
}

// API Handlers
func (ms *MonitoringService) getServicesStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"services": ms.services,
		"timestamp": time.Now(),
	})
}

func (ms *MonitoringService) getServiceStatus(c *gin.Context) {
	serviceName := c.Param("service")
	
	service, exists := ms.services[serviceName]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		return
	}

	c.JSON(http.StatusOK, service)
}

func (ms *MonitoringService) forceHealthCheck(c *gin.Context) {
	log.Println("🔄 Forced health check triggered")
	go ms.checkAllServices()
	c.JSON(http.StatusOK, gin.H{"message": "Health check triggered"})
}

// Utility functions
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}