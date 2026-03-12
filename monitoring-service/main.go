package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

type MonitoringService struct {
	mu              sync.RWMutex
	services        map[string]*ServiceStatus
	configCache     *NotificationConfig
	lastConfigFetch time.Time
	httpClient      *http.Client
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

type NotificationConfig struct {
	SendSystemEmailNotifications    bool   `json:"send_system_email_notifications"`
	SendSystemTelegramNotifications bool   `json:"send_system_telegram_notifications"`
	SystemEmailRecipient            string `json:"system_email_recipient"`
	SystemTelegramUsername          string `json:"system_telegram_username"`
}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	}

	// Initialize monitoring service
	ms := &MonitoringService{
		services: make(map[string]*ServiceStatus),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
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

	// Start monitoring goroutine with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ms.startMonitoring(ctx)

	// Start server with graceful shutdown
	port := getEnvOrDefault("PORT", "80")
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	go func() {
		log.Printf("🔍 Starting monitoring service on port %s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("⏳ Shutting down monitoring service...")

	cancel() // Stop monitoring goroutine

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("❌ Server forced to shutdown: %v", err)
	}
	log.Println("✅ Monitoring service stopped gracefully")
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

func (ms *MonitoringService) startMonitoring(ctx context.Context) {
	checkInterval := getEnvAsInt("CHECK_INTERVAL_SECONDS", 30)
	ticker := time.NewTicker(time.Duration(checkInterval) * time.Second)
	defer ticker.Stop()

	log.Printf("🔄 Starting monitoring loop (checking every %d seconds)", checkInterval)

	// Initial check
	ms.checkAllServices()

	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 Monitoring loop stopped")
			return
		case <-ticker.C:
			ms.checkAllServices()
		}
	}
}

func (ms *MonitoringService) checkAllServices() {
	ms.mu.RLock()
	// Copy keys to avoid holding lock during HTTP checks
	names := make([]string, 0, len(ms.services))
	for name := range ms.services {
		names = append(names, name)
	}
	ms.mu.RUnlock()

	for _, name := range names {
		ms.mu.RLock()
		service, ok := ms.services[name]
		ms.mu.RUnlock()
		if ok {
			ms.checkService(name, service)
		}
	}
}

func (ms *MonitoringService) checkService(name string, service *ServiceStatus) {
	resp, err := ms.httpClient.Get(service.URL)

	ms.mu.Lock()
	service.LastCheck = time.Now()

	previousStatus := service.Status

	if err != nil {
		service.Status = "unhealthy"
		service.ErrorCount++
		service.LastError = err.Error()
		ms.mu.Unlock()
		log.Printf("❌ %s is unhealthy: %v", name, err)
	} else {
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			service.Status = "healthy"
			service.LastHealthy = time.Now()
			service.ErrorCount = 0
			service.LastError = ""
			ms.mu.Unlock()
			log.Printf("✅ %s is healthy", name)
		} else {
			service.Status = "unhealthy"
			service.ErrorCount++
			service.LastError = fmt.Sprintf("HTTP %d", resp.StatusCode)
			ms.mu.Unlock()
			log.Printf("❌ %s is unhealthy: HTTP %d", name, resp.StatusCode)
		}
	}

	// Get notification settings from API (with caching)
	config := ms.getNotificationConfig()
	sendEmailAlerts := config.SendSystemEmailNotifications
	sendTelegramAlerts := config.SendSystemTelegramNotifications
	enablePersistentAlerts := getEnvAsBool("ENABLE_PERSISTENT_ALERTS", false)

	if !sendEmailAlerts && !sendTelegramAlerts {
		// Skip all alerts if both notification types are disabled
		return
	}

	// Send alert if status changed from healthy to unhealthy
	if previousStatus == "healthy" && service.Status == "unhealthy" {
		ms.sendAlert(name, service, "Service became unhealthy")
	}

	// Send recovery alert if status changed from unhealthy to healthy
	if previousStatus == "unhealthy" && service.Status == "healthy" {
		ms.sendAlert(name, service, "Service recovered")
	}

	// Send persistent alert if service is unhealthy for too long (only if enabled)
	if enablePersistentAlerts {
		persistentAlertThreshold := getEnvAsInt("PERSISTENT_ALERT_THRESHOLD", 20)
		if service.Status == "unhealthy" && service.ErrorCount > 0 && service.ErrorCount%persistentAlertThreshold == 0 {
			ms.sendAlert(name, service, fmt.Sprintf("Service still unhealthy after %d checks", service.ErrorCount))
		}
	}
}

func (ms *MonitoringService) sendAlert(serviceName string, service *ServiceStatus, alertType string) {
	notificationServiceURL := getEnvOrDefault("NOTIFICATION_SERVICE_URL", "http://notification-service:80")

	// Get notification settings from API (with caching) - includes recipients
	config := ms.getNotificationConfig()
	sendEmailAlerts := config.SendSystemEmailNotifications
	sendTelegramAlerts := config.SendSystemTelegramNotifications
	systemEmailRecipient := config.SystemEmailRecipient
	systemTelegramUsername := config.SystemTelegramUsername

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

	resp, err := ms.httpClient.Post(
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
		log.Printf("✅ %s notification sent successfully", capitalizeFirst(notificationType))
	} else {
		log.Printf("❌ Failed to send %s notification: HTTP %d", notificationType, resp.StatusCode)
	}
}

// capitalizeFirst capitalizes the first letter of a string (replaces deprecated strings.Title)
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// API Handlers
func (ms *MonitoringService) getServicesStatus(c *gin.Context) {
	ms.mu.RLock()
	// Copy map for safe serialization
	servicesCopy := make(map[string]*ServiceStatus, len(ms.services))
	for k, v := range ms.services {
		copy := *v
		servicesCopy[k] = &copy
	}
	ms.mu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"services":  servicesCopy,
		"timestamp": time.Now(),
	})
}

func (ms *MonitoringService) getServiceStatus(c *gin.Context) {
	serviceName := c.Param("service")

	ms.mu.RLock()
	service, exists := ms.services[serviceName]
	if !exists {
		ms.mu.RUnlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		return
	}
	copy := *service
	ms.mu.RUnlock()

	c.JSON(http.StatusOK, &copy)
}

func (ms *MonitoringService) forceHealthCheck(c *gin.Context) {
	log.Println("🔄 Forced health check triggered")
	go ms.checkAllServices()
	c.JSON(http.StatusOK, gin.H{"message": "Health check triggered"})
}

// getNotificationConfig fetches notification settings from notification-service API
// Uses caching with 60 second TTL to avoid excessive API calls
func (ms *MonitoringService) getNotificationConfig() NotificationConfig {
	// Use cached config if less than 60 seconds old
	if ms.configCache != nil && time.Since(ms.lastConfigFetch) < 60*time.Second {
		return *ms.configCache
	}

	notificationServiceURL := getEnvOrDefault("NOTIFICATION_SERVICE_URL", "http://notification-service:80")

	// Try to fetch from API
	resp, err := ms.httpClient.Get(notificationServiceURL + "/api/v1/config")

	if err != nil {
		log.Printf("⚠️ Failed to fetch notification config from API, using env fallback: %v", err)
		return ms.getConfigFromEnv()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("⚠️ Notification service returned status %d, using env fallback", resp.StatusCode)
		return ms.getConfigFromEnv()
	}

	var apiResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		log.Printf("⚠️ Failed to parse notification config, using env fallback: %v", err)
		return ms.getConfigFromEnv()
	}

	config := NotificationConfig{
		SendSystemEmailNotifications:    true, // Default to true
		SendSystemTelegramNotifications: true,
		SystemEmailRecipient:            "",
		SystemTelegramUsername:          "",
	}

	if val, ok := apiResponse["send_system_email_notifications"].(bool); ok {
		config.SendSystemEmailNotifications = val
	}
	if val, ok := apiResponse["send_system_telegram_notifications"].(bool); ok {
		config.SendSystemTelegramNotifications = val
	}
	if val, ok := apiResponse["system_email_recipient"].(string); ok {
		config.SystemEmailRecipient = val
	}
	if val, ok := apiResponse["system_telegram_username"].(string); ok {
		config.SystemTelegramUsername = val
	}

	// Cache the config
	ms.configCache = &config
	ms.lastConfigFetch = time.Now()

	log.Printf("✅ Fetched notification config from API: Email=%v (to: %s), Telegram=%v (to: %s)",
		config.SendSystemEmailNotifications, config.SystemEmailRecipient,
		config.SendSystemTelegramNotifications, config.SystemTelegramUsername)

	return config
}

// getConfigFromEnv returns notification settings from environment variables as fallback
func (ms *MonitoringService) getConfigFromEnv() NotificationConfig {
	config := NotificationConfig{
		SendSystemEmailNotifications:    getEnvAsBool("SEND_SYSTEM_EMAIL_NOTIFICATIONS", false),
		SendSystemTelegramNotifications: getEnvAsBool("SEND_SYSTEM_TELEGRAM_NOTIFICATIONS", false),
		SystemEmailRecipient:            getEnvOrDefault("SYSTEM_EMAIL_RECIPIENT", ""),
		SystemTelegramUsername:          getEnvOrDefault("SYSTEM_TELEGRAM_USERNAME", ""),
	}
	log.Printf("📝 Using notification config from ENV: Email=%v (to: %s), Telegram=%v (to: %s)",
		config.SendSystemEmailNotifications, config.SystemEmailRecipient,
		config.SendSystemTelegramNotifications, config.SystemTelegramUsername)
	return config
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
