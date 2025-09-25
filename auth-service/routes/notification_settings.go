package routes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
)

// NotificationSettings represents notification service configuration
type NotificationSettings struct {
	SMTPHost         string `json:"smtp_host" form:"smtp_host"`
	SMTPPort         string `json:"smtp_port" form:"smtp_port"`
	SMTPUsername     string `json:"smtp_username" form:"smtp_username"`
	SMTPPassword     string `json:"smtp_password" form:"smtp_password"`
	SMTPFrom         string `json:"smtp_from" form:"smtp_from"`
	SMTPUseTLS       bool   `json:"smtp_use_tls" form:"smtp_use_tls"`
	SMTPUseAuth      bool   `json:"smtp_use_auth" form:"smtp_use_auth"`
	SMTPAuthMethod   string `json:"smtp_auth_method" form:"smtp_auth_method"`
	MaxRetryAttempts int    `json:"max_retry_attempts" form:"max_retry_attempts"`
	BatchSize        int    `json:"batch_size" form:"batch_size"`
	DelayBetweenMS   int    `json:"delay_between_batches_ms" form:"delay_between_batches_ms"`
}

// getNotificationSettings displays the notification settings page
func getNotificationSettings(c *gin.Context) {
	// Get current settings from notification service
	notificationServiceURL := os.Getenv("NOTIFICATION_SERVICE_URL")
	if notificationServiceURL == "" {
		notificationServiceURL = "http://notification-service:8082"
	}

	var currentSettings NotificationSettings
	
	// Try to get current config from notification service
	resp, err := http.Get(notificationServiceURL + "/api/v1/config")
	if err != nil {
		log.Printf("Failed to get notification service config: %v", err)
		// Use default values
		currentSettings = getDefaultNotificationSettings()
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var config map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&config); err == nil {
				currentSettings = mapToNotificationSettings(config)
			} else {
				currentSettings = getDefaultNotificationSettings()
			}
		} else {
			currentSettings = getDefaultNotificationSettings()
		}
	}

	// Get user info for template
	user, exists := c.Get("user")
	if !exists {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"error": "User information not found",
		})
		return
	}

	c.HTML(http.StatusOK, "notification-settings.html", gin.H{
		"user":     user,
		"settings": currentSettings,
		"title":    "Настройки сервиса уведомлений",
	})
}

// updateNotificationSettings handles the form submission for notification settings
func updateNotificationSettings(c *gin.Context) {
	var settings NotificationSettings
	if err := c.ShouldBind(&settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid form data: " + err.Error(),
		})
		return
	}

	// Update notification service configuration
	err := updateNotificationServiceConfig(settings)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to update notification service: " + err.Error(),
		})
		return
	}

	// Also update environment variables for auth-service (optional)
	updateAuthServiceEnvVars(settings)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Настройки сервиса уведомлений успешно обновлены",
	})
}

// testNotificationSettings tests the notification service with current settings
func testNotificationSettings(c *gin.Context) {
	// Get test email from form
	testEmail := c.PostForm("test_email")
	if testEmail == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Test email is required",
		})
		return
	}

	// Create test notification
	testNotification := map[string]interface{}{
		"type":      "email",
		"recipient": testEmail,
		"subject":   "Тест настроек уведомлений",
		"content":   "Это тестовое сообщение для проверки настроек сервиса уведомлений. Если вы получили это письмо, настройки работают корректно!",
	}

	// Send to notification service
	notificationServiceURL := os.Getenv("NOTIFICATION_SERVICE_URL")
	if notificationServiceURL == "" {
		notificationServiceURL = "http://notification-service:8082"
	}

	jsonData, err := json.Marshal(testNotification)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to create test notification: " + err.Error(),
		})
		return
	}

	resp, err := http.Post(notificationServiceURL+"/api/v1/notifications", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to send test notification: " + err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to parse response: " + err.Error(),
		})
		return
	}

	if resp.StatusCode == 202 {
		c.JSON(http.StatusOK, gin.H{
			"success":        true,
			"message":        fmt.Sprintf("Тестовое уведомление отправлено на %s", testEmail),
			"notification_id": result["id"],
		})
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   fmt.Sprintf("Notification service error: %v", result["error"]),
		})
	}
}

// Helper functions

func getDefaultNotificationSettings() NotificationSettings {
	return NotificationSettings{
		SMTPHost:         "smtp.gmail.com",
		SMTPPort:         "587",
		SMTPUsername:     "",
		SMTPPassword:     "",
		SMTPFrom:         "",
		SMTPUseTLS:       true,
		SMTPUseAuth:      true,
		SMTPAuthMethod:   "plain",
		MaxRetryAttempts: 3,
		BatchSize:        10,
		DelayBetweenMS:   1000,
	}
}

func mapToNotificationSettings(config map[string]interface{}) NotificationSettings {
	settings := getDefaultNotificationSettings()

	if val, ok := config["smtp_host"].(string); ok {
		settings.SMTPHost = val
	}
	if val, ok := config["smtp_port"].(string); ok {
		settings.SMTPPort = val
	}
	if val, ok := config["smtp_username"].(string); ok {
		settings.SMTPUsername = val
	}
	if val, ok := config["smtp_from"].(string); ok {
		settings.SMTPFrom = val
	}
	if val, ok := config["smtp_use_tls"].(string); ok {
		settings.SMTPUseTLS = val == "true"
	}
	if val, ok := config["smtp_use_auth"].(string); ok {
		settings.SMTPUseAuth = val == "true"
	}
	if val, ok := config["smtp_auth_method"].(string); ok {
		settings.SMTPAuthMethod = val
	}
	if val, ok := config["max_retry_attempts"].(float64); ok {
		settings.MaxRetryAttempts = int(val)
	}
	if val, ok := config["batch_size"].(float64); ok {
		settings.BatchSize = int(val)
	}

	return settings
}

func updateNotificationServiceConfig(settings NotificationSettings) error {
	notificationServiceURL := os.Getenv("NOTIFICATION_SERVICE_URL")
	if notificationServiceURL == "" {
		notificationServiceURL = "http://notification-service:8082"
	}

	// Convert settings to map for JSON
	configMap := map[string]interface{}{
		"smtp_host":              settings.SMTPHost,
		"smtp_port":              settings.SMTPPort,
		"smtp_username":          settings.SMTPUsername,
		"smtp_password":          settings.SMTPPassword,
		"smtp_from":              settings.SMTPFrom,
		"smtp_use_tls":           strconv.FormatBool(settings.SMTPUseTLS),
		"smtp_use_auth":          strconv.FormatBool(settings.SMTPUseAuth),
		"smtp_auth_method":       settings.SMTPAuthMethod,
		"max_retry_attempts":     settings.MaxRetryAttempts,
		"batch_size":             settings.BatchSize,
		"delay_between_batches_ms": settings.DelayBetweenMS,
	}

	jsonData, err := json.Marshal(configMap)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	resp, err := http.Post(notificationServiceURL+"/api/v1/config", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send config update: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("notification service returned status: %d", resp.StatusCode)
	}

	return nil
}

func updateAuthServiceEnvVars(settings NotificationSettings) {
	// Update environment variables for auth-service
	// This is for runtime configuration, actual .env file update would require file I/O
	os.Setenv("SMTP_HOST", settings.SMTPHost)
	os.Setenv("SMTP_PORT", settings.SMTPPort)
	os.Setenv("SMTP_USERNAME", settings.SMTPUsername)
	os.Setenv("SMTP_PASSWORD", settings.SMTPPassword)
	os.Setenv("SMTP_FROM", settings.SMTPFrom)
	os.Setenv("SMTP_USE_TLS", strconv.FormatBool(settings.SMTPUseTLS))
	os.Setenv("SMTP_USE_AUTH", strconv.FormatBool(settings.SMTPUseAuth))
	os.Setenv("SMTP_AUTH_METHOD", settings.SMTPAuthMethod)

	log.Printf("Updated auth-service environment variables for SMTP")
}