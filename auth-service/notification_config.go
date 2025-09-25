package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

// NotificationConfig represents the configuration for notification service
type NotificationConfig struct {
	SMTPHost       string `json:"smtp_host"`
	SMTPPort       string `json:"smtp_port"`
	SMTPUsername   string `json:"smtp_username"`
	SMTPUseTLS     string `json:"smtp_use_tls"`
	SMTPUseAuth    string `json:"smtp_use_auth"`
	SMTPAuthMethod string `json:"smtp_auth_method"`
	MaxRetryAttempts int  `json:"max_retry_attempts"`
	BatchSize       int   `json:"batch_size"`
}

// ConfigureNotificationService configures the notification service with auth-service SMTP settings
func ConfigureNotificationService() error {
	if notificationClient == nil {
		log.Printf("Notification service client not initialized")
		return nil
	}

	// Get current SMTP configuration from environment
	config := NotificationConfig{
		SMTPHost:       os.Getenv("SMTP_HOST"),
		SMTPPort:       os.Getenv("SMTP_PORT"),
		SMTPUsername:   os.Getenv("SMTP_USERNAME"),
		SMTPUseTLS:     os.Getenv("SMTP_USE_TLS"),
		SMTPUseAuth:    os.Getenv("SMTP_USE_AUTH"),
		SMTPAuthMethod: os.Getenv("SMTP_AUTH_METHOD"),
		MaxRetryAttempts: 3,
		BatchSize:       10,
	}

	// Only try to configure if we have SMTP settings
	if config.SMTPHost == "" {
		log.Printf("No SMTP configuration found, skipping notification service configuration")
		return nil
	}

	jsonData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal notification config: %v", err)
	}

	resp, err := notificationClient.client.Post(notificationClient.BaseURL+"/api/v1/config", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Warning: Failed to configure notification service: %v", err)
		return nil // Don't fail startup if notification service is unavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Warning: Notification service configuration returned status: %d", resp.StatusCode)
		return nil
	}

	log.Printf("Notification service configured successfully")
	return nil
}