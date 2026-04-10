package main

import (
	"auth-service/models"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// NotificationClient provides methods to send notifications via the notification service
type NotificationClient struct {
	BaseURL string
	client  *http.Client
}

// NewNotificationClient creates a new notification service client
func NewNotificationClient() *NotificationClient {
	baseURL := os.Getenv("NOTIFICATION_SERVICE_URL")
	if baseURL == "" {
		baseURL = "http://notification-service:80"
	}

	return &NotificationClient{
		BaseURL: baseURL,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// NotificationRequest represents a single notification request for the service
type NotificationRequest struct {
	Type      string `json:"type"`
	Recipient string `json:"recipient"`
	Subject   string `json:"subject,omitempty"`
	Content   string `json:"content"`
}

// BatchNotificationRequest represents a batch notification request
type BatchNotificationRequest struct {
	Notifications []NotificationRequest `json:"notifications"`
	BatchID       string                `json:"batch_id,omitempty"`
}

// newRequest creates an HTTP request with the internal API key header
func (nc *NotificationClient) newRequest(method, url string, body *bytes.Buffer) (*http.Request, error) {
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, url, body)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey := os.Getenv("INTERNAL_API_KEY"); apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	return req, nil
}

// SendEmailNotification sends a single email notification through the notification service
func (nc *NotificationClient) SendEmailNotification(to, subject, body string) error {
	notification := NotificationRequest{
		Type:      "email",
		Recipient: to,
		Subject:   subject,
		Content:   body,
	}

	jsonData, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to marshal notification: %v", err)
	}

	req, err := nc.newRequest("POST", nc.BaseURL+"/api/v1/notifications", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create notification request: %v", err)
	}

	resp, err := nc.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send notification request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("notification service returned status: %d", resp.StatusCode)
	}

	log.Printf("Email notification sent successfully to %s", to)
	return nil
}

// SendBatchEmailNotifications sends multiple email notifications as a batch
func (nc *NotificationClient) SendBatchEmailNotifications(notifications []NotificationRequest, batchID string) error {
	batch := BatchNotificationRequest{
		Notifications: notifications,
		BatchID:       batchID,
	}

	jsonData, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("failed to marshal batch notification: %v", err)
	}

	req, err := nc.newRequest("POST", nc.BaseURL+"/api/v1/notifications/batch", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create batch request: %v", err)
	}

	resp, err := nc.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send batch notification request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("notification service returned status: %d", resp.StatusCode)
	}

	log.Printf("Batch email notifications sent successfully, batch ID: %s", batchID)
	return nil
}

// Global notification client instance
var notificationClient *NotificationClient

// InitNotificationClient initializes the global notification client
func InitNotificationClient() {
	log.Println("🔧 Initializing notification service client...")
	notificationClient = NewNotificationClient()
	// Set the function pointer in models package
	models.SendEmailNotificationViaService = SendEmailNotificationViaServiceImpl
	log.Printf("✅ Notification service client initialized: %s\n", notificationClient.BaseURL)
}

// SendEmailNotificationViaServiceImpl sends an email notification via the notification service
func SendEmailNotificationViaServiceImpl(to, subject, body string) error {
	if notificationClient == nil {
		// No fallback - return error if notification service is not available
		log.Printf("ERROR: Notification service client not initialized")
		return fmt.Errorf("notification service client not initialized")
	}

	return notificationClient.SendEmailNotification(to, subject, body)
}
