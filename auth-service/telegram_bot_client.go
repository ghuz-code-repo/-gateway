package main

import (
	"auth-service/models"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// TelegramBotClient sends messages through the notification-bot service
type TelegramBotClient struct {
	BaseURL string
	client  *http.Client
}

// NewTelegramBotClient creates a new notification-bot client
func NewTelegramBotClient() *TelegramBotClient {
	baseURL := os.Getenv("NOTIFICATION_BOT_URL")
	if baseURL == "" {
		baseURL = "http://notification-bot:80"
	}
	return &TelegramBotClient{
		BaseURL: baseURL,
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

// SendMessage sends a Telegram message (optionally with inline buttons) via notification-bot
func (tc *TelegramBotClient) SendMessage(chatID int64, text string, buttons [][]models.TelegramButton) error {
	payload := map[string]interface{}{
		"chat_id": chatID,
		"text":    text,
	}
	if len(buttons) > 0 {
		payload["buttons"] = buttons
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal telegram message: %v", err)
	}

	req, err := http.NewRequest("POST", tc.BaseURL+"/api/v1/send", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create telegram send request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey := os.Getenv("INTERNAL_API_KEY"); apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	resp, err := tc.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send telegram message request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("notification-bot returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Global notification-bot client instance
var telegramBotClient *TelegramBotClient

// InitTelegramBotClient initializes the global notification-bot client
// and wires it into the models package
func InitTelegramBotClient() {
	log.Println("🔧 Initializing notification-bot client...")
	telegramBotClient = NewTelegramBotClient()
	models.SendTelegramViaBot = func(chatID int64, text string, buttons [][]models.TelegramButton) error {
		return telegramBotClient.SendMessage(chatID, text, buttons)
	}
	log.Printf("✅ Notification-bot client initialized: %s\n", telegramBotClient.BaseURL)
}
