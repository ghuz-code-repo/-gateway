package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AuthClient calls auth-service internal API (link confirmation, login decisions)
type AuthClient struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewAuthClient creates a client for the auth-service internal API
func NewAuthClient(baseURL, apiKey string) *AuthClient {
	return &AuthClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

// AuthResponse is a generic response from auth-service telegram endpoints
type AuthResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Frozen  bool   `json:"frozen,omitempty"`
}

// post sends a JSON POST to auth-service and decodes the response.
// Auth-service replies with a user-facing message even on 4xx statuses.
func (a *AuthClient) post(path string, payload interface{}) (*AuthResponse, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	req, err := http.NewRequest("POST", a.baseURL+path, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth-service request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read auth-service response: %v", err)
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return nil, fmt.Errorf("failed to parse auth-service response (status %d): %v", resp.StatusCode, err)
	}
	return &authResp, nil
}

// ConfirmLink confirms a Telegram account link started via /start <token>
func (a *AuthClient) ConfirmLink(token string, chatID int64, tgUsername, firstName string) (*AuthResponse, error) {
	return a.post("/api/telegram/link/confirm", map[string]interface{}{
		"token":       token,
		"chat_id":     chatID,
		"tg_username": tgUsername,
		"first_name":  firstName,
	})
}

// LoginDecision reports the user's approve/reject decision for a login request
func (a *AuthClient) LoginDecision(requestID, decision string, chatID int64) (*AuthResponse, error) {
	return a.post("/api/telegram/login/decision", map[string]interface{}{
		"request_id": requestID,
		"decision":   decision,
		"chat_id":    chatID,
	})
}
