package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// TelegramBot is a minimal Telegram Bot API client (raw HTTP, no external deps)
type TelegramBot struct {
	token  string
	client *http.Client
}

// NewTelegramBot creates a Telegram Bot API client
func NewTelegramBot(token string) *TelegramBot {
	return &TelegramBot{
		token: token,
		// Timeout must exceed long-polling timeout (30s) used in GetUpdates
		client: &http.Client{Timeout: 40 * time.Second},
	}
}

// InlineButton is a single inline keyboard button
type InlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// BotUser describes the bot itself (getMe response)
type BotUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

// Update is an incoming Telegram update (only fields we need)
type Update struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		MessageID int64  `json:"message_id"`
		Text      string `json:"text"`
		Chat      struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		From struct {
			ID        int64  `json:"id"`
			Username  string `json:"username"`
			FirstName string `json:"first_name"`
		} `json:"from"`
	} `json:"message"`
	CallbackQuery *struct {
		ID   string `json:"id"`
		Data string `json:"data"`
		From struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
		} `json:"from"`
		Message *struct {
			MessageID int64 `json:"message_id"`
			Chat      struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
	} `json:"callback_query"`
}

// apiResponse is the generic Telegram API response envelope
type apiResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	Description string          `json:"description"`
}

// call performs a Telegram Bot API method call with a JSON payload
func (b *TelegramBot) call(method string, payload interface{}, result interface{}) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/%s", b.token, method)

	var body io.Reader
	if payload != nil {
		jsonData, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal %s payload: %v", method, err)
		}
		body = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return fmt.Errorf("failed to create %s request: %v", method, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram API %s request failed: %v", method, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read %s response: %v", method, err)
	}

	var apiResp apiResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("failed to parse %s response: %v", method, err)
	}
	if !apiResp.OK {
		return fmt.Errorf("telegram API %s error: %s", method, apiResp.Description)
	}

	if result != nil {
		if err := json.Unmarshal(apiResp.Result, result); err != nil {
			return fmt.Errorf("failed to parse %s result: %v", method, err)
		}
	}
	return nil
}

// GetMe verifies the token and returns bot info
func (b *TelegramBot) GetMe() (*BotUser, error) {
	var me BotUser
	if err := b.call("getMe", nil, &me); err != nil {
		return nil, err
	}
	return &me, nil
}

// GetUpdates performs a long-polling getUpdates call
func (b *TelegramBot) GetUpdates(offset int64) ([]Update, error) {
	payload := map[string]interface{}{
		"offset":          offset,
		"timeout":         30,
		"allowed_updates": []string{"message", "callback_query"},
	}
	var updates []Update
	if err := b.call("getUpdates", payload, &updates); err != nil {
		return nil, err
	}
	return updates, nil
}

// SendMessage sends a text message with an optional inline keyboard, returns message_id.
// parseMode is optional ("Markdown", "MarkdownV2", "HTML" or "" for plain text).
func (b *TelegramBot) SendMessage(chatID int64, text, parseMode string, buttons [][]InlineButton) (int64, error) {
	payload := map[string]interface{}{
		"chat_id": chatID,
		"text":    text,
	}
	if parseMode != "" {
		payload["parse_mode"] = parseMode
	}
	if len(buttons) > 0 {
		payload["reply_markup"] = map[string]interface{}{
			"inline_keyboard": buttons,
		}
	}

	var result struct {
		MessageID int64 `json:"message_id"`
	}
	if err := b.call("sendMessage", payload, &result); err != nil {
		return 0, err
	}
	return result.MessageID, nil
}

// EditMessageText replaces the text of an existing message (also removes its inline keyboard)
func (b *TelegramBot) EditMessageText(chatID, messageID int64, text string) error {
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"message_id": messageID,
		"text":       text,
	}
	return b.call("editMessageText", payload, nil)
}

// AnswerCallbackQuery acknowledges a button press with an optional toast text
func (b *TelegramBot) AnswerCallbackQuery(callbackID, text string) error {
	payload := map[string]interface{}{
		"callback_query_id": callbackID,
	}
	if text != "" {
		payload["text"] = text
	}
	return b.call("answerCallbackQuery", payload, nil)
}
