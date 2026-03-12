package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// waitForSendSlot применяет глобальную задержку между ВСЕМИ отправками
func (ns *NotificationService) waitForSendSlot() {
	ns.sendMutex.Lock()
	defer ns.sendMutex.Unlock()

	config := ns.getConfigFromDB()
	delayBetweenMessages := time.Duration(config.DelayBetweenMessagesMS) * time.Millisecond

	// Проверяем прошло ли достаточно времени с последней отправки
	if !ns.lastSendTime.IsZero() {
		timeSinceLastSend := time.Since(ns.lastSendTime)
		if timeSinceLastSend < delayBetweenMessages {
			waitTime := delayBetweenMessages - timeSinceLastSend
			time.Sleep(waitTime)
		}
	}

	// Обновляем время последней отправки
	ns.lastSendTime = time.Now()
}

// processBatch processes all notifications in a batch
func (ns *NotificationService) processBatch(batchID string) {
	log.Printf("Processing batch: %s", batchID)

	// Get batch
	var batch NotificationBatch
	if err := ns.db.First(&batch, "id = ?", batchID).Error; err != nil {
		log.Printf("Failed to get batch %s: %v", batchID, err)
		return
	}

	// Get notifications for this batch
	var notifications []Notification
	if err := ns.db.Where("batch_id = ? AND status = ?", batchID, StatusPending).Find(&notifications).Error; err != nil {
		log.Printf("Failed to get notifications for batch %s: %v", batchID, err)
		return
	}

	// Get current config from database
	config := ns.getConfigFromDB()

	// Process notifications with rate limiting
	batchSize := config.BatchSize
	delayBetweenBatches := time.Duration(config.DelayBetweenBatchesMS) * time.Millisecond

	for i := 0; i < len(notifications); i += batchSize {
		end := i + batchSize
		if end > len(notifications) {
			end = len(notifications)
		}

		// Process batch of notifications
		// Глобальная задержка применяется автоматически через waitForSendSlot()
		for j := i; j < end; j++ {
			ns.processNotification(&notifications[j])
		}

		// Update batch statistics
		ns.updateBatchStats(batchID)

		// Wait before next batch (except for the last one)
		if end < len(notifications) {
			time.Sleep(delayBetweenBatches)
		}
	}

	// Final update of batch status
	ns.updateBatchStats(batchID)

	// Mark batch as completed
	ns.db.Model(&batch).Where("id = ?", batchID).Update("status", "completed")

	log.Printf("Batch %s processing completed", batchID)
}

// processNotification processes a single notification
func (ns *NotificationService) processNotification(notification *Notification) {
	// Update status to sending
	ns.db.Model(notification).Updates(Notification{
		Status: StatusSending,
	})

	var err error
	config := ns.getConfigFromDB()
	maxAttempts := config.MaxRetryAttempts
	const maxRateLimitRetries = 10
	rateLimitRetries := 0

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		notification.Attempts = attempt

		// Применяем глобальную задержку перед отправкой
		ns.waitForSendSlot()

		switch notification.Type {
		case NotificationTypeEmail:
			err = ns.sendEmail(notification)
		case NotificationTypeTelegram:
			err = ns.sendTelegram(notification, false) // Обычный бот
		case NotificationTypeTelegramSystem:
			err = ns.sendTelegram(notification, true) // Системный бот
		case NotificationTypeSMS:
			err = ns.sendSMS(notification)
		case NotificationTypePush:
			err = ns.sendPush(notification)
		default:
			err = fmt.Errorf("unsupported notification type: %s", notification.Type)
		}

		if err == nil {
			// Success
			now := time.Now().Unix()
			ns.db.Model(notification).Updates(Notification{
				Status:   StatusSent,
				SentAt:   &now,
				Attempts: attempt,
			})
			log.Printf("Notification %d sent successfully on attempt %d", notification.ID, attempt)
			return
		}

		// Check if error is rate-limit (Telegram 429 Too Many Requests)
		if isRateLimitError(err) {
			rateLimitRetries++
			if rateLimitRetries > maxRateLimitRetries {
				log.Printf("❌ Rate limit retry limit (%d) exceeded for notification %d", maxRateLimitRetries, notification.ID)
				break
			}
			log.Printf("⏳ Rate limit exceeded for notification %d (retry %d/%d), waiting 30 seconds...", notification.ID, rateLimitRetries, maxRateLimitRetries)
			time.Sleep(30 * time.Second)
			// Не считаем попытку проваленной, пробуем снова
			attempt--
			continue
		}

		// Check if error is permanent
		if isPermanentError(err) {
			log.Printf("Permanent error for notification %d: %v", notification.ID, err)
			break
		}

		log.Printf("Attempt %d failed for notification %d: %v", attempt, notification.ID, err)

		// Wait before retry (exponential backoff)
		if attempt < maxAttempts {
			waitTime := time.Duration(attempt*attempt) * time.Second
			time.Sleep(waitTime)
		}
	}

	// All attempts failed
	ns.db.Model(notification).Updates(Notification{
		Status:    StatusFailed,
		LastError: err.Error(),
		Attempts:  maxAttempts,
	})
	log.Printf("Notification %d failed after %d attempts: %v", notification.ID, maxAttempts, err)
}

// encodeRFC2047 кодирует строку в формат RFC 2047 для email заголовков (UTF-8)
func encodeRFC2047(s string) string {
	// RFC 2047: =?charset?encoding?encoded-text?=
	// Используем base64 encoding (B)
	return "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
}

// encodeQuotedPrintable кодирует содержимое в quoted-printable для UTF-8
func encodeQuotedPrintable(s string) string {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	w.Write([]byte(s))
	w.Close()
	return buf.String()
}

// sendEmail sends an email notification
func (ns *NotificationService) sendEmail(notification *Notification) error {
	config := ns.getEmailConfig()

	// Validate configuration
	if config.Host == "" || config.Port == "" {
		log.Printf("❌ SMTP configuration incomplete: host=%s, port=%s", config.Host, config.Port)
		return fmt.Errorf("SMTP configuration not complete")
	}

	if config.UseAuth && (config.Username == "" || config.Password == "") {
		return fmt.Errorf("SMTP authentication required but credentials not provided")
	}

	// Prepare recipient and content
	originalRecipient := notification.Recipient
	actualRecipient := notification.Recipient
	subject := notification.Subject
	content := notification.Content

	// Apply debug mode if enabled
	if config.DebugMode && config.DebugEmail != "" {
		actualRecipient = config.DebugEmail
		subject = "[DEBUG] " + subject
		content = fmt.Sprintf("Конечным получателем является: %s\n\n%s", originalRecipient, content)
	}

	// Build email message
	var messageBody string

	if notification.AttachmentFilename != "" && len(notification.AttachmentContent) > 0 {
		// Email with attachment - use MIME multipart
		boundary := "----=_Part_" + fmt.Sprintf("%d", time.Now().Unix())
		headers := []string{
			"From: " + config.From,
			"To: " + actualRecipient,
			"Subject: " + subject,
			"MIME-Version: 1.0",
			"Content-Type: multipart/mixed; boundary=\"" + boundary + "\"",
			"",
		}

		// Text part
		textPart := []string{
			"--" + boundary,
			"Content-Type: text/plain; charset=UTF-8",
			"Content-Transfer-Encoding: 8bit",
			"",
			content,
			"",
		}

		// Attachment part
		attachmentEncoded := base64.StdEncoding.EncodeToString(notification.AttachmentContent)
		attachmentPart := []string{
			"--" + boundary,
			"Content-Type: application/octet-stream; name=\"" + notification.AttachmentFilename + "\"",
			"Content-Transfer-Encoding: base64",
			"Content-Disposition: attachment; filename=\"" + notification.AttachmentFilename + "\"",
			"",
			attachmentEncoded,
			"",
			"--" + boundary + "--",
		}

		messageBody = strings.Join(headers, "\r\n") + "\r\n" + strings.Join(textPart, "\r\n") + "\r\n" + strings.Join(attachmentPart, "\r\n")
	} else {
		// Simple email without attachment
		message := []string{
			"From: " + config.From,
			"To: " + actualRecipient,
			"Subject: " + subject,
			"MIME-Version: 1.0",
			"Content-Type: text/plain; charset=UTF-8",
			"",
			content,
		}
		messageBody = strings.Join(message, "\r\n")
	}
	addr := fmt.Sprintf("%s:%s", config.Host, config.Port)

	// Create SMTP client
	var client *smtp.Client
	var err error

	if config.UseTLS {
		tlsConfig := getTLSConfig(config.Host)
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("TLS dial error: %v", err)
		}

		client, err = smtp.NewClient(conn, config.Host)
		if err != nil {
			return fmt.Errorf("SMTP client error: %v", err)
		}
	} else {
		client, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("SMTP dial error: %v", err)
		}

		// Start TLS if available
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsConfig := getTLSConfig(config.Host)
			if err = client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("start TLS error: %v", err)
			}
		}
	}
	defer client.Quit()

	// Authenticate if needed
	if config.UseAuth {
		var auth smtp.Auth
		switch strings.ToLower(config.AuthMethod) {
		case "plain":
			auth = smtp.PlainAuth("", config.Username, config.Password, config.Host)
		case "login":
			auth = LoginAuth(config.Username, config.Password)
		case "crammd5":
			auth = smtp.CRAMMD5Auth(config.Username, config.Password)
		default:
			auth = smtp.PlainAuth("", config.Username, config.Password, config.Host)
		}

		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication error: %v", err)
		}
	}

	// Set sender and recipient
	if err = client.Mail(config.From); err != nil {
		return fmt.Errorf("SMTP MAIL command error: %v", err)
	}

	if err = client.Rcpt(actualRecipient); err != nil {
		return fmt.Errorf("SMTP RCPT command error: %v", err)
	}

	// Send email body
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA command error: %v", err)
	}

	_, err = fmt.Fprint(wc, messageBody)
	if err != nil {
		return fmt.Errorf("SMTP body write error: %v", err)
	}

	err = wc.Close()
	if err != nil {
		return fmt.Errorf("SMTP data close error: %v", err)
	}

	log.Printf("✅ Email sent to %s (notification #%d)", notification.Recipient, notification.ID)
	return nil
}

// sendTelegram sends a Telegram notification
func (ns *NotificationService) sendTelegram(notification *Notification, isSystemBot bool) error {
	config := ns.getConfigFromDB()

	// Select appropriate bot token and recipient
	var botToken string
	var chatID string

	if isSystemBot {
		botToken = config.TelegramSystemBotToken
		if !config.TelegramSystemEnabled {
			return fmt.Errorf("telegram system bot is not enabled")
		}

		if config.SystemTelegramChatID != "" {
			chatID = config.SystemTelegramChatID
		} else {
			chatID = notification.Recipient
		}
	} else {
		botToken = config.TelegramBotToken
		chatID = notification.Recipient
		if !config.TelegramEnabled {
			return fmt.Errorf("telegram bot is not enabled")
		}
	}

	if botToken == "" {
		return fmt.Errorf("telegram bot token not configured")
	}

	// Prepare message text
	messageText := notification.Content
	if notification.Subject != "" {
		messageText = fmt.Sprintf("*%s*\n\n%s", notification.Subject, notification.Content)
	}

	// Prepare request payload
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       messageText,
		"parse_mode": "Markdown",
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Send request to Telegram Bot API
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	resp, err := ns.httpClient.Post(url, "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("telegram API request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	// Check response
	if resp.StatusCode != http.StatusOK {
		log.Printf("❌ Telegram API error (status %d): %s", resp.StatusCode, string(body))
		return fmt.Errorf("telegram API error: %s", string(body))
	}

	// Parse response to check if message was sent
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	if ok, exists := response["ok"].(bool); !exists || !ok {
		description := "unknown error"
		if desc, exists := response["description"].(string); exists {
			description = desc
		}
		return fmt.Errorf("telegram API returned error: %s", description)
	}

	log.Printf("✅ Telegram message sent to %s (notification #%d)", notification.Recipient, notification.ID)
	return nil
}

// sendSMS sends an SMS notification (placeholder)
func (ns *NotificationService) sendSMS(notification *Notification) error {
	// TODO: Implement SMS sending
	log.Printf("SMS sending not implemented yet for notification %d", notification.ID)
	return fmt.Errorf("SMS sending not implemented")
}

// sendPush sends a push notification (placeholder)
func (ns *NotificationService) sendPush(notification *Notification) error {
	// TODO: Implement push notification sending
	log.Printf("Push notification sending not implemented yet for notification %d", notification.ID)
	return fmt.Errorf("push notification sending not implemented")
}

// updateBatchStats updates batch statistics
func (ns *NotificationService) updateBatchStats(batchID string) {
	var stats struct {
		ProcessedCount int64 `json:"processed_count"`
		SuccessCount   int64 `json:"success_count"`
		FailedCount    int64 `json:"failed_count"`
	}

	// Count processed notifications
	ns.db.Model(&Notification{}).
		Where("batch_id = ? AND status IN (?)", batchID, []string{string(StatusSent), string(StatusFailed)}).
		Count(&stats.ProcessedCount)

	// Count successful notifications
	ns.db.Model(&Notification{}).
		Where("batch_id = ? AND status = ?", batchID, StatusSent).
		Count(&stats.SuccessCount)

	// Count failed notifications
	ns.db.Model(&Notification{}).
		Where("batch_id = ? AND status = ?", batchID, StatusFailed).
		Count(&stats.FailedCount)

	// Update batch
	ns.db.Model(&NotificationBatch{}).
		Where("id = ?", batchID).
		Updates(NotificationBatch{
			ProcessedCount: int(stats.ProcessedCount),
			SuccessCount:   int(stats.SuccessCount),
			FailedCount:    int(stats.FailedCount),
		})
}

// EmailConfig holds SMTP configuration
type EmailConfig struct {
	Host       string
	Port       string
	Username   string
	Password   string
	From       string
	UseTLS     bool
	UseAuth    bool
	AuthMethod string
	Debug      bool
	DebugMode  bool   // Debug режим - все письма на debug email
	DebugEmail string // Email для всех писем в debug режиме
}

// getEmailConfig loads email configuration from database
func (ns *NotificationService) getEmailConfig() EmailConfig {
	dbConfig := ns.getConfigFromDB()
	debug, _ := strconv.ParseBool(os.Getenv("SMTP_DEBUG"))

	config := EmailConfig{
		Host:       dbConfig.SMTPHost,
		Port:       dbConfig.SMTPPort,
		Username:   dbConfig.SMTPUsername,
		Password:   dbConfig.SMTPPassword,
		From:       dbConfig.SMTPFrom,
		UseTLS:     dbConfig.SMTPUseTLS,
		UseAuth:    dbConfig.SMTPUseAuth,
		AuthMethod: dbConfig.SMTPAuthMethod,
		Debug:      debug,
		DebugMode:  dbConfig.DebugMode,
		DebugEmail: dbConfig.DebugEmail,
	}

	// Use environment variables as fallback if database values are empty
	if config.Host == "" {
		config.Host = os.Getenv("SMTP_HOST")
		if config.Host == "" {
			config.Host = "smtp.gmail.com"
		}
	}
	if config.Port == "" {
		config.Port = os.Getenv("SMTP_PORT")
		if config.Port == "" {
			config.Port = "587"
		}
	}
	if config.Username == "" {
		config.Username = os.Getenv("SMTP_USERNAME")
	}
	if config.Password == "" {
		config.Password = os.Getenv("SMTP_PASSWORD")
	}
	if config.From == "" {
		config.From = os.Getenv("SMTP_FROM")
		if config.From == "" {
			config.From = config.Username
		}
	}
	if config.AuthMethod == "" {
		config.AuthMethod = os.Getenv("SMTP_AUTH_METHOD")
		if config.AuthMethod == "" {
			config.AuthMethod = "plain"
		}
	}
	// Parse boolean environment variables if not set in DB
	if !config.UseTLS {
		useTLS, _ := strconv.ParseBool(os.Getenv("SMTP_USE_TLS"))
		config.UseTLS = useTLS
	}
	if !config.UseAuth {
		useAuth, _ := strconv.ParseBool(os.Getenv("SMTP_USE_AUTH"))
		config.UseAuth = useAuth
	}

	return config
}

// isIPAddress checks if the given string is an IP address
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// getTLSConfig creates appropriate TLS configuration
func getTLSConfig(host string) *tls.Config {
	if isIPAddress(host) {
		return &tls.Config{
			InsecureSkipVerify: true,
		}
	} else {
		return &tls.Config{
			ServerName: host,
		}
	}
}

// isPermanentError determines if an error is permanent and shouldn't be retried
func isPermanentError(err error) bool {
	errStr := strings.ToLower(err.Error())

	// Common permanent SMTP errors (НЕ временные/rate-limit ошибки!)
	permanentErrors := []string{
		"no such user",               // Пользователь не существует
		"user unknown",               // Неизвестный пользователь
		"recipient address rejected", // Адрес получателя отклонён
		"invalid recipient",          // Недействительный получатель
		"550",                        // SMTP 550 Requested action not taken: mailbox unavailable (permanent)
		"551",                        // SMTP 551 User not local
		"553",                        // SMTP 553 Requested action not taken: mailbox name not allowed
		"554",                        // SMTP 554 Transaction failed (permanent)
	}

	for _, permErr := range permanentErrors {
		if strings.Contains(errStr, permErr) {
			return true
		}
	}

	return false
}

// isRateLimitError checks if error is a rate limit error (Telegram 429 or SMTP rate limiting)
func isRateLimitError(err error) bool {
	errStr := strings.ToLower(err.Error())

	// Check for rate limit indicators (Telegram and SMTP)
	rateLimitErrors := []string{
		"429",                     // HTTP 429 Too Many Requests (Telegram)
		"too many requests",       // Generic rate limit message
		"rate limit",              // Generic rate limit
		"retry after",             // Retry-After header indicator
		"451",                     // SMTP 451 Requested action aborted: local error in processing
		"452",                     // SMTP 452 Requested action not taken: insufficient system storage
		"421",                     // SMTP 421 Service not available, closing transmission channel
		"throttling",              // Outlook/Exchange throttling
		"exceeded sending limits", // Outlook sending limit
		"mailbox full",            // Temporary mailbox full (может быть временной)
		"try again later",         // Generic retry suggestion
		"temporarily deferred",    // SMTP temporary deferral
		"recipient rate limit",    // Recipient-specific rate limit
	}

	for _, rateLimitErr := range rateLimitErrors {
		if strings.Contains(errStr, rateLimitErr) {
			return true
		}
	}

	return false
}

// LoginAuth implements the LOGIN authentication mechanism
type loginAuth struct {
	username, password string
}

// LoginAuth returns an Auth that implements the LOGIN authentication mechanism
func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

// Start begins an authentication with the server
func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

// Next continues the authentication
func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, fmt.Errorf("unknown LOGIN challenge: %s", fromServer)
		}
	}
	return nil, nil
}

// Utility functions
func init() {
	// Update getCurrentTimestamp to return actual timestamp
	getCurrentTimestamp = func() int64 {
		return time.Now().Unix()
	}

	// Update generateBatchID to use proper UUID
	generateBatchID = func() string {
		return "batch_" + uuid.New().String()
	}
}

// Global functions that can be overridden
var getCurrentTimestamp = func() int64 {
	return time.Now().Unix()
}

var generateBatchID = func() string {
	return "batch_" + uuid.New().String()
}
