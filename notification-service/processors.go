package main

// processors.go — собственно отправка по каналам.
//
// Темп, повторы и очередь живут в limiter.go / dispatcher.go; здесь остаётся
// только «как положить сообщение в провайдера» и как получить от него внятную
// ошибку. Каждая отправка ограничена по времени: и установка соединения, и весь
// обмен целиком — таймауты берутся из конфига своего канала.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// rateLimitError — отказ провайдера по темпу с названным им сроком ожидания.
// Отдельный тип нужен, чтобы не выуживать число из текста ошибки.
type rateLimitError struct {
	msg        string
	retryAfter time.Duration
}

func (e *rateLimitError) Error() string { return e.msg }

// parseTelegramRetryAfter достаёт срок ожидания, если провайдер его назвал.
func parseTelegramRetryAfter(err error) (time.Duration, bool) {
	var rl *rateLimitError
	if errors.As(err, &rl) && rl.retryAfter > 0 {
		return rl.retryAfter, true
	}
	return 0, false
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

// buildEmailMessage собирает тело письма (с вложением или без).
func buildEmailMessage(from, recipient, subject, content, contentTypeHeader string, n *Notification) string {
	if n.AttachmentFilename != "" && len(n.AttachmentContent) > 0 {
		boundary := "----=_Part_" + fmt.Sprintf("%d", time.Now().UnixNano())
		headers := []string{
			"From: " + from,
			"To: " + recipient,
			"Subject: " + subject,
			"MIME-Version: 1.0",
			"Content-Type: multipart/mixed; boundary=\"" + boundary + "\"",
			"",
		}
		textPart := []string{
			"--" + boundary,
			"Content-Type: " + contentTypeHeader,
			"Content-Transfer-Encoding: 8bit",
			"",
			content,
			"",
		}
		attachmentPart := []string{
			"--" + boundary,
			"Content-Type: application/octet-stream; name=\"" + n.AttachmentFilename + "\"",
			"Content-Transfer-Encoding: base64",
			"Content-Disposition: attachment; filename=\"" + n.AttachmentFilename + "\"",
			"",
			base64.StdEncoding.EncodeToString(n.AttachmentContent),
			"",
			"--" + boundary + "--",
		}
		return strings.Join(headers, "\r\n") + "\r\n" +
			strings.Join(textPart, "\r\n") + "\r\n" +
			strings.Join(attachmentPart, "\r\n")
	}

	message := []string{
		"From: " + from,
		"To: " + recipient,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: " + contentTypeHeader,
		"",
		content,
	}
	return strings.Join(message, "\r\n")
}

// dialSMTP открывает соединение с почтовым сервером в рамках таймаутов канала.
//
// Раньше здесь был smtp.Dial без дедлайна: недоступный почтовый сервер держал
// отправку до таймаута TCP в ОС (минуты), занимая воркер канала. Теперь ограничены
// и установка соединения, и каждая команда протокола.
func dialSMTP(ctx context.Context, cfg EmailConfig, chCfg ChannelConfig) (*smtp.Client, error) {
	addr := net.JoinHostPort(cfg.Host, cfg.Port)

	deadline := time.Now().Add(chCfg.sendTimeout())
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	dialer := &net.Dialer{Timeout: chCfg.connectTimeout()}

	var conn net.Conn
	var err error
	if cfg.UseTLS {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: getTLSConfig(cfg.Host)}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("TLS dial error: %v", err)
		}
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("SMTP dial error: %v", err)
		}
	}

	// Дедлайн на сокете покрывает все последующие команды: сервер, замолчавший
	// на середине диалога, не подвесит отправку.
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMTP deadline error: %v", err)
	}

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMTP client error: %v", err)
	}

	if !cfg.UseTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(getTLSConfig(cfg.Host)); err != nil {
				client.Close()
				return nil, fmt.Errorf("start TLS error: %v", err)
			}
		}
	}

	return client, nil
}

// sendEmail отправляет письмо в рамках таймаутов канала email.
func (ns *NotificationService) sendEmail(ctx context.Context, notification *Notification, chCfg ChannelConfig) error {
	config := ns.getEmailConfig()

	if config.Host == "" || config.Port == "" {
		log.Printf("❌ SMTP configuration incomplete: host=%s, port=%s", config.Host, config.Port)
		return fmt.Errorf("SMTP configuration not complete")
	}
	if config.UseAuth && (config.Username == "" || config.Password == "") {
		return fmt.Errorf("SMTP authentication required but credentials not provided")
	}

	originalRecipient := notification.Recipient
	actualRecipient := notification.Recipient
	subject := notification.Subject
	content := notification.Content

	contentType := strings.ToLower(strings.TrimSpace(notification.ContentType))
	if contentType == "" {
		contentType = "text/plain"
	}
	isHTML := contentType == "text/html"
	contentTypeHeader := "text/plain; charset=UTF-8"
	if isHTML {
		contentTypeHeader = "text/html; charset=UTF-8"
	}

	if config.DebugMode && config.DebugEmail != "" {
		actualRecipient = config.DebugEmail
		subject = "[DEBUG] " + subject
		log.Printf("🐞 DEBUG MODE: письмо #%d для %s перенаправлено на %s",
			notification.ID, notificationTarget(notification), maskRecipient(actualRecipient))
		if isHTML {
			content = fmt.Sprintf("<p><b>Конечным получателем является:</b> %s</p><hr>%s", originalRecipient, content)
		} else {
			content = fmt.Sprintf("Конечным получателем является: %s\n\n%s", originalRecipient, content)
		}
	}

	messageBody := buildEmailMessage(config.From, actualRecipient, subject, content, contentTypeHeader, notification)

	client, err := dialSMTP(ctx, config, chCfg)
	if err != nil {
		return err
	}
	defer client.Close()

	if config.UseAuth {
		var auth smtp.Auth
		switch strings.ToLower(config.AuthMethod) {
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

	if err = client.Mail(config.From); err != nil {
		return fmt.Errorf("SMTP MAIL command error: %v", err)
	}
	if err = client.Rcpt(actualRecipient); err != nil {
		return fmt.Errorf("SMTP RCPT command error: %v", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA command error: %v", err)
	}
	if _, err = fmt.Fprint(wc, messageBody); err != nil {
		wc.Close()
		return fmt.Errorf("SMTP body write error: %v", err)
	}
	if err = wc.Close(); err != nil {
		return fmt.Errorf("SMTP data close error: %v", err)
	}

	// Ошибку QUIT не поднимаем: письмо уже принято сервером,
	// повтор из-за неудачного прощания привёл бы к дублю.
	if err := client.Quit(); err != nil {
		log.Printf("⚠️ SMTP QUIT после успешной отправки #%d: %v", notification.ID, err)
	}

	log.Printf("✅ Email sent to %s (notification #%d)", maskRecipient(actualRecipient), notification.ID)
	return nil
}

// getNotificationBotURL returns the notification-bot service URL
func getNotificationBotURL() string {
	url := os.Getenv("NOTIFICATION_BOT_URL")
	if url == "" {
		url = "http://notification-bot:80"
	}
	return url
}

// botErrorResponse — ответ notification-bot об ошибке. retry_after проброшен
// из ответа Telegram, чтобы ждать ровно столько, сколько требует Telegram.
type botErrorResponse struct {
	Error      string `json:"error"`
	RetryAfter int    `json:"retry_after"`
}

// sendTelegram отправляет сообщение через сервис notification-bot.
// Все telegram/telegram_system идут через единого бота портала.
func (ns *NotificationService) sendTelegram(ctx context.Context, notification *Notification, isSystemBot bool, chCfg ChannelConfig) error {
	config := ns.getConfigFromDB()

	// NOTE: флаги telegram_enabled / telegram_system_enabled больше НЕ гейтят
	// отправку. Раньше они означали «настроен собственный токен бота»; теперь
	// единственный канал — notification-bot, который всегда доступен. Включение
	// системных алертов управляется send_system_telegram_notifications на стороне
	// вызывающего сервиса (monitoring-service, security guard).
	var chatIDStr string
	if isSystemBot && config.SystemTelegramChatID != "" {
		chatIDStr = config.SystemTelegramChatID
	} else {
		chatIDStr = notification.Recipient
	}

	chatIDStr = strings.TrimSpace(chatIDStr)
	chatID, err := strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		// Не число — значит telegram-ник. Такое приходит из external_recipient и из
		// system_telegram_username в конфиге системных алертов; для пользователей
		// портала правильный путь — поле login, оно резолвится на приёме запроса.
		// Резолв ника работает только для привязавших Telegram в личном кабинете.
		resolved, rerr := ns.resolveTelegramChatID(chatIDStr)
		if rerr != nil {
			return fmt.Errorf("получатель «%s»: %v", chatIDStr, rerr)
		}
		chatID, err = strconv.ParseInt(resolved, 10, 64)
		if err != nil {
			return fmt.Errorf("некорректный chat_id «%s» от auth-service", resolved)
		}
	}

	messageText := notification.Content
	if notification.Subject != "" {
		messageText = fmt.Sprintf("*%s*\n\n%s", notification.Subject, notification.Content)
	}

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       messageText,
		"parse_mode": "Markdown",
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", getNotificationBotURL()+"/api/v1/send", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create notification-bot request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey := os.Getenv("INTERNAL_API_KEY"); apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	resp, err := ns.channelHTTPClient(chCfg).Do(req)
	if err != nil {
		return fmt.Errorf("notification-bot request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read notification-bot response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("❌ notification-bot error (status %d): %s", resp.StatusCode, string(body))

		var botErr botErrorResponse
		_ = json.Unmarshal(body, &botErr)

		sendErr := error(fmt.Errorf("notification-bot error: %s", string(body)))
		if resp.StatusCode == http.StatusTooManyRequests || botErr.RetryAfter > 0 {
			sendErr = &rateLimitError{
				msg:        fmt.Sprintf("notification-bot rate limit: %s", string(body)),
				retryAfter: time.Duration(botErr.RetryAfter) * time.Second,
			}
		}

		// Пользователь заблокировал бота (или чат исчез) — привязка мертва.
		// Пока chat_id остаётся в профиле, каждое следующее уведомление снова
		// пойдёт этим путём и будет держать очередь; убираем адрес из источника
		// истины и из кэша, чтобы отказ приходил вызывающему сразу на приёме.
		if isDeadTelegramBinding(sendErr) {
			ns.reportTelegramLinkBroken(chatID, strings.TrimSpace(string(body)))
			ns.invalidateRecipientCache("telegram", notification.RecipientLogin)
		}

		return sendErr
	}

	log.Printf("✅ Telegram message sent to %s via notification-bot (notification #%d)",
		maskRecipient(strconv.FormatInt(chatID, 10)), notification.ID)
	return nil
}

// updateBatchStats пересчитывает статистику пачки и закрывает её, когда все
// уведомления дошли до конечного статуса. Уведомления пачки расходятся по
// каналам с разным темпом, поэтому «пачка завершена» определяется по счётчикам,
// а не по окончанию цикла обработки.
func (ns *NotificationService) updateBatchStats(batchID string) {
	var stats struct {
		ProcessedCount int64
		SuccessCount   int64
		FailedCount    int64
	}

	ns.db.Model(&Notification{}).
		Where("batch_id = ? AND status IN (?)", batchID, []string{string(StatusSent), string(StatusFailed)}).
		Count(&stats.ProcessedCount)

	ns.db.Model(&Notification{}).
		Where("batch_id = ? AND status = ?", batchID, StatusSent).
		Count(&stats.SuccessCount)

	ns.db.Model(&Notification{}).
		Where("batch_id = ? AND status = ?", batchID, StatusFailed).
		Count(&stats.FailedCount)

	updates := map[string]interface{}{
		"processed_count": int(stats.ProcessedCount),
		"success_count":   int(stats.SuccessCount),
		"failed_count":    int(stats.FailedCount),
		"updated_at":      time.Now().Unix(),
	}

	var batch NotificationBatch
	if err := ns.db.First(&batch, "id = ?", batchID).Error; err == nil {
		if batch.TotalCount > 0 && int(stats.ProcessedCount) >= batch.TotalCount {
			updates["status"] = "completed"
		}
	}

	ns.db.Model(&NotificationBatch{}).Where("id = ?", batchID).Updates(updates)
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
