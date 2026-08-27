package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
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
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type NotificationService struct {
	db              *gorm.DB
	sendGates       map[string]*channelGate // Пер-канальный throttle (email/telegram/sms/push независимы)
	configCache     *NotificationConfig
	configCacheMu   sync.RWMutex
	lastConfigFetch time.Time
	httpClient      *http.Client   // Shared HTTP client for external API calls
	workerSem       chan struct{}  // Semaphore to limit concurrent send goroutines
	wg              sync.WaitGroup // Tracks in-flight goroutines for graceful shutdown
	guard           *ServiceGuard  // Детектор аномалий межсервисных запросов (security.go)

	// Кэш резолва telegram username -> chat_id (чтобы не ходить в auth-service
	// на каждую отправку и не тормозить доставку telegram-уведомлений)
	chatIDCache map[string]chatIDEntry
	chatIDMu    sync.RWMutex

	// Кэш резолва «логин портала -> адрес доставки» (recipients.go).
	// Ключ учитывает сервис и канал: доступ к пользователю проверяется
	// для конкретного сервиса-отправителя, адрес зависит от канала.
	recipientCache map[string]recipientCacheEntry
	recipientMu    sync.RWMutex
}

type chatIDEntry struct {
	chatID string
	at     time.Time
}

// channelGate throttles sends within one channel independently of others
type channelGate struct {
	mu   sync.Mutex
	last time.Time
}

type NotificationType string

const (
	NotificationTypeEmail          NotificationType = "email"
	NotificationTypeSMS            NotificationType = "sms"
	NotificationTypePush           NotificationType = "push"
	NotificationTypeTelegram       NotificationType = "telegram"        // Для отправки пользователям
	NotificationTypeTelegramSystem NotificationType = "telegram_system" // Для системных уведомлений
)

type NotificationStatus string

const (
	StatusPending   NotificationStatus = "pending"
	StatusSending   NotificationStatus = "sending"
	StatusSent      NotificationStatus = "sent"
	StatusFailed    NotificationStatus = "failed"
	StatusCancelled NotificationStatus = "cancelled"
)

// Notification represents a single notification
type Notification struct {
	ID   uint             `json:"id" gorm:"primaryKey"`
	Type NotificationType `json:"type" gorm:"not null"`

	// Recipient — фактический адрес доставки, куда уведомление ушло (chat_id, email,
	// телефон). Для адресации по логину он не приходит извне, а резолвится
	// auth-service на приёме запроса; хранится для аудита и разбора инцидентов.
	Recipient string `json:"recipient" gorm:"not null"`

	// RecipientLogin — логин портала, если уведомление адресовано пользователю системы.
	// ExternalRecipient — адрес получателя вне портала. Заполнено ровно одно из двух
	// (либо ни одного — легаси-вызов через поле recipient или системный алерт).
	RecipientLogin     string             `json:"recipient_login,omitempty" gorm:"index"`
	ExternalRecipient  string             `json:"external_recipient,omitempty"`
	Subject            string             `json:"subject,omitempty"`
	Content            string             `json:"content" gorm:"not null"`
	ContentType        string             `json:"content_type,omitempty" gorm:"default:'text/plain'"`
	AttachmentFilename string             `json:"attachment_filename,omitempty"`
	AttachmentContent  []byte             `json:"attachment_content,omitempty" gorm:"type:bytea"`
	Status             NotificationStatus `json:"status" gorm:"default:pending;index"`
	Attempts           int                `json:"attempts" gorm:"default:0"`
	MaxAttempts        int                `json:"max_attempts" gorm:"default:3"`
	LastError          string             `json:"last_error,omitempty"`
	FailureCode        string             `json:"failure_code,omitempty"` // машинный код отказа для вызывающего сервиса
	BatchID            string             `json:"batch_id,omitempty" gorm:"index"`
	CreatedAt          int64              `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt          int64              `json:"updated_at" gorm:"autoUpdateTime"`
	SentAt             *int64             `json:"sent_at,omitempty"`
}

// NotificationBatch represents a batch of notifications
type NotificationBatch struct {
	ID             string `json:"id" gorm:"primaryKey"`
	TotalCount     int    `json:"total_count"`
	ProcessedCount int    `json:"processed_count" gorm:"default:0"`
	SuccessCount   int    `json:"success_count" gorm:"default:0"`
	FailedCount    int    `json:"failed_count" gorm:"default:0"`
	Status         string `json:"status" gorm:"default:processing"`
	CreatedAt      int64  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt      int64  `json:"updated_at" gorm:"autoUpdateTime"`
}

// BatchNotificationRequest represents a request to send multiple notifications
type BatchNotificationRequest struct {
	Notifications []SingleNotificationRequest `json:"notifications" binding:"required,min=1"`
	BatchID       string                      `json:"batch_id,omitempty"`
}

// SingleNotificationRequest represents a single notification request
type SingleNotificationRequest struct {
	Type NotificationType `json:"type" binding:"required,oneof=email sms push telegram telegram_system"`

	// Login — логин пользователя портала; адрес доставки определяет auth-service.
	// ExternalRecipient — получатель, которого нет в системе (внешний email/телефон/chat_id).
	// Заполнять нужно ровно одно из двух.
	Login              string `json:"login,omitempty"`
	ExternalRecipient  string `json:"external_recipient,omitempty"`
	Subject            string `json:"subject,omitempty"`
	Content            string `json:"content" binding:"required"`
	ContentType        string `json:"content_type,omitempty" binding:"omitempty,oneof=text/plain text/html"`
	AttachmentFilename string `json:"attachment_filename,omitempty"`
	AttachmentContent  string `json:"attachment_content,omitempty"` // base64 encoded
}

// NotificationConfig represents stored notification service configuration
type NotificationConfig struct {
	ID                              uint   `json:"id" gorm:"primaryKey"`
	SMTPHost                        string `json:"smtp_host" gorm:"default:'smtp.gmail.com'"`
	SMTPPort                        string `json:"smtp_port" gorm:"default:'587'"`
	SMTPUsername                    string `json:"smtp_username"`
	SMTPPassword                    string `json:"smtp_password"`
	SMTPFrom                        string `json:"smtp_from"`
	SMTPUseTLS                      bool   `json:"smtp_use_tls" gorm:"default:false"`
	SMTPUseAuth                     bool   `json:"smtp_use_auth" gorm:"default:true"`
	SMTPAuthMethod                  string `json:"smtp_auth_method" gorm:"default:'plain'"`
	TelegramBotToken                string `json:"telegram_bot_token"`        // Токен для обычного бота
	TelegramSystemBotToken          string `json:"telegram_system_bot_token"` // Токен для системного бота
	TelegramEnabled                 bool   `json:"telegram_enabled" gorm:"default:false"`
	TelegramSystemEnabled           bool   `json:"telegram_system_enabled" gorm:"default:false"`
	SystemEmailRecipient            string `json:"system_email_recipient"`                                 // Email для системных уведомлений
	SystemTelegramUsername          string `json:"system_telegram_username"`                               // Telegram Username для системных уведомлений (сохраняется для UI)
	SystemTelegramChatID            string `json:"system_telegram_chat_id"`                                // Telegram Chat ID (используется для отправки)
	SendSystemEmailNotifications    bool   `json:"send_system_email_notifications" gorm:"default:true"`    // Включить отправку системных уведомлений на почту
	SendSystemTelegramNotifications bool   `json:"send_system_telegram_notifications" gorm:"default:true"` // Включить отправку системных уведомлений в Telegram
	DebugMode                       bool   `json:"debug_mode" gorm:"default:false"`                        // Debug режим - все письма на debug email
	DebugEmail                      string `json:"debug_email"`                                            // Email для всех писем в debug режиме
	MaxRetryAttempts                int    `json:"max_retry_attempts" gorm:"default:3"`
	BatchSize                       int    `json:"batch_size" gorm:"default:10"`
	DelayBetweenBatchesMS           int    `json:"delay_between_batches_ms" gorm:"default:1000"`
	DelayBetweenMessagesMS          int    `json:"delay_between_messages_ms" gorm:"default:100"`          // Задержка между email-сообщениями (мс)
	TelegramDelayBetweenMessagesMS  int    `json:"telegram_delay_between_messages_ms" gorm:"default:0"`  // Задержка между telegram-сообщениями (мс); 0 = мгновенно
	CreatedAt                       int64  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt                       int64  `json:"updated_at" gorm:"autoUpdateTime"`
}

// isInternalIP checks if the IP is from internal Docker networks
func isInternalIP(ip string) bool {
	// Parse IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Allow IPv6 localhost
	if parsedIP.IsLoopback() {
		return true
	}

	// Define allowed internal networks
	allowedNetworks := []string{
		"172.16.0.0/12",  // Docker default networks
		"10.0.0.0/8",     // Docker internal networks
		"192.168.0.0/16", // Docker compose networks
		"127.0.0.0/8",    // localhost range
	}

	// Check if IP is in any allowed network
	for _, network := range allowedNetworks {
		_, cidr, err := net.ParseCIDR(network)
		if err != nil {
			continue
		}
		if cidr.Contains(parsedIP) {
			return true
		}
	}

	return false
}

func main() {
	log.Println("========================================")
	log.Println("🚀 Notification Service Starting...")
	log.Println("========================================")

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️  No .env file found, using system environment variables")
	} else {
		log.Println("✅ Environment variables loaded from .env")
	}

	// Initialize database
	log.Println("📦 Connecting to database...")
	db, err := initDB()
	if err != nil {
		log.Fatalf("❌ Failed to connect to database: %v", err)
	}
	log.Println("✅ Database connected successfully")

	// Create service instance
	maxConcurrent := getEnvAsInt("MAX_CONCURRENT_SENDS", 10)
	service := &NotificationService{
		db:             db,
		chatIDCache:    make(map[string]chatIDEntry),
		recipientCache: make(map[string]recipientCacheEntry),
		sendGates: map[string]*channelGate{
			"email":    {},
			"telegram": {},
			"sms":      {},
			"push":     {},
		},
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		workerSem: make(chan struct{}, maxConcurrent),
	}
	service.guard = NewServiceGuard(service.sendSecurityAlert)
	log.Printf("✅ Notification service instance created (max concurrent sends: %d)", maxConcurrent)

	// Initialize router
	router := gin.Default()

	// Set trusted proxies for internal Docker networks
	router.SetTrustedProxies([]string{
		"172.16.0.0/12",  // Docker default networks
		"10.0.0.0/8",     // Docker internal networks
		"192.168.0.0/16", // Docker compose networks
		"127.0.0.1",      // localhost
	})

	// Add internal access middleware (IP whitelist + API key)
	internalAPIKey := os.Getenv("INTERNAL_API_KEY")
	router.Use(func(c *gin.Context) {
		// Allow if valid API key is provided
		if internalAPIKey != "" && c.GetHeader("X-API-Key") == internalAPIKey {
			c.Next()
			return
		}

		// Fallback: allow internal Docker networks
		if isInternalIP(c.ClientIP()) {
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "Доступ запрещён",
		})
	})

	// Setup routes
	service.setupRoutes(router)

	// Get port from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "80"
	}

	log.Println("========================================")
	log.Printf("🌐 Starting notification service on port %s", port)
	log.Println("📧 Ready to process email notifications")
	log.Println("========================================")

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("⏳ Shutting down notification service...")

	// Wait for in-flight goroutines to finish (with timeout)
	wgDone := make(chan struct{})
	go func() {
		service.wg.Wait()
		close(wgDone)
	}()

	select {
	case <-wgDone:
		log.Println("✅ All in-flight notifications completed")
	case <-time.After(25 * time.Second):
		log.Println("⚠️ Timeout waiting for in-flight notifications, proceeding with shutdown")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("❌ Server forced to shutdown: %v", err)
	}
	log.Println("✅ Notification service stopped gracefully")
}

func initDB() (*gorm.DB, error) {
	// Database configuration from environment variables
	host := os.Getenv("DB_HOST")
	if host == "" {
		host = "localhost"
	}

	user := os.Getenv("DB_USER")
	if user == "" {
		user = "postgres"
	}

	password := os.Getenv("DB_PASSWORD")
	if password == "" {
		password = "password"
	}

	dbname := os.Getenv("DB_NAME")
	if dbname == "" {
		dbname = "notifications"
	}

	port := os.Getenv("DB_PORT")
	if port == "" {
		port = "5432"
	}

	sslmode := os.Getenv("DB_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}

	dsn := "host=" + host + " user=" + user + " password=" + password + " dbname=" + dbname + " port=" + port + " sslmode=" + sslmode + " TimeZone=Asia/Tashkent"

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Auto-migrate the schema
	err = db.AutoMigrate(&Notification{}, &NotificationBatch{}, &NotificationConfig{})
	if err != nil {
		return nil, err
	}

	return db, nil
}

// loadServiceAPIKeys собирает карту "api-key -> имя сервиса" из окружения.
//
// Источники:
//   - SERVICE_API_KEYS — per-service ключи в формате "referal:key1,client-service:key2,..."
//   - INTERNAL_API_KEY — общий легаси-ключ (его уже шлёт auth-service / auth-connector)
func loadServiceAPIKeys() map[string]string {
	keys := make(map[string]string)

	if raw := os.Getenv("SERVICE_API_KEYS"); raw != "" {
		for _, pair := range strings.Split(raw, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				log.Printf("⚠️ SERVICE_API_KEYS: пропущена некорректная запись %q (ожидается name:key)", pair)
				continue
			}
			keys[strings.TrimSpace(parts[1])] = strings.TrimSpace(parts[0])
		}
	}

	if legacy := os.Getenv("INTERNAL_API_KEY"); legacy != "" {
		if _, exists := keys[legacy]; !exists {
			keys[legacy] = "internal-shared-key"
		}
	}

	return keys
}

// serviceAuthMiddleware проверяет X-API-Key входящих запросов от других сервисов
// и пропускает их через ServiceGuard (rate-limit + алерты при аномалиях).
// Если ни одного ключа не настроено — аутентификация отключена (с предупреждением в лог),
// чтобы не сломать существующие деплои до раскатки ключей.
func (ns *NotificationService) serviceAuthMiddleware() gin.HandlerFunc {
	keys := loadServiceAPIKeys()
	if len(keys) == 0 {
		log.Printf("⚠️ SERVICE_API_KEYS / INTERNAL_API_KEY не заданы — аутентификация сервисов ОТКЛЮЧЕНА")
		return func(c *gin.Context) { c.Next() }
	}

	log.Printf("🔐 Service authentication enabled (%d key(s) configured)", len(keys))
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			log.Printf("🚫 AUTH REJECT: missing X-API-Key | path=%s ip=%s", c.Request.URL.Path, c.ClientIP())
			ns.guard.RecordInvalidKey(c.ClientIP(), c.Request.URL.Path)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "X-API-Key header required"})
			return
		}
		serviceName, ok := keys[apiKey]
		if !ok {
			log.Printf("🚫 AUTH REJECT: invalid X-API-Key | path=%s ip=%s", c.Request.URL.Path, c.ClientIP())
			ns.guard.RecordInvalidKey(c.ClientIP(), c.Request.URL.Path)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid X-API-Key"})
			return
		}
		if !ns.guard.Allow(serviceName) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded, try again later"})
			return
		}
		c.Set("service_name", serviceName)
		c.Next()
	}
}

func (ns *NotificationService) setupRoutes(router *gin.Engine) {
	// Статические файлы
	router.Static("/static", "./static")

	// Главная страница с интерфейсом настроек
	router.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/static/config.html")
	})

	router.GET("/config", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/static/config.html")
	})

	api := router.Group("/api/v1")

	// Health check — без аутентификации (docker healthcheck, monitoring)
	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Ханипот-эндпоинты: легитимного трафика на эти пути не существует.
	// Любое обращение — бинарный индикатор компрометации источника:
	// лог-маркер GUARD TRIPWIRE ловит guard-watchdog и карантинит контейнер.
	// Без аутентификации (смысл — поймать пробы), ответ — обычный 404.
	tripwire := func(c *gin.Context) {
		ns.guard.Tripwire(c.ClientIP(), c.Request.URL.Path)
		c.String(http.StatusNotFound, "404 page not found")
	}
	for _, p := range []string{"/.env", "/api/v1/internal/keys", "/api/v1/admin/exec", "/api/v1/debug/pprof"} {
		router.Any(p, tripwire)
	}

	// Все остальные эндпоинты требуют валидный X-API-Key сервиса
	protected := api.Group("")
	protected.Use(ns.serviceAuthMiddleware())
	{
		// Batch notifications endpoint
		protected.POST("/notifications/batch", ns.sendBatchNotifications)

		// Single notification endpoint
		protected.POST("/notifications", ns.sendSingleNotification)

		// Get notification status
		protected.GET("/notifications/:id", ns.getNotificationStatus)

		// Get batch status
		protected.GET("/batches/:batch_id", ns.getBatchStatus)

		// Get notifications by batch
		protected.GET("/batches/:batch_id/notifications", ns.getBatchNotifications)

		// Configuration endpoints
		protected.GET("/config", ns.getConfig)
		protected.POST("/config", ns.updateConfig)
	}
}

func (ns *NotificationService) sendBatchNotifications(c *gin.Context) {
	var req BatchNotificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("❌ Failed to parse batch notification request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate batch ID if not provided
	if req.BatchID == "" {
		req.BatchID = generateBatchID()
	}

	serviceName := c.GetString("service_name")
	log.Printf("📦 Received batch notification request: batch_id=%s, count=%d, from_service=%s", req.BatchID, len(req.Notifications), serviceName)

	// Адресацию разбираем до создания записей: битый запрос отвергаем целиком,
	// а не наполовину созданной пачкой
	modes := make([]string, len(req.Notifications))
	values := make([]string, len(req.Notifications))
	loginsByChannel := make(map[string][]string)
	for i := range req.Notifications {
		mode, value, err := resolveRecipientMode(&req.Notifications[i])
		if err != nil {
			log.Printf("❌ Bad recipient in batch %s (#%d, from_service=%s): %v", req.BatchID, i+1, serviceName, err)
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("уведомление #%d: %v", i+1, err)})
			return
		}
		modes[i], values[i] = mode, value
		if mode == recipientModeLogin {
			channel := channelForType(req.Notifications[i].Type)
			loginsByChannel[channel] = append(loginsByChannel[channel], value)
		}
	}

	// Один резолв на канал вместо запроса к auth-service на каждое уведомление пачки
	resolvedByChannel := make(map[string]map[string]recipientResolution, len(loginsByChannel))
	for channel, logins := range loginsByChannel {
		resolved, rerr := ns.resolveRecipients(serviceName, channel, logins)
		if rerr != nil {
			log.Printf("❌ Batch recipient resolve failed (batch_id=%s, channel=%s, count=%d): %v", req.BatchID, channel, len(logins), rerr)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":        "не удалось определить получателей: auth-service недоступен",
				"failure_code": failureAuthUnavailable,
			})
			return
		}
		resolvedByChannel[channel] = resolved
	}

	// Create batch record
	batch := NotificationBatch{
		ID:         req.BatchID,
		TotalCount: len(req.Notifications),
		Status:     "processing",
	}

	if err := ns.db.Create(&batch).Error; err != nil {
		log.Printf("❌ Failed to create batch %s: %v", req.BatchID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать пакет"})
		return
	}

	// Create notifications
	unresolved := make([]gin.H, 0)
	notifications := make([]Notification, len(req.Notifications))
	for i, notifReq := range req.Notifications {
		notification := Notification{
			Type:        notifReq.Type,
			Subject:     notifReq.Subject,
			Content:     notifReq.Content,
			ContentType: notifReq.ContentType,
			BatchID:     req.BatchID,
		}

		var resolved recipientResolution
		if modes[i] == recipientModeLogin {
			channel := channelForType(notifReq.Type)
			resolved = resolvedByChannel[channel][values[i]]

			if !resolved.Found {
				// Нерезолвнутого получателя пачки создаём сразу failed: processBatch
				// берёт только pending, так что отправки не будет, а причина и
				// статистика пачки остаются видны вызывающему сервису
				notification.Status = StatusFailed
				notification.FailureCode = resolved.Reason
				notification.LastError = fmt.Sprintf("получатель «%s» недоступен по каналу %s: %s", values[i], channel, resolved.Reason)
				unresolved = append(unresolved, gin.H{"login": values[i], "failure_code": resolved.Reason})
			}
		}

		applyRecipient(&notification, modes[i], values[i], resolved)
		notifications[i] = notification
	}

	if len(unresolved) > 0 {
		log.Printf("⚠️ Batch %s: %d из %d получателей не разрешены", req.BatchID, len(unresolved), len(notifications))
	}

	if err := ns.db.Create(&notifications).Error; err != nil {
		log.Printf("❌ Failed to create notifications for batch %s: %v", req.BatchID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать уведомления"})
		return
	}

	log.Printf("✅ Batch %s created with %d notifications, starting processing...", req.BatchID, len(notifications))

	// Start processing in background (tracked by WaitGroup)
	ns.wg.Add(1)
	go func() {
		defer ns.wg.Done()
		ns.workerSem <- struct{}{} // Acquire semaphore slot
		defer func() { <-ns.workerSem }()
		ns.processBatch(req.BatchID)
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"batch_id":   req.BatchID,
		"message":    "Пакет создан, обработка начата",
		"unresolved": unresolved,
	})
}

func (ns *NotificationService) sendSingleNotification(c *gin.Context) {
	var req SingleNotificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("❌ Failed to parse notification request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	serviceName := c.GetString("service_name")

	mode, value, err := resolveRecipientMode(&req)
	if err != nil {
		log.Printf("❌ Bad recipient (from_service=%s, type=%s): %v", serviceName, req.Type, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Логин в логах оставляем как есть — это идентификатор, а не контакт;
	// маскируем только сырые адреса доставки
	logged := value
	if mode != recipientModeLogin {
		logged = maskRecipient(value)
	}
	log.Printf("📧 Received notification: type=%s, mode=%s, recipient=%s, subject=%s, from_service=%s",
		req.Type, mode, logged, req.Subject, serviceName)

	// Create notification
	notification := Notification{
		Type:        req.Type,
		Subject:     req.Subject,
		Content:     req.Content,
		ContentType: req.ContentType,
	}

	var resolved recipientResolution
	if mode == recipientModeLogin {
		channel := channelForType(req.Type)
		results, rerr := ns.resolveRecipients(serviceName, channel, []string{value})
		if rerr != nil {
			// auth-service недоступен — это временный сбой, а не плохой запрос:
			// отдаём 503, чтобы вызывающий повторил, а не хоронил уведомление в failed
			log.Printf("❌ Recipient resolve failed (login=%s, channel=%s): %v", value, channel, rerr)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":        "не удалось определить получателя: auth-service недоступен",
				"failure_code": failureAuthUnavailable,
			})
			return
		}

		resolved = results[value]
		if !resolved.Found {
			log.Printf("⚠️ Recipient unresolved (login=%s, channel=%s): %s", value, channel, resolved.Reason)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":        fmt.Sprintf("получатель «%s» недоступен по каналу %s", value, channel),
				"failure_code": resolved.Reason,
			})
			return
		}
	}

	applyRecipient(&notification, mode, value, resolved)

	// Handle attachment if present
	if req.AttachmentFilename != "" && req.AttachmentContent != "" {
		// Decode base64 attachment
		attachmentBytes, err := base64.StdEncoding.DecodeString(req.AttachmentContent)
		if err != nil {
			log.Printf("⚠️ Failed to decode attachment: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверная кодировка вложения"})
			return
		}
		notification.AttachmentFilename = req.AttachmentFilename
		notification.AttachmentContent = attachmentBytes
		log.Printf("📎 Attachment received: %s (%d bytes)", req.AttachmentFilename, len(attachmentBytes))
	}

	if err := ns.db.Create(&notification).Error; err != nil {
		log.Printf("❌ Failed to create notification: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать уведомление"})
		return
	}

	log.Printf("✅ Notification #%d created, starting processing...", notification.ID)

	// Process immediately (tracked by WaitGroup)
	ns.wg.Add(1)
	go func() {
		defer ns.wg.Done()
		ns.workerSem <- struct{}{} // Acquire semaphore slot
		defer func() { <-ns.workerSem }()
		ns.processNotification(&notification)
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"id":      notification.ID,
		"message": "Уведомление создано, обработка начата",
	})
}

func (ns *NotificationService) getNotificationStatus(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID уведомления"})
		return
	}

	var notification Notification
	if err := ns.db.First(&notification, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Уведомление не найдено"})
		return
	}

	c.JSON(http.StatusOK, notification)
}

func (ns *NotificationService) getBatchStatus(c *gin.Context) {
	batchID := c.Param("batch_id")

	var batch NotificationBatch
	if err := ns.db.First(&batch, "id = ?", batchID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пакет не найден"})
		return
	}

	c.JSON(http.StatusOK, batch)
}

func (ns *NotificationService) getBatchNotifications(c *gin.Context) {
	batchID := c.Param("batch_id")

	var notifications []Notification
	if err := ns.db.Where("batch_id = ?", batchID).Find(&notifications).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить уведомления"})
		return
	}

	c.JSON(http.StatusOK, notifications)
}

func (ns *NotificationService) getConfig(c *gin.Context) {
	var dbConfig NotificationConfig

	// Try to get config from database first
	result := ns.db.First(&dbConfig)
	if result.Error != nil {
		// If no config found in DB, create default config from environment
		dbConfig = NotificationConfig{
			SMTPHost:                        getEnvOrDefault("SMTP_HOST", "smtp.gmail.com"),
			SMTPPort:                        getEnvOrDefault("SMTP_PORT", "587"),
			SMTPUsername:                    getEnvOrDefault("SMTP_USERNAME", ""),
			SMTPPassword:                    getEnvOrDefault("SMTP_PASSWORD", ""),
			SMTPFrom:                        getEnvOrDefault("SMTP_FROM", ""),
			SMTPUseTLS:                      getEnvAsBool("SMTP_USE_TLS", true),
			SMTPUseAuth:                     getEnvAsBool("SMTP_USE_AUTH", true),
			SMTPAuthMethod:                  getEnvOrDefault("SMTP_AUTH_METHOD", "plain"),
			TelegramBotToken:                getEnvOrDefault("TELEGRAM_BOT_TOKEN", ""),
			TelegramSystemBotToken:          getEnvOrDefault("TELEGRAM_SYSTEM_BOT_TOKEN", ""),
			TelegramEnabled:                 getEnvAsBool("TELEGRAM_ENABLED", false),
			TelegramSystemEnabled:           getEnvAsBool("TELEGRAM_SYSTEM_ENABLED", false),
			SystemEmailRecipient:            getEnvOrDefault("SYSTEM_EMAIL_RECIPIENT", ""),
			SystemTelegramUsername:          getEnvOrDefault("SYSTEM_TELEGRAM_USERNAME", ""),
			SendSystemEmailNotifications:    getEnvAsBool("SEND_SYSTEM_EMAIL_NOTIFICATIONS", true),
			SendSystemTelegramNotifications: getEnvAsBool("SEND_SYSTEM_TELEGRAM_NOTIFICATIONS", true),
			MaxRetryAttempts:                getEnvAsInt("MAX_RETRY_ATTEMPTS", 3),
			BatchSize:                       getEnvAsInt("BATCH_SIZE", 10),
			DelayBetweenBatchesMS:           getEnvAsInt("DELAY_BETWEEN_BATCHES_MS", 1000),
			DelayBetweenMessagesMS:          getEnvAsInt("DELAY_BETWEEN_MESSAGES_MS", 100),
			TelegramDelayBetweenMessagesMS:  getEnvAsInt("TELEGRAM_DELAY_BETWEEN_MESSAGES_MS", 0),
		}
		// Save default config to DB
		ns.db.Create(&dbConfig)
	}

	config := map[string]interface{}{
		"smtp_host":                          dbConfig.SMTPHost,
		"smtp_port":                          dbConfig.SMTPPort,
		"smtp_username":                      dbConfig.SMTPUsername,
		"smtp_from":                          dbConfig.SMTPFrom,
		"smtp_use_tls":                       dbConfig.SMTPUseTLS,
		"smtp_use_auth":                      dbConfig.SMTPUseAuth,
		"smtp_auth_method":                   dbConfig.SMTPAuthMethod,
		"smtp_password_set":                  dbConfig.SMTPPassword != "",
		"telegram_bot_token_set":             dbConfig.TelegramBotToken != "",
		"telegram_system_bot_token_set":      dbConfig.TelegramSystemBotToken != "",
		"telegram_enabled":                   dbConfig.TelegramEnabled,
		"telegram_system_enabled":            dbConfig.TelegramSystemEnabled,
		"system_email_recipient":             dbConfig.SystemEmailRecipient,
		"system_telegram_username":           dbConfig.SystemTelegramUsername,
		"send_system_email_notifications":    dbConfig.SendSystemEmailNotifications,
		"send_system_telegram_notifications": dbConfig.SendSystemTelegramNotifications,
		"debug_mode":                         dbConfig.DebugMode,
		"debug_email":                        dbConfig.DebugEmail,
		"max_retry_attempts":                 dbConfig.MaxRetryAttempts,
		"batch_size":                         dbConfig.BatchSize,
		"delay_between_batches_ms":           dbConfig.DelayBetweenBatchesMS,
		"delay_between_messages_ms":          dbConfig.DelayBetweenMessagesMS,
		"telegram_delay_between_messages_ms": dbConfig.TelegramDelayBetweenMessagesMS,
	}
	c.JSON(http.StatusOK, config)
}

func (ns *NotificationService) updateConfig(c *gin.Context) {
	var config map[string]interface{}
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing config or create new one
	var dbConfig NotificationConfig
	result := ns.db.First(&dbConfig)
	if result.Error != nil {
		dbConfig = NotificationConfig{}
	}

	updated := []string{}

	// --- String fields (table-driven) ---
	stringFields := map[string]*string{
		"smtp_host":                 &dbConfig.SMTPHost,
		"smtp_port":                 &dbConfig.SMTPPort,
		"smtp_username":             &dbConfig.SMTPUsername,
		"smtp_password":             &dbConfig.SMTPPassword,
		"smtp_from":                 &dbConfig.SMTPFrom,
		"smtp_auth_method":          &dbConfig.SMTPAuthMethod,
		"telegram_bot_token":        &dbConfig.TelegramBotToken,
		"telegram_system_bot_token": &dbConfig.TelegramSystemBotToken,
		"system_email_recipient":    &dbConfig.SystemEmailRecipient,
		"debug_email":               &dbConfig.DebugEmail,
	}
	for key, ptr := range stringFields {
		if val, ok := config[key].(string); ok {
			*ptr = val
			updated = append(updated, strings.ToUpper(key))
		}
	}

	// --- Bool fields (explicit exists-check for GORM zero-value safety) ---
	boolFields := map[string]*bool{
		"smtp_use_tls":                       &dbConfig.SMTPUseTLS,
		"smtp_use_auth":                      &dbConfig.SMTPUseAuth,
		"telegram_enabled":                   &dbConfig.TelegramEnabled,
		"telegram_system_enabled":            &dbConfig.TelegramSystemEnabled,
		"send_system_email_notifications":    &dbConfig.SendSystemEmailNotifications,
		"send_system_telegram_notifications": &dbConfig.SendSystemTelegramNotifications,
		"debug_mode":                         &dbConfig.DebugMode,
	}
	for key, ptr := range boolFields {
		if val, exists := config[key]; exists {
			if boolVal, ok := val.(bool); ok {
				*ptr = boolVal
				updated = append(updated, strings.ToUpper(key))
			} else {
				log.Printf("WARNING: %s value is not boolean: %v (type: %T)", key, val, val)
			}
		}
	}

	// --- Int fields (JSON sends numbers as float64) ---
	intFields := map[string]*int{
		"max_retry_attempts":        &dbConfig.MaxRetryAttempts,
		"batch_size":                &dbConfig.BatchSize,
		"delay_between_batches_ms":           &dbConfig.DelayBetweenBatchesMS,
		"delay_between_messages_ms":          &dbConfig.DelayBetweenMessagesMS,
		"telegram_delay_between_messages_ms": &dbConfig.TelegramDelayBetweenMessagesMS,
	}
	for key, ptr := range intFields {
		if val, ok := config[key].(float64); ok {
			*ptr = int(val)
			updated = append(updated, strings.ToUpper(key))
		}
	}

	// --- Special: explicit system chat ID (e.g. group chats that cannot be resolved by username) ---
	if systemChatID, ok := config["system_telegram_chat_id"].(string); ok {
		dbConfig.SystemTelegramChatID = systemChatID
		updated = append(updated, "SYSTEM_TELEGRAM_CHAT_ID")
	}

	// --- Special: Telegram username → Chat ID resolution (via auth-service linked accounts) ---
	if systemTelegramUsername, ok := config["system_telegram_username"].(string); ok {
		usernameChanged := dbConfig.SystemTelegramUsername != systemTelegramUsername
		dbConfig.SystemTelegramUsername = systemTelegramUsername
		updated = append(updated, "SYSTEM_TELEGRAM_USERNAME")

		if usernameChanged && systemTelegramUsername != "" {
			log.Printf("📱 Telegram username changed to %s, attempting to resolve Chat ID via auth-service...", systemTelegramUsername)
			chatID, err := ns.resolveTelegramChatID(systemTelegramUsername)
			if err != nil {
				log.Printf("⚠️ Failed to resolve Chat ID for %s: %v", systemTelegramUsername, err)
				log.Printf("💡 Пользователь должен привязать Telegram в личном кабинете портала")
			} else {
				dbConfig.SystemTelegramChatID = chatID
				updated = append(updated, "SYSTEM_TELEGRAM_CHAT_ID")
				log.Printf("✅ Resolved Chat ID for %s: %s", systemTelegramUsername, chatID)
			}
		}
	}

	// Save config to database
	var saveErr error
	if dbConfig.ID == 0 {
		saveErr = ns.db.Create(&dbConfig).Error
	} else {
		saveErr = ns.db.Save(&dbConfig).Error
	}

	if saveErr != nil {
		log.Printf("Failed to save configuration: %v", saveErr)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Не удалось сохранить конфигурацию: " + saveErr.Error(),
		})
		return
	}

	// Invalidate cache so new config takes effect immediately
	ns.invalidateConfigCache()

	log.Printf("Configuration updated successfully. Updated fields: %v", updated)

	c.JSON(http.StatusOK, gin.H{
		"message":        "Конфигурация успешно обновлена",
		"updated_fields": updated,
	})
}

// resolveTelegramChatID resolves a Telegram username to a chat ID through
// auth-service (users who linked Telegram in the portal profile).
// Direct getUpdates calls are no longer possible: updates are consumed by
// the notification-bot long-polling loop.
func (ns *NotificationService) resolveTelegramChatID(username string) (string, error) {
	key := strings.ToLower(strings.TrimPrefix(username, "@"))

	// Cache hit (10 min TTL) — избегаем HTTP к auth-service на каждой отправке
	ns.chatIDMu.RLock()
	if e, ok := ns.chatIDCache[key]; ok && time.Since(e.at) < 10*time.Minute {
		ns.chatIDMu.RUnlock()
		return e.chatID, nil
	}
	ns.chatIDMu.RUnlock()

	authServiceURL := os.Getenv("AUTH_SERVICE_URL")
	if authServiceURL == "" {
		authServiceURL = "http://auth-service:80"
	}

	url := fmt.Sprintf("%s/api/telegram/chat-id?username=%s", authServiceURL, key)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create auth-service request: %v", err)
	}
	if apiKey := os.Getenv("INTERNAL_API_KEY"); apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	resp, err := ns.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth-service request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth-service returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		ChatID  int64  `json:"chat_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse auth-service response: %v", err)
	}

	if !result.Success {
		return "", fmt.Errorf("%s (пользователь должен привязать Telegram в личном кабинете портала)", result.Message)
	}

	chatID := strconv.FormatInt(result.ChatID, 10)
	ns.chatIDMu.Lock()
	ns.chatIDCache[key] = chatIDEntry{chatID: chatID, at: time.Now()}
	ns.chatIDMu.Unlock()
	return chatID, nil
}

// These functions are now defined as variables in processors.go and initialized there

func getEnvAsInt(name string, defaultValue int) int {
	valueStr := os.Getenv(name)
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}

func getEnvOrDefault(name string, defaultValue string) string {
	value := os.Getenv(name)
	if value == "" {
		return defaultValue
	}
	return value
}

func getEnvAsBool(name string, defaultValue bool) bool {
	valueStr := os.Getenv(name)
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}

// getConfigFromDB retrieves configuration from database with caching (60s TTL)
func (ns *NotificationService) getConfigFromDB() NotificationConfig {
	ns.configCacheMu.RLock()
	if ns.configCache != nil && time.Since(ns.lastConfigFetch) < 60*time.Second {
		cached := *ns.configCache
		ns.configCacheMu.RUnlock()
		return cached
	}
	ns.configCacheMu.RUnlock()

	var dbConfig NotificationConfig
	result := ns.db.First(&dbConfig)
	if result.Error != nil {
		// Return default config if not found in database
		return NotificationConfig{
			SMTPHost:               getEnvOrDefault("SMTP_HOST", "smtp.gmail.com"),
			SMTPPort:               getEnvOrDefault("SMTP_PORT", "587"),
			SMTPUsername:           getEnvOrDefault("SMTP_USERNAME", ""),
			SMTPPassword:           getEnvOrDefault("SMTP_PASSWORD", ""),
			SMTPFrom:               getEnvOrDefault("SMTP_FROM", ""),
			SMTPUseTLS:             getEnvAsBool("SMTP_USE_TLS", true),
			SMTPUseAuth:            getEnvAsBool("SMTP_USE_AUTH", true),
			SMTPAuthMethod:         getEnvOrDefault("SMTP_AUTH_METHOD", "plain"),
			TelegramBotToken:       getEnvOrDefault("TELEGRAM_BOT_TOKEN", ""),
			TelegramSystemBotToken: getEnvOrDefault("TELEGRAM_SYSTEM_BOT_TOKEN", ""),
			TelegramEnabled:        getEnvAsBool("TELEGRAM_ENABLED", false),
			TelegramSystemEnabled:  getEnvAsBool("TELEGRAM_SYSTEM_ENABLED", false),
			MaxRetryAttempts:       getEnvAsInt("MAX_RETRY_ATTEMPTS", 3),
			BatchSize:              getEnvAsInt("BATCH_SIZE", 10),
			DelayBetweenBatchesMS:  getEnvAsInt("DELAY_BETWEEN_BATCHES_MS", 1000),
			DelayBetweenMessagesMS:         getEnvAsInt("DELAY_BETWEEN_MESSAGES_MS", 100),
			TelegramDelayBetweenMessagesMS: getEnvAsInt("TELEGRAM_DELAY_BETWEEN_MESSAGES_MS", 0),
		}
	}

	ns.configCacheMu.Lock()
	ns.configCache = &dbConfig
	ns.lastConfigFetch = time.Now()
	ns.configCacheMu.Unlock()

	return dbConfig
}

// invalidateConfigCache forces the next getConfigFromDB call to fetch from DB
func (ns *NotificationService) invalidateConfigCache() {
	ns.configCacheMu.Lock()
	ns.configCache = nil
	ns.configCacheMu.Unlock()
}
