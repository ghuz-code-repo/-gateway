package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type NotificationService struct {
	db *gorm.DB
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
	ID                  uint                `json:"id" gorm:"primaryKey"`
	Type                NotificationType    `json:"type" gorm:"not null"`
	Recipient           string              `json:"recipient" gorm:"not null"`
	Subject             string              `json:"subject,omitempty"`
	Content             string              `json:"content" gorm:"not null"`
	AttachmentFilename  string              `json:"attachment_filename,omitempty"`
	AttachmentContent   []byte              `json:"attachment_content,omitempty" gorm:"type:bytea"`
	Status              NotificationStatus  `json:"status" gorm:"default:pending"`
	Attempts            int                 `json:"attempts" gorm:"default:0"`
	MaxAttempts         int                 `json:"max_attempts" gorm:"default:3"`
	LastError           string              `json:"last_error,omitempty"`
	BatchID             string              `json:"batch_id,omitempty"`
	CreatedAt           int64               `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt           int64               `json:"updated_at" gorm:"autoUpdateTime"`
	SentAt              *int64              `json:"sent_at,omitempty"`
}

// NotificationBatch represents a batch of notifications
type NotificationBatch struct {
	ID              string `json:"id" gorm:"primaryKey"`
	TotalCount      int    `json:"total_count"`
	ProcessedCount  int    `json:"processed_count" gorm:"default:0"`
	SuccessCount    int    `json:"success_count" gorm:"default:0"`
	FailedCount     int    `json:"failed_count" gorm:"default:0"`
	Status          string `json:"status" gorm:"default:processing"`
	CreatedAt       int64  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt       int64  `json:"updated_at" gorm:"autoUpdateTime"`
}

// BatchNotificationRequest represents a request to send multiple notifications
type BatchNotificationRequest struct {
	Notifications []SingleNotificationRequest `json:"notifications" binding:"required,min=1"`
	BatchID       string                      `json:"batch_id,omitempty"`
}

// SingleNotificationRequest represents a single notification request
type SingleNotificationRequest struct {
	Type               NotificationType `json:"type" binding:"required,oneof=email sms push telegram telegram_system"`
	Recipient          string           `json:"recipient" binding:"required"`
	Subject            string           `json:"subject,omitempty"`
	Content            string           `json:"content" binding:"required"`
	AttachmentFilename string           `json:"attachment_filename,omitempty"`
	AttachmentContent  string           `json:"attachment_content,omitempty"` // base64 encoded
}

// NotificationConfig represents stored notification service configuration
type NotificationConfig struct {
	ID                          uint   `json:"id" gorm:"primaryKey"`
	SMTPHost                    string `json:"smtp_host" gorm:"default:'smtp.gmail.com'"`
	SMTPPort                    string `json:"smtp_port" gorm:"default:'587'"`
	SMTPUsername                string `json:"smtp_username"`
	SMTPPassword                string `json:"smtp_password"`
	SMTPFrom                    string `json:"smtp_from"`
	SMTPUseTLS                  bool   `json:"smtp_use_tls" gorm:"default:true"`
	SMTPUseAuth                 bool   `json:"smtp_use_auth" gorm:"default:true"`
	SMTPAuthMethod              string `json:"smtp_auth_method" gorm:"default:'plain'"`
	TelegramBotToken            string `json:"telegram_bot_token"`              // Токен для обычного бота
	TelegramSystemBotToken      string `json:"telegram_system_bot_token"`       // Токен для системного бота
	TelegramEnabled             bool   `json:"telegram_enabled" gorm:"default:false"`
	TelegramSystemEnabled       bool   `json:"telegram_system_enabled" gorm:"default:false"`
	SystemEmailRecipient        string `json:"system_email_recipient"`          // Email для системных уведомлений
	SystemTelegramUsername      string `json:"system_telegram_username"`        // Telegram Username для системных уведомлений (сохраняется для UI)
	SystemTelegramChatID        string `json:"system_telegram_chat_id"`         // Telegram Chat ID (используется для отправки)
	SendSystemEmailNotifications     bool   `json:"send_system_email_notifications" gorm:"default:true"`      // Включить отправку системных уведомлений на почту
	SendSystemTelegramNotifications  bool   `json:"send_system_telegram_notifications" gorm:"default:true"`   // Включить отправку системных уведомлений в Telegram
	DebugMode                   bool   `json:"debug_mode" gorm:"default:false"`                          // Debug режим - все письма на debug email
	DebugEmail                  string `json:"debug_email"`                                               // Email для всех писем в debug режиме
	MaxRetryAttempts            int    `json:"max_retry_attempts" gorm:"default:3"`
	BatchSize                   int    `json:"batch_size" gorm:"default:10"`
	DelayBetweenBatchesMS       int    `json:"delay_between_batches_ms" gorm:"default:1000"`
	CreatedAt                   int64  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt                   int64  `json:"updated_at" gorm:"autoUpdateTime"`
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
	service := &NotificationService{db: db}
	log.Println("✅ Notification service instance created")

	// Initialize router
	router := gin.Default()

	// Set trusted proxies for internal Docker networks
	router.SetTrustedProxies([]string{
		"172.16.0.0/12",  // Docker default networks
		"10.0.0.0/8",     // Docker internal networks
		"192.168.0.0/16", // Docker compose networks
		"127.0.0.1",      // localhost
	})

	// Add IP whitelist middleware
	router.Use(func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		// Allow only internal Docker networks
		allowed := isInternalIP(clientIP)
		
		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Access denied",
			})
			return
		}
		
		c.Next()
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
	
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("❌ Failed to start server: %v", err)
	}
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
	{
		// Batch notifications endpoint
		api.POST("/notifications/batch", ns.sendBatchNotifications)
		
		// Single notification endpoint
		api.POST("/notifications", ns.sendSingleNotification)
		
		// Get notification status
		api.GET("/notifications/:id", ns.getNotificationStatus)
		
		// Get batch status
		api.GET("/batches/:batch_id", ns.getBatchStatus)
		
		// Get notifications by batch
		api.GET("/batches/:batch_id/notifications", ns.getBatchNotifications)
		
		// Configuration endpoints
		api.GET("/config", ns.getConfig)
		api.POST("/config", ns.updateConfig)
		
		// Health check
		api.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
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

	log.Printf("📦 Received batch notification request: batch_id=%s, count=%d", req.BatchID, len(req.Notifications))

	// Create batch record
	batch := NotificationBatch{
		ID:          req.BatchID,
		TotalCount:  len(req.Notifications),
		Status:      "processing",
	}

	if err := ns.db.Create(&batch).Error; err != nil {
		log.Printf("❌ Failed to create batch %s: %v", req.BatchID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create batch"})
		return
	}

	// Create notifications
	notifications := make([]Notification, len(req.Notifications))
	for i, notifReq := range req.Notifications {
		notifications[i] = Notification{
			Type:      notifReq.Type,
			Recipient: notifReq.Recipient,
			Subject:   notifReq.Subject,
			Content:   notifReq.Content,
			BatchID:   req.BatchID,
		}
	}

	if err := ns.db.Create(&notifications).Error; err != nil {
		log.Printf("❌ Failed to create notifications for batch %s: %v", req.BatchID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create notifications"})
		return
	}

	log.Printf("✅ Batch %s created with %d notifications, starting processing...", req.BatchID, len(notifications))

	// Start processing in background
	go ns.processBatch(req.BatchID)

	c.JSON(http.StatusAccepted, gin.H{
		"batch_id": req.BatchID,
		"message":  "Batch created and processing started",
	})
}

func (ns *NotificationService) sendSingleNotification(c *gin.Context) {
	var req SingleNotificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("❌ Failed to parse notification request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("📧 Received notification: type=%s, recipient=%s, subject=%s", req.Type, req.Recipient, req.Subject)

	// Create notification
	notification := Notification{
		Type:      req.Type,
		Recipient: req.Recipient,
		Subject:   req.Subject,
		Content:   req.Content,
	}

	// Handle attachment if present
	if req.AttachmentFilename != "" && req.AttachmentContent != "" {
		// Decode base64 attachment
		attachmentBytes, err := base64.StdEncoding.DecodeString(req.AttachmentContent)
		if err != nil {
			log.Printf("⚠️ Failed to decode attachment: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid attachment encoding"})
			return
		}
		notification.AttachmentFilename = req.AttachmentFilename
		notification.AttachmentContent = attachmentBytes
		log.Printf("📎 Attachment received: %s (%d bytes)", req.AttachmentFilename, len(attachmentBytes))
	}

	if err := ns.db.Create(&notification).Error; err != nil {
		log.Printf("❌ Failed to create notification: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create notification"})
		return
	}

	log.Printf("✅ Notification #%d created, starting processing...", notification.ID)

	// Process immediately
	go ns.processNotification(&notification)

	c.JSON(http.StatusAccepted, gin.H{
		"id":      notification.ID,
		"message": "Notification created and processing started",
	})
}

func (ns *NotificationService) getNotificationStatus(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification ID"})
		return
	}

	var notification Notification
	if err := ns.db.First(&notification, uint(id)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Notification not found"})
		return
	}

	c.JSON(http.StatusOK, notification)
}

func (ns *NotificationService) getBatchStatus(c *gin.Context) {
	batchID := c.Param("batch_id")

	var batch NotificationBatch
	if err := ns.db.First(&batch, "id = ?", batchID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Batch not found"})
		return
	}

	c.JSON(http.StatusOK, batch)
}

func (ns *NotificationService) getBatchNotifications(c *gin.Context) {
	batchID := c.Param("batch_id")

	var notifications []Notification
	if err := ns.db.Where("batch_id = ?", batchID).Find(&notifications).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get notifications"})
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
		}
		// Save default config to DB
		ns.db.Create(&dbConfig)
	}

	config := map[string]interface{}{
		"smtp_host":                        dbConfig.SMTPHost,
		"smtp_port":                        dbConfig.SMTPPort,
		"smtp_username":                    dbConfig.SMTPUsername,
		"smtp_from":                        dbConfig.SMTPFrom,
		"smtp_use_tls":                     dbConfig.SMTPUseTLS,
		"smtp_use_auth":                    dbConfig.SMTPUseAuth,
		"smtp_auth_method":                 dbConfig.SMTPAuthMethod,
		"telegram_bot_token":               dbConfig.TelegramBotToken,
		"telegram_system_bot_token":        dbConfig.TelegramSystemBotToken,
		"telegram_enabled":                 dbConfig.TelegramEnabled,
		"telegram_system_enabled":          dbConfig.TelegramSystemEnabled,
		"system_email_recipient":           dbConfig.SystemEmailRecipient,
		"system_telegram_username":         dbConfig.SystemTelegramUsername,
		"send_system_email_notifications":  dbConfig.SendSystemEmailNotifications,
		"send_system_telegram_notifications": dbConfig.SendSystemTelegramNotifications,
		"debug_mode":                       dbConfig.DebugMode,
		"debug_email":                      dbConfig.DebugEmail,
		"max_retry_attempts":               dbConfig.MaxRetryAttempts,
		"batch_size":                       dbConfig.BatchSize,
		"delay_between_batches_ms":         dbConfig.DelayBetweenBatchesMS,
	}
	c.JSON(http.StatusOK, config)
}

func (ns *NotificationService) updateConfig(c *gin.Context) {
	var config map[string]interface{}
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Debug: log received config
	log.Printf("DEBUG: Received config data: %+v", config)

	// Get existing config or create new one
	var dbConfig NotificationConfig
	result := ns.db.First(&dbConfig)
	if result.Error != nil {
		// Create new config with defaults
		dbConfig = NotificationConfig{}
	}

	// Update config fields from the received data
	updated := []string{}
	
	if smtpHost, ok := config["smtp_host"].(string); ok {
		dbConfig.SMTPHost = smtpHost
		updated = append(updated, "SMTP_HOST")
	}
	
	if smtpPort, ok := config["smtp_port"].(string); ok {
		dbConfig.SMTPPort = smtpPort
		updated = append(updated, "SMTP_PORT")
	}
	
	if smtpUsername, ok := config["smtp_username"].(string); ok {
		dbConfig.SMTPUsername = smtpUsername
		updated = append(updated, "SMTP_USERNAME")
	}
	
	if smtpPassword, ok := config["smtp_password"].(string); ok {
		dbConfig.SMTPPassword = smtpPassword
		updated = append(updated, "SMTP_PASSWORD")
	}
	
	if smtpFrom, ok := config["smtp_from"].(string); ok {
		dbConfig.SMTPFrom = smtpFrom
		updated = append(updated, "SMTP_FROM")
	}
	
	if smtpUseTLS, ok := config["smtp_use_tls"].(bool); ok {
		dbConfig.SMTPUseTLS = smtpUseTLS
		updated = append(updated, "SMTP_USE_TLS")
	}
	
	if smtpUseAuth, ok := config["smtp_use_auth"].(bool); ok {
		dbConfig.SMTPUseAuth = smtpUseAuth
		updated = append(updated, "SMTP_USE_AUTH")
	}
	
	if smtpAuthMethod, ok := config["smtp_auth_method"].(string); ok {
		dbConfig.SMTPAuthMethod = smtpAuthMethod
		updated = append(updated, "SMTP_AUTH_METHOD")
	}
	
	if telegramBotToken, ok := config["telegram_bot_token"].(string); ok {
		dbConfig.TelegramBotToken = telegramBotToken
		updated = append(updated, "TELEGRAM_BOT_TOKEN")
	}
	
	if telegramSystemBotToken, ok := config["telegram_system_bot_token"].(string); ok {
		dbConfig.TelegramSystemBotToken = telegramSystemBotToken
		updated = append(updated, "TELEGRAM_SYSTEM_BOT_TOKEN")
	}
	
	if telegramEnabled, ok := config["telegram_enabled"].(bool); ok {
		dbConfig.TelegramEnabled = telegramEnabled
		updated = append(updated, "TELEGRAM_ENABLED")
	}
	
	if telegramSystemEnabled, ok := config["telegram_system_enabled"].(bool); ok {
		dbConfig.TelegramSystemEnabled = telegramSystemEnabled
		updated = append(updated, "TELEGRAM_SYSTEM_ENABLED")
	}
	
	if systemEmailRecipient, ok := config["system_email_recipient"].(string); ok {
		dbConfig.SystemEmailRecipient = systemEmailRecipient
		updated = append(updated, "SYSTEM_EMAIL_RECIPIENT")
	}
	
	if systemTelegramUsername, ok := config["system_telegram_username"].(string); ok {
		// Check if username changed
		usernameChanged := dbConfig.SystemTelegramUsername != systemTelegramUsername
		dbConfig.SystemTelegramUsername = systemTelegramUsername
		updated = append(updated, "SYSTEM_TELEGRAM_USERNAME")
		
		// If username changed and not empty, try to resolve Chat ID
		if usernameChanged && systemTelegramUsername != "" && dbConfig.TelegramSystemBotToken != "" {
			log.Printf("📱 Telegram username changed to %s, attempting to resolve Chat ID...", systemTelegramUsername)
			chatID, err := ns.resolveTelegramChatID(dbConfig.TelegramSystemBotToken, systemTelegramUsername)
			if err != nil {
				log.Printf("⚠️ Failed to resolve Chat ID for %s: %v", systemTelegramUsername, err)
				log.Printf("💡 User must send /start to the bot first")
			} else {
				dbConfig.SystemTelegramChatID = chatID
				updated = append(updated, "SYSTEM_TELEGRAM_CHAT_ID")
				log.Printf("✅ Resolved Chat ID for %s: %s", systemTelegramUsername, chatID)
			}
		}
	}
	
	// Handle system notification booleans with explicit key checking
	if val, exists := config["send_system_email_notifications"]; exists {
		if sendSystemEmailNotifications, ok := val.(bool); ok {
			dbConfig.SendSystemEmailNotifications = sendSystemEmailNotifications
			updated = append(updated, "SEND_SYSTEM_EMAIL_NOTIFICATIONS")
			log.Printf("DEBUG: Updated SendSystemEmailNotifications to %v", sendSystemEmailNotifications)
		} else {
			log.Printf("WARNING: send_system_email_notifications value is not boolean: %v (type: %T)", val, val)
		}
	} else {
		log.Printf("DEBUG: send_system_email_notifications key not found in config")
	}
	
	if val, exists := config["send_system_telegram_notifications"]; exists {
		if sendSystemTelegramNotifications, ok := val.(bool); ok {
			dbConfig.SendSystemTelegramNotifications = sendSystemTelegramNotifications
			updated = append(updated, "SEND_SYSTEM_TELEGRAM_NOTIFICATIONS")
			log.Printf("DEBUG: Updated SendSystemTelegramNotifications to %v", sendSystemTelegramNotifications)
		} else {
			log.Printf("WARNING: send_system_telegram_notifications value is not boolean: %v (type: %T)", val, val)
		}
	} else {
		log.Printf("DEBUG: send_system_telegram_notifications key not found in config")
	}
	
	if maxRetryAttempts, ok := config["max_retry_attempts"].(float64); ok {
		dbConfig.MaxRetryAttempts = int(maxRetryAttempts)
		updated = append(updated, "MAX_RETRY_ATTEMPTS")
	}
	
	if batchSize, ok := config["batch_size"].(float64); ok {
		dbConfig.BatchSize = int(batchSize)
		updated = append(updated, "BATCH_SIZE")
	}
	
	if delayBetweenMS, ok := config["delay_between_batches_ms"].(float64); ok {
		dbConfig.DelayBetweenBatchesMS = int(delayBetweenMS)
		updated = append(updated, "DELAY_BETWEEN_BATCHES_MS")
	}
	
	// Handle debug mode settings
	if val, exists := config["debug_mode"]; exists {
		if debugMode, ok := val.(bool); ok {
			dbConfig.DebugMode = debugMode
			updated = append(updated, "DEBUG_MODE")
			log.Printf("DEBUG: Updated DebugMode to %v", debugMode)
		} else {
			log.Printf("WARNING: debug_mode value is not boolean: %v (type: %T)", val, val)
		}
	} else {
		log.Printf("DEBUG: debug_mode key not found in config")
	}
	
	if val, exists := config["debug_email"]; exists {
		if debugEmail, ok := val.(string); ok {
			dbConfig.DebugEmail = debugEmail
			updated = append(updated, "DEBUG_EMAIL")
			log.Printf("DEBUG: Updated DebugEmail to %s", debugEmail)
		} else {
			log.Printf("WARNING: debug_email value is not string: %v (type: %T)", val, val)
		}
	} else {
		log.Printf("DEBUG: debug_email key not found in config")
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
			"error": "Failed to save configuration: " + saveErr.Error(),
		})
		return
	}

	log.Printf("Configuration updated successfully. Updated fields: %v", updated)
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Configuration updated successfully",
		"updated_fields": updated,
	})
}

// resolveTelegramChatID attempts to get Chat ID from Telegram username
// by querying bot updates. User must have sent /start to the bot first.
func (ns *NotificationService) resolveTelegramChatID(botToken, username string) (string, error) {
	// Remove @ prefix if present
	username = strings.TrimPrefix(username, "@")
	
	// Request recent updates from Telegram API
	url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?limit=100", botToken)
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to request Telegram API: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("Telegram API returned status %d: %s", resp.StatusCode, string(body))
	}
	
	// Parse response
	var result struct {
		Ok     bool `json:"ok"`
		Result []struct {
			Message struct {
				Chat struct {
					ID       int64  `json:"id"`
					Username string `json:"username"`
					Type     string `json:"type"`
				} `json:"chat"`
			} `json:"message"`
		} `json:"result"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse Telegram API response: %v", err)
	}
	
	if !result.Ok {
		return "", fmt.Errorf("Telegram API returned ok=false")
	}
	
	// Search for matching username in updates
	for _, update := range result.Result {
		chat := update.Message.Chat
		if chat.Type == "private" && strings.EqualFold(chat.Username, username) {
			chatID := strconv.FormatInt(chat.ID, 10)
			return chatID, nil
		}
	}
	
	return "", fmt.Errorf("chat not found for username @%s (user must send /start to bot first)", username)
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

// getConfigFromDB retrieves configuration from database
func (ns *NotificationService) getConfigFromDB() NotificationConfig {
	var dbConfig NotificationConfig
	
	result := ns.db.First(&dbConfig)
	if result.Error != nil {
		// Return default config if not found in database
		return NotificationConfig{
			SMTPHost:              getEnvOrDefault("SMTP_HOST", "smtp.gmail.com"),
			SMTPPort:              getEnvOrDefault("SMTP_PORT", "587"),
			SMTPUsername:          getEnvOrDefault("SMTP_USERNAME", ""),
			SMTPPassword:          getEnvOrDefault("SMTP_PASSWORD", ""),
			SMTPFrom:              getEnvOrDefault("SMTP_FROM", ""),
			SMTPUseTLS:            getEnvAsBool("SMTP_USE_TLS", true),
			SMTPUseAuth:           getEnvAsBool("SMTP_USE_AUTH", true),
			SMTPAuthMethod:        getEnvOrDefault("SMTP_AUTH_METHOD", "plain"),
			TelegramBotToken:      getEnvOrDefault("TELEGRAM_BOT_TOKEN", ""),
			TelegramSystemBotToken: getEnvOrDefault("TELEGRAM_SYSTEM_BOT_TOKEN", ""),
			TelegramEnabled:       getEnvAsBool("TELEGRAM_ENABLED", false),
			TelegramSystemEnabled: getEnvAsBool("TELEGRAM_SYSTEM_ENABLED", false),
			MaxRetryAttempts:      getEnvAsInt("MAX_RETRY_ATTEMPTS", 3),
			BatchSize:             getEnvAsInt("BATCH_SIZE", 10),
			DelayBetweenBatchesMS: getEnvAsInt("DELAY_BETWEEN_BATCHES_MS", 1000),
		}
	}
	
	return dbConfig
}