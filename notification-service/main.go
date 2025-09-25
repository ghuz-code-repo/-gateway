package main

import (
	"log"
	"net/http"
	"os"
	"strconv"

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
	NotificationTypeEmail NotificationType = "email"
	NotificationTypeSMS   NotificationType = "sms"
	NotificationTypePush  NotificationType = "push"
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
	ID          uint                `json:"id" gorm:"primaryKey"`
	Type        NotificationType    `json:"type" gorm:"not null"`
	Recipient   string              `json:"recipient" gorm:"not null"`
	Subject     string              `json:"subject,omitempty"`
	Content     string              `json:"content" gorm:"not null"`
	Status      NotificationStatus  `json:"status" gorm:"default:pending"`
	Attempts    int                 `json:"attempts" gorm:"default:0"`
	MaxAttempts int                 `json:"max_attempts" gorm:"default:3"`
	LastError   string              `json:"last_error,omitempty"`
	BatchID     string              `json:"batch_id,omitempty"`
	CreatedAt   int64               `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   int64               `json:"updated_at" gorm:"autoUpdateTime"`
	SentAt      *int64              `json:"sent_at,omitempty"`
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
	Type      NotificationType `json:"type" binding:"required,oneof=email sms push"`
	Recipient string           `json:"recipient" binding:"required"`
	Subject   string           `json:"subject,omitempty"`
	Content   string           `json:"content" binding:"required"`
}

// NotificationConfig represents stored notification service configuration
type NotificationConfig struct {
	ID                      uint   `json:"id" gorm:"primaryKey"`
	SMTPHost                string `json:"smtp_host" gorm:"default:'smtp.gmail.com'"`
	SMTPPort                string `json:"smtp_port" gorm:"default:'587'"`
	SMTPUsername            string `json:"smtp_username"`
	SMTPPassword            string `json:"smtp_password"`
	SMTPFrom                string `json:"smtp_from"`
	SMTPUseTLS              bool   `json:"smtp_use_tls" gorm:"default:true"`
	SMTPUseAuth             bool   `json:"smtp_use_auth" gorm:"default:true"`
	SMTPAuthMethod          string `json:"smtp_auth_method" gorm:"default:'plain'"`
	MaxRetryAttempts        int    `json:"max_retry_attempts" gorm:"default:3"`
	BatchSize               int    `json:"batch_size" gorm:"default:10"`
	DelayBetweenBatchesMS   int    `json:"delay_between_batches_ms" gorm:"default:1000"`
	CreatedAt               int64  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt               int64  `json:"updated_at" gorm:"autoUpdateTime"`
}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Initialize database
	db, err := initDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Create service instance
	service := &NotificationService{db: db}

	// Initialize router
	router := gin.Default()

	// Setup routes
	service.setupRoutes(router)

	// Get port from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	log.Printf("Starting notification service on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate batch ID if not provided
	if req.BatchID == "" {
		req.BatchID = generateBatchID()
	}

	// Create batch record
	batch := NotificationBatch{
		ID:          req.BatchID,
		TotalCount:  len(req.Notifications),
		Status:      "processing",
	}

	if err := ns.db.Create(&batch).Error; err != nil {
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create notifications"})
		return
	}

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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create notification
	notification := Notification{
		Type:      req.Type,
		Recipient: req.Recipient,
		Subject:   req.Subject,
		Content:   req.Content,
	}

	if err := ns.db.Create(&notification).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create notification"})
		return
	}

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
			SMTPHost:              getEnvOrDefault("SMTP_HOST", "smtp.gmail.com"),
			SMTPPort:              getEnvOrDefault("SMTP_PORT", "587"),
			SMTPUsername:          getEnvOrDefault("SMTP_USERNAME", ""),
			SMTPPassword:          getEnvOrDefault("SMTP_PASSWORD", ""),
			SMTPFrom:              getEnvOrDefault("SMTP_FROM", ""),
			SMTPUseTLS:            getEnvAsBool("SMTP_USE_TLS", true),
			SMTPUseAuth:           getEnvAsBool("SMTP_USE_AUTH", true),
			SMTPAuthMethod:        getEnvOrDefault("SMTP_AUTH_METHOD", "plain"),
			MaxRetryAttempts:      getEnvAsInt("MAX_RETRY_ATTEMPTS", 3),
			BatchSize:             getEnvAsInt("BATCH_SIZE", 10),
			DelayBetweenBatchesMS: getEnvAsInt("DELAY_BETWEEN_BATCHES_MS", 1000),
		}
		// Save default config to DB
		ns.db.Create(&dbConfig)
	}

	config := map[string]interface{}{
		"smtp_host":                dbConfig.SMTPHost,
		"smtp_port":                dbConfig.SMTPPort,
		"smtp_username":            dbConfig.SMTPUsername,
		"smtp_from":                dbConfig.SMTPFrom,
		"smtp_use_tls":             strconv.FormatBool(dbConfig.SMTPUseTLS),
		"smtp_use_auth":            strconv.FormatBool(dbConfig.SMTPUseAuth),
		"smtp_auth_method":         dbConfig.SMTPAuthMethod,
		"max_retry_attempts":       dbConfig.MaxRetryAttempts,
		"batch_size":               dbConfig.BatchSize,
		"delay_between_batches_ms": dbConfig.DelayBetweenBatchesMS,
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
	
	if smtpUseTLS, ok := config["smtp_use_tls"].(string); ok {
		dbConfig.SMTPUseTLS = smtpUseTLS == "true"
		updated = append(updated, "SMTP_USE_TLS")
	}
	
	if smtpUseAuth, ok := config["smtp_use_auth"].(string); ok {
		dbConfig.SMTPUseAuth = smtpUseAuth == "true"
		updated = append(updated, "SMTP_USE_AUTH")
	}
	
	if smtpAuthMethod, ok := config["smtp_auth_method"].(string); ok {
		dbConfig.SMTPAuthMethod = smtpAuthMethod
		updated = append(updated, "SMTP_AUTH_METHOD")
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
			MaxRetryAttempts:      getEnvAsInt("MAX_RETRY_ATTEMPTS", 3),
			BatchSize:             getEnvAsInt("BATCH_SIZE", 10),
			DelayBetweenBatchesMS: getEnvAsInt("DELAY_BETWEEN_BATCHES_MS", 1000),
		}
	}
	
	return dbConfig
}