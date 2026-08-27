package main

import (
	"errors"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
)

func main() {
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	if botToken == "" {
		log.Fatal("FATAL: TELEGRAM_BOT_TOKEN environment variable is required")
	}

	apiKey := os.Getenv("INTERNAL_API_KEY")
	if apiKey == "" {
		log.Fatal("FATAL: INTERNAL_API_KEY environment variable is required. " +
			"Generate with: openssl rand -base64 32")
	}

	authServiceURL := os.Getenv("AUTH_SERVICE_URL")
	if authServiceURL == "" {
		authServiceURL = "http://auth-service:80"
	}

	// Лимиты Telegram соблюдаются здесь: через этого бота шлют и
	// notification-service, и auth-service, и сам цикл входящих обновлений —
	// ни один из них не видит трафик остальных
	limiter := NewSendLimiter()
	bot := NewTelegramBot(botToken, limiter)
	authClient := NewAuthClient(authServiceURL, apiKey)

	// Verify bot token on startup
	me, err := bot.GetMe()
	if err != nil {
		log.Fatalf("FATAL: Failed to verify bot token (getMe): %v", err)
	}
	log.Printf("✅ Telegram bot authorized: @%s (id=%d)", me.Username, me.ID)

	// Start long-polling loop for incoming updates (link confirmations, login decisions)
	go runUpdatesLoop(bot, authClient)

	// Internal HTTP API for other services (auth-service) to send messages
	port := os.Getenv("PORT")
	if port == "" {
		port = "80"
	}

	if os.Getenv("ENVIRONMENT") == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()
	router.SetTrustedProxies(nil)

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "bot": me.Username})
	})

	api := router.Group("/api/v1", apiKeyRequired(apiKey))
	{
		api.POST("/send", sendMessageHandler(bot))
	}

	log.Printf("Starting notification-bot HTTP API on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// apiKeyRequired validates the X-API-Key header for service-to-service calls
func apiKeyRequired(apiKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("X-API-Key") != apiKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or missing X-API-Key"})
			return
		}
		c.Next()
	}
}

// sendMessageRequest is the payload other services use to send a Telegram message
type sendMessageRequest struct {
	ChatID    int64            `json:"chat_id" binding:"required"`
	Text      string           `json:"text" binding:"required"`
	ParseMode string           `json:"parse_mode,omitempty" binding:"omitempty,oneof=Markdown MarkdownV2 HTML"`
	Buttons   [][]InlineButton `json:"buttons,omitempty"`
}

// sendMessageHandler sends a message (optionally with inline keyboard) to a chat
func sendMessageHandler(bot *TelegramBot) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req sendMessageRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
			return
		}

		messageID, err := bot.SendMessage(req.ChatID, req.Text, req.ParseMode, req.Buttons)
		if err != nil {
			// Отказ по темпу отдаём как 429 с точным сроком ожидания: вызывающий
			// сервис должен вернуть сообщение в очередь, а не считать его
			// проваленным и не подбирать паузу наугад
			var rl *RateLimitedError
			if errors.As(err, &rl) {
				retryAfter := int(math.Ceil(rl.RetryAfter.Seconds()))
				if retryAfter < 1 {
					retryAfter = 1
				}
				log.Printf("WARNING: rate limited for chat %d: %v", req.ChatID, err)
				c.Header("Retry-After", strconv.Itoa(retryAfter))
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error":       err.Error(),
					"retry_after": retryAfter,
				})
				return
			}

			log.Printf("ERROR: failed to send message to chat %d: %v", req.ChatID, err)
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message_id": messageID})
	}
}
