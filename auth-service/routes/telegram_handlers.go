package routes

import (
	"auth-service/models"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// getTelegramBotUsername returns the bot username for t.me deep links
func getTelegramBotUsername() string {
	botUsername := os.Getenv("TELEGRAM_BOT_USERNAME")
	if botUsername == "" {
		botUsername = "notification_analytics_gh_uz_bot"
	}
	return botUsername
}

// --- Rate limiting for telegram login endpoints (JSON responses) ---

var (
	tgLoginAttempts = make(map[string]*LoginAttempt)
	tgLoginMutex    sync.Mutex
)

// telegramLoginRateLimit limits POST /login/telegram to 5 requests per minute per IP
func telegramLoginRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now()

		tgLoginMutex.Lock()
		attempt, exists := tgLoginAttempts[ip]
		if !exists || now.After(attempt.ResetTime) {
			tgLoginAttempts[ip] = &LoginAttempt{Count: 1, ResetTime: now.Add(1 * time.Minute)}
			tgLoginMutex.Unlock()
			c.Next()
			return
		}
		attempt.Count++
		count := attempt.Count
		tgLoginMutex.Unlock()

		if count > maxLoginAttempts {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Слишком много попыток. Попробуйте снова через минуту.",
			})
			return
		}
		c.Next()
	}
}

// ============================================================
// Личный кабинет: привязка / отвязка Telegram
// ============================================================

// telegramLinkRequestHandler (POST /profile/telegram/link) creates a link token
// and emails the user a t.me deep link that confirms the link via the bot
func telegramLinkRequestHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	// Username необязателен: привязку подтверждает сам бот по deep-link, а
	// фактический username берётся из данных Telegram в ConfirmTelegramLink.
	// Если поле всё же передали — используем его в тексте письма.
	tgUsername := models.NormalizeTelegramUsername(c.PostForm("tg_username"))

	if user.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "У вашей учетной записи не настроен email. Привязка Telegram подтверждается по почте — обратитесь к администратору."})
		return
	}

	linkToken, err := models.CreateTelegramLinkToken(user.ID, tgUsername)
	if err != nil {
		log.Printf("Error creating telegram link token for user %s: %v", user.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать токен привязки"})
		return
	}

	deepLink := fmt.Sprintf("https://t.me/%s?start=%s", getTelegramBotUsername(), linkToken.Token)
	subject, body := models.GetTelegramLinkEmail(user.GetFullName(), tgUsername, deepLink)

	if err := models.SendEmailNotificationToLogin(user.Username, subject, body); err != nil {
		log.Printf("Failed to send telegram link email to %s: %v", user.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось отправить письмо. Попробуйте позже."})
		return
	}

	log.Printf("Telegram link email sent to %s (tg: %s)", user.Email, formatTelegramUsernameForLog(tgUsername))
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Ссылка для подтверждения отправлена на ваш email. Перейдите по ней — она откроет бота и подтвердит привязку.",
	})
}

// formatTelegramUsernameForLog renders an optional username for log lines
func formatTelegramUsernameForLog(tgUsername string) string {
	if tgUsername == "" {
		return "не указан"
	}
	return "@" + tgUsername
}

// telegramUnlinkHandler (POST /profile/telegram/unlink) removes the Telegram link
func telegramUnlinkHandler(c *gin.Context) {
	user := c.MustGet("user").(*models.User)

	if err := models.UnlinkTelegram(user.ID); err != nil {
		log.Printf("Error unlinking telegram for user %s: %v", user.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось отвязать Telegram"})
		return
	}

	log.Printf("Telegram unlinked for user %s", user.Username)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Telegram отвязан от аккаунта"})
}

// ============================================================
// Вход через Telegram
// ============================================================

// telegramLoginPageHandler (GET /login/telegram) shows the telegram login page
func telegramLoginPageHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "telegram-login.html", gin.H{
		"redirect": c.Query("redirect"),
	})
}

// telegramLoginStartHandler (POST /login/telegram) creates a login request and
// sends a confirmation message with Approve/Reject buttons to the user's Telegram
func telegramLoginStartHandler(c *gin.Context) {
	identifier := c.PostForm("identifier")
	if identifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Введите Telegram username, email или логин"})
		return
	}

	// Combined "not found" / "not linked" message keeps account existence hidden
	// while still telling the user Telegram login is unavailable for this input.
	const notLinkedMsg = "К этому аккаунту не привязан Telegram, либо аккаунт не найден. " +
		"Войдите по логину и паролю и привяжите Telegram в личном кабинете."

	user, err := models.GetUserByLoginIdentifier(identifier)
	if err != nil {
		log.Printf("Error looking up user for telegram login: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Внутренняя ошибка. Попробуйте позже."})
		return
	}
	if user == nil || user.TelegramChatID == 0 || user.IsBanned {
		debugLog("DEBUG: telegram login rejected for identifier '%s' (not found / not linked / banned)", identifier)
		c.JSON(http.StatusBadRequest, gin.H{"error": notLinkedMsg})
		return
	}

	if user.TelegramLoginFrozen {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Вход через Telegram заморожен из-за повторных отклонений. Войдите по логину и паролю, чтобы разблокировать.",
		})
		return
	}

	request, err := models.CreateTelegramLoginRequest(user.ID, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		log.Printf("Error creating telegram login request for user %s: %v", user.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать запрос на вход"})
		return
	}

	messageText := fmt.Sprintf(
		"🔐 Новый запрос на вход в портал Golden House Analytics\n\n"+
			"Аккаунт: %s\n"+
			"IP-адрес: %s\n"+
			"Браузер: %s\n"+
			"Время: %s\n\n"+
			"Если это не вы — отклоните вход.",
		user.Username, request.IP, request.UserAgent, request.CreatedAt.Format("02.01.2006 15:04:05"))

	buttons := [][]models.TelegramButton{{
		{Text: "✅ Подтвердить вход", CallbackData: "login:" + request.RequestID + ":approve"},
		{Text: "🚫 Отклонить вход", CallbackData: "login:" + request.RequestID + ":reject"},
	}}

	if models.SendTelegramViaBot == nil {
		log.Printf("ERROR: notification-bot client not initialized")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Сервис Telegram временно недоступен"})
		return
	}
	if err := models.SendTelegramViaBot(user.TelegramChatID, messageText, buttons); err != nil {
		log.Printf("Failed to send telegram login confirmation to user %s: %v", user.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось отправить сообщение в Telegram. Попробуйте позже."})
		return
	}

	log.Printf("Telegram login request %s sent to user %s", request.RequestID, user.Username)
	c.JSON(http.StatusOK, gin.H{
		"request_id": request.RequestID,
		"message":    "Запрос на подтверждение входа отправлен в ваш Telegram.",
	})
}

// telegramLoginStatusHandler (GET /login/telegram/status) is polled by the browser.
// When the request is approved, it issues the session cookie (exactly once).
func telegramLoginStatusHandler(c *gin.Context) {
	requestID := c.Query("request_id")
	if requestID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request_id обязателен"})
		return
	}

	status := models.GetTelegramLoginRequestStatus(requestID)
	if status != "approved" {
		c.JSON(http.StatusOK, gin.H{"status": status})
		return
	}

	// Approved: consume the request atomically and issue the session
	user, err := models.ConsumeApprovedTelegramLoginRequest(requestID)
	if err != nil {
		// Already consumed (e.g. second tab) — treat as expired
		c.JSON(http.StatusOK, gin.H{"status": "expired"})
		return
	}

	if user.IsBanned {
		c.JSON(http.StatusOK, gin.H{"status": "rejected"})
		return
	}

	tokenString, err := models.GenerateToken(user)
	if err != nil {
		log.Printf("Error generating token for telegram login (user %s): %v", user.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать сессию"})
		return
	}

	isProduction := os.Getenv("ENVIRONMENT") == "production"
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("token", tokenString, 28800, "/", "", isProduction, true) // 8 hours, httpOnly

	// Only local paths are allowed ("//host" would be an open redirect)
	redirect := c.Query("redirect")
	if redirect == "" || redirect[0] != '/' || strings.HasPrefix(redirect, "//") {
		redirect = "/menu"
	}

	log.Printf("Telegram login completed for user %s", user.Username)
	c.JSON(http.StatusOK, gin.H{"status": "approved", "redirect": redirect})
}

// ============================================================
// Сброс пароля через Telegram
// ============================================================

// forgotPasswordViaTelegram sends the password reset link through the bot
// instead of email (called from forgotPasswordHandler when method=telegram)
func forgotPasswordViaTelegram(c *gin.Context, identifier string) {
	user, err := models.GetUserByLoginIdentifier(identifier)
	if err != nil {
		log.Printf("Error looking up user for telegram password reset: %v", err)
		c.HTML(http.StatusInternalServerError, "forgot-password-result.html", gin.H{
			"error": "Внутренняя ошибка. Попробуйте позже.",
		})
		return
	}
	// Combined "not found" / "not linked" message keeps account existence hidden
	if user == nil || user.TelegramChatID == 0 || user.IsBanned {
		debugLog("DEBUG: telegram password reset rejected for identifier '%s' (not found / not linked / banned)", identifier)
		c.HTML(http.StatusOK, "forgot-password-result.html", gin.H{
			"error": "К этому аккаунту не привязан Telegram, либо аккаунт не найден. " +
				"Используйте восстановление по email или войдите по паролю и привяжите Telegram в личном кабинете.",
		})
		return
	}

	resetToken, err := models.CreatePasswordResetTokenForUser(user)
	if err != nil {
		log.Printf("Error creating password reset token (telegram) for user %s: %v", user.Username, err)
		c.HTML(http.StatusInternalServerError, "forgot-password-result.html", gin.H{
			"error": "Произошла ошибка при создании токена восстановления",
		})
		return
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost"
	}
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", baseURL, resetToken.Token)

	messageText := fmt.Sprintf(
		"🔑 Восстановление пароля\n\n"+
			"Для аккаунта «%s» запрошен сброс пароля.\n\n"+
			"Ссылка для установки нового пароля (действует 15 минут):\n%s\n\n"+
			"Если вы не запрашивали сброс — проигнорируйте это сообщение и сообщите администратору.",
		user.Username, resetLink)

	if models.SendTelegramViaBot == nil {
		log.Printf("ERROR: notification-bot client not initialized")
		c.HTML(http.StatusInternalServerError, "forgot-password-result.html", gin.H{
			"error": "Сервис Telegram временно недоступен. Попробуйте восстановление по email.",
		})
		return
	}
	if err := models.SendTelegramViaBot(user.TelegramChatID, messageText, nil); err != nil {
		log.Printf("Failed to send telegram password reset to user %s: %v", user.Username, err)
		c.HTML(http.StatusInternalServerError, "forgot-password-result.html", gin.H{
			"error": "Не удалось отправить сообщение в Telegram. Попробуйте восстановление по email.",
		})
		return
	}

	log.Printf("Password reset link sent via Telegram to user %s", user.Username)
	c.HTML(http.StatusOK, "forgot-password-result.html", gin.H{
		"success": "Ссылка для восстановления пароля отправлена в ваш Telegram.",
	})
}

// ============================================================
// Внутренний API для notification-bot (X-API-Key)
// ============================================================

// telegramLinkConfirmAPIHandler (POST /api/telegram/link/confirm) is called by
// notification-bot when a user opens the /start deep link from the email
func telegramLinkConfirmAPIHandler(c *gin.Context) {
	var req struct {
		Token      string `json:"token" binding:"required"`
		ChatID     int64  `json:"chat_id" binding:"required"`
		TgUsername string `json:"tg_username"`
		FirstName  string `json:"first_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Некорректный запрос"})
		return
	}

	user, err := models.ConfirmTelegramLink(req.Token, req.ChatID, req.TgUsername)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Telegram привязан к аккаунту «%s». Теперь вы можете входить на портал через Telegram и сбрасывать пароль через бота.", user.Username),
	})
}

// telegramChatIDLookupAPIHandler (GET /api/telegram/chat-id?username=) resolves a
// linked Telegram username to its chat_id (used by notification-service for system alerts)
func telegramChatIDLookupAPIHandler(c *gin.Context) {
	username := c.Query("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "username обязателен"})
		return
	}

	chatID, err := models.GetTelegramChatIDByUsername(username)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "chat_id": chatID})
}

// telegramLoginDecisionAPIHandler (POST /api/telegram/login/decision) is called by
// notification-bot when the user presses Approve/Reject
func telegramLoginDecisionAPIHandler(c *gin.Context) {
	var req struct {
		RequestID string `json:"request_id" binding:"required"`
		Decision  string `json:"decision" binding:"required"`
		ChatID    int64  `json:"chat_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Некорректный запрос"})
		return
	}

	if req.Decision != "approve" && req.Decision != "reject" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Неизвестное действие"})
		return
	}

	request, frozen, err := models.ResolveTelegramLoginRequest(req.RequestID, req.Decision, req.ChatID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": err.Error()})
		return
	}

	message := "Вход отклонён"
	if request.Status == "approved" {
		message = "Вход подтверждён"
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": message,
		"frozen":  frozen,
	})
}
