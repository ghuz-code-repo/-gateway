package routes

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"auth-service/models"

	"github.com/gin-gonic/gin"
)

// maxResolveLogins ограничивает размер пачки: notification-service резолвит всю
// batch-рассылку одним запросом, но безлимитный $in — это скан по коллекции
const maxResolveLogins = 500

// recipientAccessEnforced сообщает, блокировать ли отправку пользователю, у которого
// нет ролей в сервисе-отправителе.
//
// По умолчанию ВЫКЛЮЧЕНО (режим наблюдения): часть живых рассылок адресована людям
// без ролей в сервисе-отправителе (алерты админам от monitoring-service, письма
// колл-центру от referal). Сначала неделя логов WARN, потом включение флага.
func recipientAccessEnforced() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RECIPIENT_ACCESS_ENFORCE"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// recipientsResolveAPIHandler (POST /api/recipients/resolve) резолвит логины портала
// в адреса доставки для указанного канала. Вызывается notification-service, когда
// уведомление адресовано полем login, а не сырым адресом.
//
// Эндпоинт живёт в группе /api под internalAPIKeyRequired() — наружу не публикуется:
// он раздаёт контактные данные пользователей.
func recipientsResolveAPIHandler(c *gin.Context) {
	var req struct {
		Service string   `json:"service"`
		Channel string   `json:"channel" binding:"required"`
		Logins  []string `json:"logins" binding:"required,min=1"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Некорректный запрос: " + err.Error()})
		return
	}

	if len(req.Logins) > maxResolveLogins {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Слишком много логинов в одном запросе (максимум " + strconv.Itoa(maxResolveLogins) + ")",
		})
		return
	}

	channel := strings.ToLower(strings.TrimSpace(req.Channel))
	if !models.IsValidRecipientChannel(channel) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Неизвестный канал доставки: " + req.Channel,
		})
		return
	}

	serviceKey := strings.TrimSpace(req.Service)
	results, err := models.ResolveRecipients(serviceKey, channel, req.Logins)
	if err != nil {
		log.Printf("API: recipient resolve failed (service=%s channel=%s): %v", serviceKey, channel, err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Не удалось разрешить получателей"})
		return
	}

	// Политика доступа применяется здесь, а не в модели.
	// В логи пишем только логин и сервис — адрес доставки это PII.
	enforce := recipientAccessEnforced()
	for login, res := range results {
		if res.Found && !res.HasServiceAccess {
			log.Printf("⚠️ RECIPIENT ACCESS: сервис «%s» шлёт пользователю «%s» без ролей в этом сервисе (enforce=%v)",
				serviceKey, login, enforce)
			if enforce {
				res.Found = false
				res.Address = ""
				res.Reason = models.RecipientReasonNoServiceAccess
				results[login] = res
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":         true,
		"channel":         channel,
		"access_enforced": enforce,
		"results":         results,
	})
}
