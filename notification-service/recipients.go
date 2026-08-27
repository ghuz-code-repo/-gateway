package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Режим адресации уведомления — определяется по тому, какое поле заполнил вызывающий сервис
const (
	recipientModeLogin    = "login"    // login: логин портала, адрес резолвит auth-service
	recipientModeExternal = "external" // external_recipient: получатель вне портала
	recipientModeSystem   = "system"   // telegram_system: получатель берётся из конфига
)

// Коды отказа резолва. Часть приходит от auth-service (user_not_found, user_banned,
// no_service_access, channel_not_linked, no_address), часть локальная.
const (
	failureAuthUnavailable = "auth_unavailable"
	failureUnknownChannel  = "unknown_channel"
	failureUserNotFound    = "user_not_found"
	failureSendFailed      = "send_failed" // резолв прошёл, упала сама отправка
)

// Сколько живёт результат резолва. Отрицательный ответ кэшируем коротко:
// пользователь может привязать Telegram или получить роль в любой момент.
const (
	recipientCacheTTL         = 10 * time.Minute
	recipientCacheNegativeTTL = 1 * time.Minute
)

// systemRecipientPlaceholder попадает в колонку recipient системных телеграм-алертов:
// фактический chat_id берётся из конфига сервиса в момент отправки, а колонка NOT NULL
const systemRecipientPlaceholder = "system"

// recipientResolution — ответ auth-service по одному логину
type recipientResolution struct {
	Found            bool   `json:"found"`
	Address          string `json:"address,omitempty"`
	Reason           string `json:"reason,omitempty"`
	HasServiceAccess bool   `json:"has_service_access"`
}

type recipientCacheEntry struct {
	res recipientResolution
	at  time.Time
}

// channelForType сводит тип уведомления к каналу доставки auth-service.
// Пустая строка => для этого типа резолв по логину не поддержан.
func channelForType(t NotificationType) string {
	switch t {
	case NotificationTypeTelegram, NotificationTypeTelegramSystem:
		return "telegram"
	case NotificationTypeEmail:
		return "email"
	case NotificationTypeSMS:
		return "sms"
	}
	return ""
}

// getAuthServiceURL возвращает адрес auth-service внутри service_network
func getAuthServiceURL() string {
	url := os.Getenv("AUTH_SERVICE_URL")
	if url == "" {
		url = "http://auth-service:80"
	}
	return url
}

// serviceAuthKey переводит имя сервиса из SERVICE_API_KEYS в его service_key в auth-service.
//
// Имена не совпадают: у apartment_finder ключ уведомлений «apartment-finder», а
// service_key в auth-service — «finder». Без маппинга проверка доступа отвергала бы
// всех получателей этого сервиса.
//
//	SERVICE_AUTH_KEY_MAP=apartment-finder=finder,client-service=client_service
func serviceAuthKey(serviceName string) string {
	raw := os.Getenv("SERVICE_AUTH_KEY_MAP")
	if raw == "" || serviceName == "" {
		return serviceName
	}
	for _, pair := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(parts[0]), serviceName) {
			return strings.TrimSpace(parts[1])
		}
	}
	return serviceName
}

// maskRecipient прячет адрес доставки в логах: сервис пишет их в общий журнал,
// а chat_id и email — персональные данные.
//
// LOG_FULL_RECIPIENTS=true отключает маскировку. Нужен для разбора инцидентов
// «письмо ушло не туда»: по маске d.***@gh.uz невозможно отличить двух сотрудников
// с похожими адресами.
func maskRecipient(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "(пусто)"
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LOG_FULL_RECIPIENTS"))) {
	case "1", "true", "yes", "on":
		return value
	}
	if at := strings.Index(value, "@"); at > 0 {
		local := value[:at]
		if len(local) <= 2 {
			return "**" + value[at:]
		}
		return local[:2] + "***" + value[at:]
	}
	if len(value) <= 4 {
		return "***"
	}
	return value[:2] + "***" + value[len(value)-2:]
}

// notificationTarget описывает получателя для лога: логин — идентификатор, его
// прячем незачем; адрес доставки маскируется.
func notificationTarget(n *Notification) string {
	if n.RecipientLogin != "" {
		return fmt.Sprintf("login=%s (%s)", n.RecipientLogin, maskRecipient(n.Recipient))
	}
	return maskRecipient(n.Recipient)
}

func recipientCacheKey(service, channel, login string) string {
	return service + "|" + channel + "|" + login
}

func (ns *NotificationService) recipientCacheGet(service, channel, login string) (recipientResolution, bool) {
	ns.recipientMu.RLock()
	defer ns.recipientMu.RUnlock()

	entry, ok := ns.recipientCache[recipientCacheKey(service, channel, login)]
	if !ok {
		return recipientResolution{}, false
	}
	ttl := recipientCacheTTL
	if !entry.res.Found {
		ttl = recipientCacheNegativeTTL
	}
	if time.Since(entry.at) >= ttl {
		return recipientResolution{}, false
	}
	return entry.res, true
}

func (ns *NotificationService) recipientCacheSet(service, channel, login string, res recipientResolution) {
	ns.recipientMu.Lock()
	defer ns.recipientMu.Unlock()
	ns.recipientCache[recipientCacheKey(service, channel, login)] = recipientCacheEntry{res: res, at: time.Now()}
}

// resolveRecipients превращает логины портала в адреса доставки через auth-service.
//
// Возвращаемая ошибка означает «auth-service недоступен» — это состояние, при котором
// уведомление надо отвергнуть с 503 и дать вызывающему повторить, а не хоронить его
// в failed. Отказы по конкретным пользователям приходят внутри map с кодом причины.
func (ns *NotificationService) resolveRecipients(serviceName, channel string, logins []string) (map[string]recipientResolution, error) {
	results := make(map[string]recipientResolution, len(logins))
	if channel == "" {
		for _, login := range logins {
			results[login] = recipientResolution{Reason: failureUnknownChannel}
		}
		return results, nil
	}

	authKey := serviceAuthKey(serviceName)

	// Из кэша берём что можем, остальное запрашиваем одной пачкой
	pending := make([]string, 0, len(logins))
	seen := make(map[string]bool, len(logins))
	for _, login := range logins {
		if seen[login] {
			continue
		}
		seen[login] = true
		if res, ok := ns.recipientCacheGet(authKey, channel, login); ok {
			results[login] = res
			continue
		}
		pending = append(pending, login)
	}
	if len(pending) == 0 {
		return results, nil
	}

	payload, err := json.Marshal(map[string]interface{}{
		"service": authKey,
		"channel": channel,
		"logins":  pending,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal resolve request: %v", err)
	}

	req, err := http.NewRequest("POST", getAuthServiceURL()+"/api/recipients/resolve", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create auth-service request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey := os.Getenv("INTERNAL_API_KEY"); apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	resp, err := ns.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth-service request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("auth-service returned status %d: %s", resp.StatusCode, string(body))
	}

	var decoded struct {
		Success        bool                           `json:"success"`
		AccessEnforced bool                           `json:"access_enforced"`
		Results        map[string]recipientResolution `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("failed to parse auth-service response: %v", err)
	}
	if !decoded.Success {
		return nil, fmt.Errorf("auth-service rejected resolve request")
	}

	for login, res := range decoded.Results {
		results[login] = res
		ns.recipientCacheSet(authKey, channel, login, res)
	}

	// Логин, про который auth-service промолчал, считаем неизвестным:
	// молча отправить «куда-нибудь» хуже, чем вернуть отказ вызывающему.
	for _, login := range pending {
		if _, ok := results[login]; !ok {
			results[login] = recipientResolution{Reason: failureUserNotFound}
		}
	}

	return results, nil
}

// addressingField описывает один способ адресации уведомления.
//
// Новый способ (по роли, по праву, по chat_id канала) добавляется одной записью в
// addressingFields и полем в SingleNotificationRequest — трогать разбор запроса
// и обработчики не нужно.
type addressingField struct {
	// name — имя поля в JSON, попадает в текст ошибки
	name string
	// mode — режим адресации, с которым дальше работают обработчики
	mode string
	// value достаёт значение поля из запроса
	value func(req *SingleNotificationRequest) string
	// validate проверяет пару «значение + тип уведомления»; nil = проверок нет
	validate func(req *SingleNotificationRequest, value string) error
}

// addressingFields перечислены в порядке предпочтения: при (недопустимом) заполнении
// нескольких полей запрос всё равно отвергается, порядок влияет только на текст ошибки.
var addressingFields = []addressingField{
	{
		name:  "login",
		mode:  recipientModeLogin,
		value: func(req *SingleNotificationRequest) string { return req.Login },
		validate: func(req *SingleNotificationRequest, value string) error {
			// Адрес в поле логина — самая вероятная ошибка вызывающего сервиса,
			// и молча отправить такое некуда: ловим на приёме
			if strings.Contains(value, "@") {
				return fmt.Errorf("поле login ожидает логин портала, а не адрес «%s»: для получателя вне портала используйте external_recipient", maskRecipient(value))
			}
			if channelForType(req.Type) == "" {
				return fmt.Errorf("адресация по login не поддержана для типа %s", req.Type)
			}
			return nil
		},
	},
	{
		name:  "external_recipient",
		mode:  recipientModeExternal,
		value: func(req *SingleNotificationRequest) string { return req.ExternalRecipient },
	},
}

// resolveRecipientMode определяет, каким полем адресовано уведомление, и валидирует
// запрос. Заполнено должно быть ровно одно поле адресации: угадывать по виду строки
// («похоже на email») нельзя — ошибка адресации молча уводит уведомление не туда.
func resolveRecipientMode(req *SingleNotificationRequest) (string, string, error) {
	var (
		filled []addressingField
		values []string
	)

	for _, field := range addressingFields {
		value := strings.TrimSpace(field.value(req))
		if value == "" {
			continue
		}
		filled = append(filled, field)
		values = append(values, value)
	}

	if len(filled) > 1 {
		names := make([]string, 0, len(filled))
		for _, field := range filled {
			names = append(names, field.name)
		}
		return "", "", fmt.Errorf("заполнено несколько полей получателя (%s): укажите ровно одно", strings.Join(names, ", "))
	}

	if len(filled) == 0 {
		// У системных телеграм-алертов получатель берётся из конфига сервиса
		if req.Type == NotificationTypeTelegramSystem {
			return recipientModeSystem, "", nil
		}
		return "", "", fmt.Errorf("не указан получатель: заполните login или external_recipient")
	}

	field, value := filled[0], values[0]
	if field.validate != nil {
		if err := field.validate(req, value); err != nil {
			return "", "", err
		}
	}

	return field.mode, value, nil
}

// applyRecipient проставляет в уведомление поля адресации по разобранному режиму.
// Для recipientModeLogin вызывающий обязан передать результат резолва.
func applyRecipient(notification *Notification, mode, value string, resolved recipientResolution) {
	switch mode {
	case recipientModeLogin:
		notification.RecipientLogin = value
		if resolved.Found {
			notification.Recipient = resolved.Address
		} else {
			// Адрес неизвестен, но получателя надо чем-то опознать в журнале
			notification.Recipient = value
		}
	case recipientModeExternal:
		notification.ExternalRecipient = value
		notification.Recipient = value
	default: // recipientModeSystem
		notification.Recipient = systemRecipientPlaceholder
	}
}
