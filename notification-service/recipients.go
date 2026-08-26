package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Режим адресации уведомления — определяется по тому, какое поле заполнил вызывающий сервис
const (
	recipientModeLogin    = "login"    // login: логин портала, адрес резолвит auth-service
	recipientModeExternal = "external" // external_recipient: получатель вне портала
	recipientModeLegacy   = "legacy"   // recipient: устаревшее поле, прежнее поведение
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

// logLegacyRecipient помечает вызовы через устаревшее поле recipient.
// По этим строкам видно, какие сервисы ещё не переведены на login / external_recipient.
func logLegacyRecipient(serviceName string, t NotificationType) {
	log.Printf("⚠️ LEGACY RECIPIENT: сервис «%s» шлёт %s через устаревшее поле recipient — переведите на login / external_recipient", serviceName, t)
}

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
func maskRecipient(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "(пусто)"
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

// resolveRecipientMode определяет, каким полем адресовано уведомление, и валидирует
// запрос. Ровно одно из login / external_recipient / recipient — угадывать по виду
// строки («похоже на email») нельзя: ошибка адресации молча уводит уведомление не туда.
func resolveRecipientMode(req *SingleNotificationRequest) (string, string, error) {
	login := strings.TrimSpace(req.Login)
	external := strings.TrimSpace(req.ExternalRecipient)
	legacy := strings.TrimSpace(req.Recipient)

	filled := 0
	for _, v := range []string{login, external, legacy} {
		if v != "" {
			filled++
		}
	}

	if filled > 1 {
		return "", "", fmt.Errorf("укажите ровно одно поле получателя: login (пользователь портала) или external_recipient (адрес вне портала)")
	}

	if filled == 0 {
		// У системных телеграм-алертов получатель берётся из конфига сервиса
		if req.Type == NotificationTypeTelegramSystem {
			return recipientModeSystem, "", nil
		}
		return "", "", fmt.Errorf("не указан получатель: заполните login или external_recipient")
	}

	if login != "" {
		if strings.Contains(login, "@") {
			return "", "", fmt.Errorf("поле login ожидает логин портала, а не адрес «%s»: для получателя вне портала используйте external_recipient", maskRecipient(login))
		}
		if channelForType(req.Type) == "" {
			return "", "", fmt.Errorf("адресация по login не поддержана для типа %s", req.Type)
		}
		return recipientModeLogin, login, nil
	}

	if external != "" {
		return recipientModeExternal, external, nil
	}

	return recipientModeLegacy, legacy, nil
}
