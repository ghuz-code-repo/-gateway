package routes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// ServiceMonitor следит за здоровьем сервисов и отправляет алерты
type ServiceMonitor struct {
	checkInterval          time.Duration
	cooldownPeriod         time.Duration
	lastAlertTimes         map[string]time.Time
	previousStates         map[string]string
	adminChatID            string
	adminEmail             string
	notificationURL        string
	monitoringEnabled      bool
	sendNotificationsEnabled bool
	mu                     sync.RWMutex
}

// NotificationRequest структура для отправки уведомлений
type NotificationRequest struct {
	Type      string `json:"type"`
	Recipient string `json:"recipient"`
	Subject   string `json:"subject"`
	Content   string `json:"content"`
}

// ServiceHealthResponse структура ответа от health endpoint
type ServiceHealthResponse struct {
	ServiceKey    string `json:"service_key"`
	ServiceName   string `json:"service_name"`
	Status        string `json:"status"`
}

// HealthAPIResponse обертка для API ответа
type HealthAPIResponse struct {
	Count    int                      `json:"count"`
	Services []ServiceHealthResponse  `json:"services"`
}

// NewServiceMonitor создает новый монитор сервисов
func NewServiceMonitor() *ServiceMonitor {
	// Читаем конфигурацию из переменных окружения
	checkIntervalStr := os.Getenv("MONITOR_CHECK_INTERVAL_SECONDS")
	if checkIntervalStr == "" {
		checkIntervalStr = "30" // По умолчанию 30 секунд
	}
	checkInterval, _ := strconv.Atoi(checkIntervalStr)

	cooldownStr := os.Getenv("MONITOR_ALERT_COOLDOWN_MINUTES")
	if cooldownStr == "" {
		cooldownStr = "10" // По умолчанию 10 минут
	}
	cooldownMinutes, _ := strconv.Atoi(cooldownStr)

	adminChatID := os.Getenv("ADMIN_TELEGRAM_CHAT_ID")
	if adminChatID == "" {
		adminChatID = "7421864098" // Ваш chat ID по умолчанию
	}

	adminEmail := os.Getenv("MONITOR_ADMIN_EMAIL")
	if adminEmail == "" {
		adminEmail = "robot@gh.uz" // Email по умолчанию
	}

	notificationURL := os.Getenv("NOTIFICATION_SERVICE_URL")
	if notificationURL == "" {
		notificationURL = "http://notification-service:8082"
	}

	monitoringEnabledStr := os.Getenv("MONITORING_ENABLED")
	monitoringEnabled := monitoringEnabledStr == "true" || monitoringEnabledStr == "1"

	sendNotificationsStr := os.Getenv("MONITOR_SEND_NOTIFICATIONS")
	sendNotificationsEnabled := sendNotificationsStr == "" || sendNotificationsStr == "true" || sendNotificationsStr == "1"

	return &ServiceMonitor{
		checkInterval:            time.Duration(checkInterval) * time.Second,
		cooldownPeriod:           time.Duration(cooldownMinutes) * time.Minute,
		lastAlertTimes:           make(map[string]time.Time),
		previousStates:           make(map[string]string),
		adminChatID:              adminChatID,
		adminEmail:               adminEmail,
		notificationURL:          notificationURL,
		monitoringEnabled:        monitoringEnabled,
		sendNotificationsEnabled: sendNotificationsEnabled,
	}
}

// Start запускает мониторинг сервисов
func (sm *ServiceMonitor) Start() {
	if !sm.monitoringEnabled {
		log.Println("⚠️  Service monitoring is disabled")
		return
	}

	log.Println("🔍 Service monitoring started")
	log.Printf("   Check interval: %v", sm.checkInterval)
	log.Printf("   Alert cooldown: %v", sm.cooldownPeriod)
	log.Printf("   Admin Telegram: %s", sm.adminChatID)
	log.Printf("   Admin Email: %s", sm.adminEmail)
	log.Printf("   Notifications enabled: %v", sm.sendNotificationsEnabled)

	// Отправляем стартовое уведомление
	if sm.sendNotificationsEnabled {
		sm.sendStartupNotification()
	}

	// Запускаем мониторинг в отдельной goroutine
	go sm.monitorLoop()
}

// monitorLoop основной цикл мониторинга
func (sm *ServiceMonitor) monitorLoop() {
	ticker := time.NewTicker(sm.checkInterval)
	defer ticker.Stop()

	for {
		<-ticker.C
		sm.checkServices()
	}
}

// checkServices проверяет все сервисы
func (sm *ServiceMonitor) checkServices() {
	// Получаем статусы всех сервисов
	services, err := sm.fetchServicesHealth()
	if err != nil {
		log.Printf("❌ Failed to fetch services health: %v", err)
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, service := range services {
		sm.processServiceStatus(service)
	}
}

// fetchServicesHealth получает статусы сервисов через API
func (sm *ServiceMonitor) fetchServicesHealth() ([]ServiceHealthResponse, error) {
	// Используем localhost:8080 так как мы внутри auth-service контейнера
	resp, err := http.Get("http://localhost:8080/api/services/health")
	if err != nil {
		return nil, fmt.Errorf("failed to request health endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("health endpoint returned status %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var apiResponse HealthAPIResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return apiResponse.Services, nil
}

// processServiceStatus обрабатывает статус одного сервиса
func (sm *ServiceMonitor) processServiceStatus(service ServiceHealthResponse) {
	previousStatus, exists := sm.previousStates[service.ServiceKey]
	currentStatus := service.Status

	// Обновляем текущее состояние
	sm.previousStates[service.ServiceKey] = currentStatus

	// Если это первая проверка, не отправляем алерт
	if !exists {
		log.Printf("📊 Initial state for %s: %s", service.ServiceName, currentStatus)
		return
	}

	// Проверяем ухудшение состояния
	if sm.isStatusDegraded(previousStatus, currentStatus) {
		sm.handleStatusDegradation(service, previousStatus, currentStatus)
	}

	// Проверяем восстановление
	if sm.isStatusImproved(previousStatus, currentStatus) {
		sm.handleStatusRecovery(service, previousStatus, currentStatus)
	}
}

// isStatusDegraded проверяет ухудшилось ли состояние
func (sm *ServiceMonitor) isStatusDegraded(previous, current string) bool {
	// healthy -> unhealthy или offline
	if previous == "healthy" && (current == "unhealthy" || current == "offline") {
		return true
	}
	// unhealthy -> offline
	if previous == "unhealthy" && current == "offline" {
		return true
	}
	return false
}

// isStatusImproved проверяет улучшилось ли состояние
func (sm *ServiceMonitor) isStatusImproved(previous, current string) bool {
	// offline -> unhealthy или healthy
	if previous == "offline" && (current == "unhealthy" || current == "healthy") {
		return true
	}
	// unhealthy -> healthy
	if previous == "unhealthy" && current == "healthy" {
		return true
	}
	return false
}

// handleStatusDegradation обрабатывает ухудшение состояния
func (sm *ServiceMonitor) handleStatusDegradation(service ServiceHealthResponse, previousStatus, currentStatus string) {
	// Проверяем cooldown
	if !sm.canSendAlert(service.ServiceKey) {
		log.Printf("⏰ Cooldown active for %s, skipping alert", service.ServiceName)
		return
	}

	log.Printf("🚨 Service degradation detected: %s (%s -> %s)", service.ServiceName, previousStatus, currentStatus)

	// Формируем и отправляем алерт с разными форматами для Telegram и Email
	sm.sendDegradationAlert(service.ServiceKey, service, previousStatus, currentStatus)
}

// handleStatusRecovery обрабатывает восстановление сервиса
func (sm *ServiceMonitor) handleStatusRecovery(service ServiceHealthResponse, previousStatus, currentStatus string) {
	log.Printf("✅ Service recovery detected: %s (%s -> %s)", service.ServiceName, previousStatus, currentStatus)

	// Отправляем уведомление о восстановлении (без cooldown)
	sm.sendRecoveryAlert(service, previousStatus, currentStatus)
}

// canSendAlert проверяет можно ли отправить алерт (cooldown)
func (sm *ServiceMonitor) canSendAlert(serviceKey string) bool {
	lastAlertTime, exists := sm.lastAlertTimes[serviceKey]
	if !exists {
		return true
	}

	timeSinceLastAlert := time.Since(lastAlertTime)
	return timeSinceLastAlert >= sm.cooldownPeriod
}

// formatTelegramDegradationAlert форматирует сообщение о проблеме для Telegram
func (sm *ServiceMonitor) formatTelegramDegradationAlert(service ServiceHealthResponse, previousStatus, currentStatus string) string {
	emoji := "⚠️"
	if currentStatus == "offline" {
		emoji = "🔴"
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	return fmt.Sprintf(
		"%s *АЛЕРТ: Проблема с сервисом*\n\n"+
			"📋 *Сервис:* %s\n"+
			"📊 *Статус:* %s → %s\n"+
			"⏰ *Время:* %s\n\n"+
			"_Требуется проверка!_",
		emoji, service.ServiceName, previousStatus, currentStatus, timestamp,
	)
}

// formatEmailDegradationAlert форматирует сообщение о проблеме для Email (без эмодзи)
func (sm *ServiceMonitor) formatEmailDegradationAlert(service ServiceHealthResponse, previousStatus, currentStatus string) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	return fmt.Sprintf(
		`АЛЕРТ: Проблема с сервисом

Уважаемый администратор,

Обнаружена проблема с сервисом в системе мониторинга.

Детали проблемы:
- Сервис: %s
- Изменение статуса: %s -> %s
- Время обнаружения: %s

Рекомендуется немедленно проверить состояние сервиса и принять необходимые меры.

ВАЖНО: Данное уведомление отправлено автоматически системой мониторинга. 
Если проблема критична, обратитесь к системному администратору.

С уважением,
Система мониторинга Golden House

Это автоматическое сообщение, пожалуйста, не отвечайте на него.`,
		service.ServiceName, previousStatus, currentStatus, timestamp,
	)
}

// formatTelegramRecoveryAlert форматирует сообщение о восстановлении для Telegram
func (sm *ServiceMonitor) formatTelegramRecoveryAlert(service ServiceHealthResponse, previousStatus, currentStatus string) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	return fmt.Sprintf(
		"✅ *Сервис восстановлен*\n\n"+
			"📋 *Сервис:* %s\n"+
			"📊 *Статус:* %s → %s\n"+
			"⏰ *Время:* %s\n\n"+
			"_Сервис снова работает нормально_",
		service.ServiceName, previousStatus, currentStatus, timestamp,
	)
}

// formatEmailRecoveryAlert форматирует сообщение о восстановлении для Email (без эмодзи)
func (sm *ServiceMonitor) formatEmailRecoveryAlert(service ServiceHealthResponse, previousStatus, currentStatus string) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	return fmt.Sprintf(
		`Сервис восстановлен

Уважаемый администратор,

Сообщаем о восстановлении работы сервиса.

Детали восстановления:
- Сервис: %s
- Изменение статуса: %s -> %s
- Время восстановления: %s

Сервис снова работает в штатном режиме. Мониторинг продолжается.

С уважением,
Система мониторинга Golden House

Это автоматическое сообщение, пожалуйста, не отвечайте на него.`,
		service.ServiceName, previousStatus, currentStatus, timestamp,
	)
}

// sendDegradationAlert отправляет алерт о проблеме с разными форматами
func (sm *ServiceMonitor) sendDegradationAlert(serviceKey string, service ServiceHealthResponse, previousStatus, currentStatus string) {
	sm.lastAlertTimes[serviceKey] = time.Now()
	
	if !sm.sendNotificationsEnabled {
		log.Printf("ℹ️  Notifications disabled, skipping degradation alert for %s", service.ServiceName)
		return
	}

	// Telegram уведомление с эмодзи
	telegramMessage := sm.formatTelegramDegradationAlert(service, previousStatus, currentStatus)
	telegramNotification := NotificationRequest{
		Type:      "telegram_system",
		Recipient: sm.adminChatID,
		Subject:   "🚨 Проблема с сервисом",
		Content:   telegramMessage,
	}
	sm.sendSingleNotification(telegramNotification, "Telegram")

	// Email уведомление без эмодзи
	emailMessage := sm.formatEmailDegradationAlert(service, previousStatus, currentStatus)
	emailNotification := NotificationRequest{
		Type:      "email",
		Recipient: sm.adminEmail,
		Subject:   "АЛЕРТ: Проблема с сервисом " + service.ServiceName,
		Content:   emailMessage,
	}
	sm.sendSingleNotification(emailNotification, "Email")
}

// sendRecoveryAlert отправляет алерт о восстановлении с разными форматами
func (sm *ServiceMonitor) sendRecoveryAlert(service ServiceHealthResponse, previousStatus, currentStatus string) {
	if !sm.sendNotificationsEnabled {
		log.Printf("ℹ️  Notifications disabled, skipping recovery alert for %s", service.ServiceName)
		return
	}

	// Telegram уведомление с эмодзи
	telegramMessage := sm.formatTelegramRecoveryAlert(service, previousStatus, currentStatus)
	telegramNotification := NotificationRequest{
		Type:      "telegram_system",
		Recipient: sm.adminChatID,
		Subject:   "✅ Сервис восстановлен",
		Content:   telegramMessage,
	}
	sm.sendSingleNotification(telegramNotification, "Telegram")

	// Email уведомление без эмодзи
	emailMessage := sm.formatEmailRecoveryAlert(service, previousStatus, currentStatus)
	emailNotification := NotificationRequest{
		Type:      "email",
		Recipient: sm.adminEmail,
		Subject:   "Сервис восстановлен: " + service.ServiceName,
		Content:   emailMessage,
	}
	sm.sendSingleNotification(emailNotification, "Email")
}



// sendSingleNotification отправляет одно уведомление
func (sm *ServiceMonitor) sendSingleNotification(notification NotificationRequest, notificationType string) {
	jsonData, err := json.Marshal(notification)
	if err != nil {
		log.Printf("❌ Failed to marshal %s notification: %v", notificationType, err)
		return
	}

	url := fmt.Sprintf("%s/api/v1/notifications", sm.notificationURL)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("❌ Failed to send %s notification: %v", notificationType, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("❌ %s notification failed with status %d: %s", notificationType, resp.StatusCode, string(body))
		return
	}

	log.Printf("📤 %s alert sent successfully", notificationType)
}

// sendStartupNotification отправляет уведомление о запуске мониторинга
func (sm *ServiceMonitor) sendStartupNotification() {
	if !sm.sendNotificationsEnabled {
		log.Printf("ℹ️  Notifications disabled, skipping startup notification")
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	// Telegram сообщение с эмодзи
	telegramMessage := fmt.Sprintf(
		"🚀 *Мониторинг запущен*\n\n"+
			"⏰ *Время:* %s\n"+
			"🔍 *Интервал проверки:* %v\n"+
			"⏱️ *Cooldown:* %v\n\n"+
			"_Система мониторинга активна_",
		timestamp, sm.checkInterval, sm.cooldownPeriod,
	)
	
	telegramNotification := NotificationRequest{
		Type:      "telegram_system",
		Recipient: sm.adminChatID,
		Subject:   "🚀 Мониторинг активен",
		Content:   telegramMessage,
	}
	sm.sendSingleNotification(telegramNotification, "Telegram")

	// Email сообщение без эмодзи
	emailMessage := fmt.Sprintf(
		`Система мониторинга запущена

Уважаемый администратор,

Сообщаем о запуске системы мониторинга сервисов Golden House.

Параметры мониторинга:
- Время запуска: %s
- Интервал проверки: %v
- Период охлаждения: %v

Система мониторинга активна и готова к работе. Вы будете получать уведомления о всех изменениях состояния сервисов.

С уважением,
Система мониторинга Golden House

Это автоматическое сообщение, пожалуйста, не отвечайте на него.`,
		timestamp, sm.checkInterval, sm.cooldownPeriod,
	)
	
	emailNotification := NotificationRequest{
		Type:      "email",
		Recipient: sm.adminEmail,
		Subject:   "Система мониторинга запущена",
		Content:   emailMessage,
	}
	sm.sendSingleNotification(emailNotification, "Email")
}
