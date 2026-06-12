package main

// security.go — детектирование аномалий в межсервисных запросах (Plan D, ступень 1).
//
// Градуированный ответ вместо жёсткой авто-блокировки:
//   1. Превышение лимита запросов от сервиса      -> rate-limit (HTTP 429) + алерт админу
//   2. Серия запросов с невалидным X-API-Key с IP -> временный бан IP (401) + алерт админу
//
// Сервис НЕ отключается от сети автоматически: ложное срабатывание (массовая
// рассылка после простоя, ретраи, рассинхрон ключей при деплое) не должно
// превращаться в полный отказ. Для реального карантина — ручной скрипт
// scripts/quarantine.sh (см. алерт-письмо).

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

type guardEntry struct {
	count          int
	windowStart    time.Time
	throttledUntil time.Time
	lastAlert      time.Time
}

// ServiceGuard отслеживает частоту запросов per-service и невалидные ключи per-IP.
type ServiceGuard struct {
	mu           sync.Mutex
	services     map[string]*guardEntry // ключ: имя сервиса
	invalidByIP  map[string]*guardEntry // ключ: IP источника
	tripwireByIP map[string]*guardEntry // ключ: IP, тронувший ханипот

	window        time.Duration // окно подсчёта
	maxRequests   int           // лимит запросов от одного сервиса за окно
	maxInvalid    int           // лимит невалидных ключей с одного IP за окно
	throttle      time.Duration // длительность rate-limit после превышения
	alertCooldown time.Duration // не слать алерты по одному источнику чаще этого

	alertFn func(subject, content string) // отправка алерта админу
}

// NewServiceGuard создаёт guard с настройками из окружения.
func NewServiceGuard(alertFn func(subject, content string)) *ServiceGuard {
	g := &ServiceGuard{
		services:      make(map[string]*guardEntry),
		invalidByIP:   make(map[string]*guardEntry),
		tripwireByIP:  make(map[string]*guardEntry),
		window:        time.Duration(getEnvAsInt("GUARD_WINDOW_SECONDS", 60)) * time.Second,
		maxRequests:   getEnvAsInt("GUARD_MAX_REQUESTS_PER_WINDOW", 600),
		maxInvalid:    getEnvAsInt("GUARD_MAX_INVALID_KEYS_PER_WINDOW", 10),
		throttle:      time.Duration(getEnvAsInt("GUARD_THROTTLE_SECONDS", 300)) * time.Second,
		alertCooldown: time.Duration(getEnvAsInt("GUARD_ALERT_COOLDOWN_SECONDS", 900)) * time.Second,
		alertFn:       alertFn,
	}
	log.Printf("🛡️ Service guard: window=%s, max_requests=%d, max_invalid_keys=%d, throttle=%s",
		g.window, g.maxRequests, g.maxInvalid, g.throttle)
	return g
}

// Allow регистрирует запрос от сервиса. false => сервис задросселен (HTTP 429).
func (g *ServiceGuard) Allow(service string) bool {
	now := time.Now()

	g.mu.Lock()
	e, ok := g.services[service]
	if !ok {
		e = &guardEntry{windowStart: now}
		g.services[service] = e
	}

	// Действующий rate-limit
	if now.Before(e.throttledUntil) {
		g.mu.Unlock()
		return false
	}

	// Скользящее окно (сброс по истечении)
	if now.Sub(e.windowStart) > g.window {
		e.count = 0
		e.windowStart = now
	}
	e.count++

	if e.count > g.maxRequests {
		e.throttledUntil = now.Add(g.throttle)
		needAlert := now.Sub(e.lastAlert) > g.alertCooldown
		if needAlert {
			e.lastAlert = now
		}
		count := e.count
		g.mu.Unlock()

		log.Printf("🛡️ GUARD THROTTLE: service=%s, %d req in %s (limit %d) — rate-limited for %s",
			service, count, g.window, g.maxRequests, g.throttle)
		if needAlert {
			g.alert(
				fmt.Sprintf("🛡️ Rate limit: подозрительная активность сервиса %s", service),
				fmt.Sprintf(
					"Сервис: %s\nЗапросов за окно %s: %d (лимит %d)\nДействие: запросы сервиса отклоняются (HTTP 429) на %s.\n\n"+
						"Возможные причины: компрометация контейнера, цикл ретраев, легитимная массовая рассылка.\n"+
						"Проверьте логи: docker logs %s\n"+
						"Если подтверждена компрометация — карантин: ./scripts/quarantine.sh %s",
					service, g.window, count, g.maxRequests, g.throttle, service, service),
			)
		}
		return false
	}

	g.mu.Unlock()
	return true
}

// RecordInvalidKey регистрирует запрос с невалидным X-API-Key.
// false => IP временно забанен, отвечать без обработки.
func (g *ServiceGuard) RecordInvalidKey(ip, path string) bool {
	now := time.Now()

	g.mu.Lock()
	e, ok := g.invalidByIP[ip]
	if !ok {
		e = &guardEntry{windowStart: now}
		g.invalidByIP[ip] = e
	}

	if now.Before(e.throttledUntil) {
		g.mu.Unlock()
		return false
	}

	if now.Sub(e.windowStart) > g.window {
		e.count = 0
		e.windowStart = now
	}
	e.count++

	if e.count > g.maxInvalid {
		e.throttledUntil = now.Add(g.throttle)
		needAlert := now.Sub(e.lastAlert) > g.alertCooldown
		if needAlert {
			e.lastAlert = now
		}
		count := e.count
		g.mu.Unlock()

		log.Printf("🛡️ GUARD BAN: ip=%s, %d invalid API keys in %s (limit %d) — banned for %s (path=%s)",
			ip, count, g.window, g.maxInvalid, g.throttle, path)
		if needAlert {
			g.alert(
				"🛡️ Подбор API-ключа в notification-service",
				fmt.Sprintf(
					"IP источника: %s\nНевалидных X-API-Key за окно %s: %d (лимит %d)\nПоследний путь: %s\nДействие: IP временно заблокирован на %s.\n\n"+
						"Это может означать компрометацию контейнера в service_network или рассинхрон ключей после деплоя.\n"+
						"Определить контейнер по IP: docker network inspect service_network\n"+
						"Если подтверждена компрометация — карантин: ./scripts/quarantine.sh <container>",
					ip, g.window, count, g.maxInvalid, path, g.throttle),
			)
		}
		return false
	}

	g.mu.Unlock()
	return true
}

// Tripwire регистрирует обращение к ханипот-эндпоинту — бинарный индикатор
// компрометации (легитимного трафика на эти пути не существует).
//
// Строка "GUARD TRIPWIRE:" пишется в лог ВСЕГДА (её ловит guard-watchdog и
// автоматически карантинит контейнер-источник); алерт админу — с кулдауном.
func (g *ServiceGuard) Tripwire(ip, path string) {
	log.Printf("🪤 GUARD TRIPWIRE: ip=%s path=%s — обращение к ханипот-эндпоинту", ip, path)

	now := time.Now()
	g.mu.Lock()
	e, ok := g.tripwireByIP[ip]
	if !ok {
		e = &guardEntry{}
		g.tripwireByIP[ip] = e
	}
	needAlert := now.Sub(e.lastAlert) > g.alertCooldown
	if needAlert {
		e.lastAlert = now
	}
	g.mu.Unlock()

	if needAlert {
		g.alert(
			"🪤 Tripwire: обращение к ханипоту в notification-service",
			fmt.Sprintf(
				"IP источника: %s\nПуть: %s\n\n"+
					"Это бинарный индикатор компрометации: легитимные сервисы на этот путь не ходят НИКОГДА.\n"+
					"Если guard-watchdog запущен, контейнер-источник уже карантинится автоматически (ждите второй алерт).\n"+
					"Определить контейнер по IP: docker network inspect service_network\n"+
					"Ручной карантин: ./scripts/quarantine.sh <container>",
				ip, path),
		)
	}
}

func (g *ServiceGuard) alert(subject, content string) {
	if g.alertFn == nil {
		return
	}
	// Никогда не блокируем и не роняем обработку запроса из-за алерта
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("❌ Security alert panic recovered: %v", r)
			}
		}()
		g.alertFn(subject, content)
	}()
}

// sendSecurityAlert отправляет алерт безопасности админу (email + telegram_system),
// используя собственный конвейер уведомлений сервиса (без HTTP-запросов к самому себе).
func (ns *NotificationService) sendSecurityAlert(subject, content string) {
	config := ns.getConfigFromDB()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	body := fmt.Sprintf("%s\n\nВремя: %s\nИсточник: notification-service security guard", content, timestamp)

	var notifications []Notification

	emailRecipient := config.SystemEmailRecipient
	if emailRecipient == "" {
		emailRecipient = os.Getenv("SECURITY_ALERT_EMAIL")
	}
	if config.SendSystemEmailNotifications && emailRecipient != "" {
		notifications = append(notifications, Notification{
			Type:      NotificationTypeEmail,
			Recipient: emailRecipient,
			Subject:   subject,
			Content:   body,
		})
	}

	telegramRecipient := config.SystemTelegramChatID
	if telegramRecipient == "" {
		telegramRecipient = config.SystemTelegramUsername
	}
	if config.SendSystemTelegramNotifications && telegramRecipient != "" {
		notifications = append(notifications, Notification{
			Type:      NotificationTypeTelegramSystem,
			Recipient: telegramRecipient,
			Subject:   subject,
			Content:   body,
		})
	}

	if len(notifications) == 0 {
		log.Printf("⚠️ Security alert NOT delivered (no recipients configured): %s", subject)
		return
	}

	for i := range notifications {
		n := &notifications[i]
		if err := ns.db.Create(n).Error; err != nil {
			log.Printf("❌ Failed to persist security alert notification: %v", err)
			continue
		}
		ns.wg.Add(1)
		go func(n *Notification) {
			defer ns.wg.Done()
			ns.workerSem <- struct{}{}
			defer func() { <-ns.workerSem }()
			ns.processNotification(n)
		}(n)
	}
	log.Printf("🛡️ Security alert queued (%d notification(s)): %s", len(notifications), subject)
}
