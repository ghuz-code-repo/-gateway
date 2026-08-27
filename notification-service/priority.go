package main

// priority.go — приоритетная полоса очереди.
//
// Очередь канала упорядочена по приоритету, потом по времени создания. Нужно это
// из-за жёсткой квоты почты: при 15 письмах в минуту массовая рассылка на сотню
// адресов занимает семь минут, и письмо со сбросом пароля, попавшее в очередь
// следом, все семь минут ждало бы своей очереди.
//
// Приоритет назначает сам notification-service по отправителю, а не запрос:
//   - потолок сервиса задаётся в SERVICE_PRIORITIES и является его приоритетом
//     по умолчанию — вызывающему не нужно ничего менять в своём коде;
//   - запрос может попросить значение НЕ ВЫШЕ потолка своего сервиса. Так
//     отправитель с приоритетной полосой (auth-service) может сам опустить свои
//     массовые рассылки вниз, а сервис без полосы не может в неё пролезть.

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// Уровни приоритета. Значения произвольные, важен только их порядок.
const (
	priorityBulk = 0   // массовые рассылки, отчёты, импорт — ждут своей очереди
	priorityHigh = 100 // то, чего пользователь ждёт прямо сейчас, и алерты безопасности
)

// defaultServicePriorities — потолки по умолчанию, если SERVICE_PRIORITIES не задан.
//
// auth-service шлёт подтверждение входа и сброс пароля: пользователь стоит перед
// экраном и ждёт письмо, поэтому его сообщения идут первыми.
func defaultServicePriorities() map[string]int {
	return map[string]int{
		"auth-service": priorityHigh,
	}
}

// loadServicePriorities разбирает SERVICE_PRIORITIES вида "auth-service=100,monitoring-service=50".
func loadServicePriorities() map[string]int {
	raw := strings.TrimSpace(os.Getenv("SERVICE_PRIORITIES"))
	if raw == "" {
		return defaultServicePriorities()
	}

	priorities := make(map[string]int)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			log.Printf("⚠️ SERVICE_PRIORITIES: пропущена некорректная запись %q (ожидается name=число)", pair)
			continue
		}
		value, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || value < 0 {
			log.Printf("⚠️ SERVICE_PRIORITIES: у %q некорректный приоритет %q (ожидается неотрицательное число)", parts[0], parts[1])
			continue
		}
		priorities[strings.TrimSpace(parts[0])] = value
	}

	if len(priorities) == 0 {
		return defaultServicePriorities()
	}
	return priorities
}

// parseServicePriorities разбирает пер-канальные потолки приоритета.
// nil — канал своих потолков не задаёт, действуют общие из SERVICE_PRIORITIES.
func parseServicePriorities(cfg ChannelConfig) map[string]int {
	raw := strings.TrimSpace(cfg.ServicePriorities)
	if raw == "" || raw == "{}" {
		return nil
	}

	var byService map[string]int
	if err := json.Unmarshal([]byte(raw), &byService); err != nil {
		// Игнорируем битое значение целиком: частично разобранные потолки хуже,
		// чем общие — приоритет молча достался бы не тем отправителям
		log.Printf("⚠️ Канал %s: service_priorities не разобран (%v), действуют общие потолки", cfg.Channel, err)
		return nil
	}

	out := make(map[string]int, len(byService))
	for service, priority := range byService {
		service = strings.TrimSpace(service)
		if service == "" {
			continue
		}
		if priority < priorityBulk {
			priority = priorityBulk
		}
		out[service] = priority
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// validateServicePriorities отвергает некорректные потолки до записи в БД:
// молча проигнорированное значение означало бы приоритет не у того отправителя.
func validateServicePriorities(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" {
		return nil
	}

	var byService map[string]int
	if err := json.Unmarshal([]byte(raw), &byService); err != nil {
		return fmt.Errorf("поле service_priorities: ожидается объект {\"сервис\": число} (%v)", err)
	}
	for service, priority := range byService {
		if strings.TrimSpace(service) == "" {
			return fmt.Errorf("поле service_priorities: пустое имя сервиса")
		}
		if priority < 0 {
			return fmt.Errorf("поле service_priorities: у %q отрицательный приоритет %d", service, priority)
		}
	}
	return nil
}

// logPriorityConfig печатает действующие полосы и предупреждает, если приоритетный
// сервис не сможет ими воспользоваться.
//
// Приоритет считается по имени сервиса, а имя берётся из его персонального ключа
// в SERVICE_API_KEYS. Отправитель, пришедший с общим легаси-ключом, неотличим от
// остальных легаси-отправителей и приоритета не получит — молча, если не сказать.
func (ns *NotificationService) logPriorityConfig() {
	if len(ns.priorities) == 0 {
		log.Printf("🎚️ Приоритетные полосы не настроены: очередь строго по времени создания")
		return
	}

	registered := make(map[string]bool)
	for _, name := range loadServiceAPIKeys() {
		registered[name] = true
	}

	for service, priority := range ns.priorities {
		if registered[service] {
			log.Printf("🎚️ Общий потолок приоритета %d: %s", priority, service)
			continue
		}
		log.Printf("⚠️ Приоритет %d назначен сервису %s, но его персонального ключа нет в SERVICE_API_KEYS — "+
			"с общим INTERNAL_API_KEY он неотличим от остальных и приоритета НЕ получит",
			priority, service)
	}

	// Пер-канальные потолки важнее общих, поэтому их видно отдельной строкой:
	// иначе расхождение «в SERVICE_PRIORITIES 100, а письма идут последними»
	// пришлось бы искать в таблице
	for _, channel := range ns.channelOrder() {
		for service, ceiling := range ns.channelServicePriorities(channel) {
			log.Printf("🎚️ Канал %s: потолок %d для %s (переопределяет общий)", channel, ceiling, service)
		}
	}
}

// priorityCeiling — потолок приоритета отправителя на конкретном канале.
//
// Потолок канала важнее общего: цена задержки у каналов разная. Подтверждение
// входа в telegram уходит мгновенно и в полосе не нуждается, а то же письмо
// стоит в очереди почты минутами. Явно заданный на канале ноль выключает
// приоритет отправителя — именно поэтому проверяется наличие ключа, а не
// ненулевое значение.
func (ns *NotificationService) priorityCeiling(channel, serviceName string) int {
	if byService := ns.channelServicePriorities(channel); byService != nil {
		if ceiling, ok := byService[serviceName]; ok {
			return ceiling
		}
	}
	return ns.priorities[serviceName]
}

// resolvePriority вычисляет приоритет уведомления.
//
// Потолок сервиса — это и его значение по умолчанию: сервису с приоритетной
// полосой ничего не нужно передавать, чтобы ею пользоваться. Запрошенное значение
// принимается, только если оно не выше потолка — иначе любой отправитель поднял бы
// себя в начало очереди, и полоса перестала бы что-либо значить.
func (ns *NotificationService) resolvePriority(channel, serviceName string, requested *int) int {
	ceiling := ns.priorityCeiling(channel, serviceName)

	if requested == nil {
		return ceiling
	}
	if *requested < priorityBulk {
		return priorityBulk
	}
	if *requested > ceiling {
		return ceiling
	}
	return *requested
}
