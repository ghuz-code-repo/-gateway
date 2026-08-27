package main

// transports.go — канал доставки как подключаемый модуль.
//
// Транспорт отвечает за три вещи, которые у каналов расходятся и раньше были
// размазаны по общему коду:
//   1. как отправить (SMTP / HTTP к notification-bot / ...)
//   2. как классифицировать ошибку — коды SMTP и описания Telegram не пересекаются,
//      а общий список подстрок ошибался в обе стороны
//   3. по какому ключу и какому классу считать лимит получателя
//
// Добавление канала: реализовать Transport, зарегистрировать в buildTransports,
// добавить строку в defaultChannelConfigs. Диспетчер, лимитер, API конфигов и
// страница настроек новый канал подхватывают без правок.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Имена каналов. Канал — единица очереди, лимита и конфига; типов уведомлений
// в канале может быть несколько (telegram и telegram_system делят одного бота,
// а значит и лимиты Telegram Bot API).
const (
	channelEmail    = "email"
	channelTelegram = "telegram"
	channelSMS      = "sms"
	channelPush     = "push"
)

// Классы получателей. Транспорт возвращает класс, лимитер берёт для него
// свой набор ограничений из recipient_class_limits.
const (
	recipientClassDefault = ""      // личный получатель
	recipientClassGroup   = "group" // групповой чат: у Telegram отдельный, более строгий лимит
)

// sendOutcome — разбор ошибки отправки, по которому диспетчер решает судьбу уведомления.
type sendOutcome struct {
	Permanent   bool          // повторять бессмысленно (нет адресата, бот заблокирован)
	RateLimited bool          // провайдер попросил снизить темп
	RetryAfter  time.Duration // сколько ждать, если провайдер назвал срок
}

// Transport — канал доставки.
type Transport interface {
	// Channel — имя канала (ключ конфига, очереди и лимитера).
	Channel() string

	// Types — типы уведомлений, которые обслуживает канал.
	Types() []NotificationType

	// LimiterKey — по какому значению считать лимит на получателя.
	// Пустая строка => лимит на получателя для этого уведомления не применяется.
	LimiterKey(n *Notification) string

	// RecipientClass — класс получателя для выбора набора лимитов.
	RecipientClass(n *Notification) string

	// Send выполняет одну попытку отправки. Отменяется по ctx.
	Send(ctx context.Context, n *Notification, cfg ChannelConfig) error

	// Classify разбирает ошибку Send.
	Classify(err error) sendOutcome
}

// buildTransports собирает реестр каналов сервиса.
func buildTransports(ns *NotificationService) []Transport {
	return []Transport{
		&emailTransport{ns: ns},
		&telegramTransport{ns: ns},
		&smsTransport{ns: ns},
		&pushTransport{ns: ns},
	}
}

// --- email ---

type emailTransport struct{ ns *NotificationService }

func (t *emailTransport) Channel() string { return channelEmail }

func (t *emailTransport) Types() []NotificationType {
	return []NotificationType{NotificationTypeEmail}
}

// Лимит почты задан администраторами на весь сервер, а не на ящик: считаем
// только канальный темп, ключа получателя нет.
func (t *emailTransport) LimiterKey(n *Notification) string { return "" }

func (t *emailTransport) RecipientClass(n *Notification) string { return recipientClassDefault }

func (t *emailTransport) Send(ctx context.Context, n *Notification, cfg ChannelConfig) error {
	return t.ns.sendEmail(ctx, n, cfg)
}

func (t *emailTransport) Classify(err error) sendOutcome {
	if err == nil {
		return sendOutcome{}
	}
	errStr := strings.ToLower(err.Error())

	// Постоянные отказы SMTP: адресата не существует, письмо отвергнуто.
	permanent := []string{
		"no such user",
		"user unknown",
		"recipient address rejected",
		"invalid recipient",
		"550", // mailbox unavailable
		"551", // user not local
		"553", // mailbox name not allowed
		"554", // transaction failed
	}
	for _, p := range permanent {
		if strings.Contains(errStr, p) {
			return sendOutcome{Permanent: true}
		}
	}

	// Временные отказы и ограничение темпа: сервер просит повторить позже.
	rateLimited := []string{
		"421", // service not available, closing transmission channel
		"450", // mailbox unavailable (temporary)
		"451", // local error in processing
		"452", // insufficient system storage
		"throttling",
		"exceeded sending limits",
		"rate limit",
		"too many",
		"try again later",
		"temporarily deferred",
		"mailbox full",
	}
	for _, r := range rateLimited {
		if strings.Contains(errStr, r) {
			return sendOutcome{RateLimited: true}
		}
	}

	return sendOutcome{}
}

// --- telegram ---

type telegramTransport struct{ ns *NotificationService }

func (t *telegramTransport) Channel() string { return channelTelegram }

// telegram и telegram_system идут через одного бота и делят его лимиты,
// поэтому это один канал с одной очередью.
func (t *telegramTransport) Types() []NotificationType {
	return []NotificationType{NotificationTypeTelegram, NotificationTypeTelegramSystem}
}

// telegramChatKey возвращает chat_id, по которому Telegram считает лимит чата.
// Для системных алертов адресат берётся из конфига, а не из строки уведомления.
func (t *telegramTransport) telegramChatKey(n *Notification) string {
	if n.Type == NotificationTypeTelegramSystem {
		if chatID := strings.TrimSpace(t.ns.getConfigFromDB().SystemTelegramChatID); chatID != "" {
			return chatID
		}
	}
	return strings.TrimSpace(n.Recipient)
}

func (t *telegramTransport) LimiterKey(n *Notification) string {
	return t.telegramChatKey(n)
}

// RecipientClass различает личный чат и группу: Telegram ограничивает группы
// строже (20 сообщений в минуту против 1 в секунду в личный чат).
// Признак группы — отрицательный chat_id.
func (t *telegramTransport) RecipientClass(n *Notification) string {
	chatID, err := strconv.ParseInt(t.telegramChatKey(n), 10, 64)
	if err == nil && chatID < 0 {
		return recipientClassGroup
	}
	return recipientClassDefault
}

func (t *telegramTransport) Send(ctx context.Context, n *Notification, cfg ChannelConfig) error {
	return t.ns.sendTelegram(ctx, n, n.Type == NotificationTypeTelegramSystem, cfg)
}

func (t *telegramTransport) Classify(err error) sendOutcome {
	if err == nil {
		return sendOutcome{}
	}
	errStr := strings.ToLower(err.Error())

	// Ограничение темпа: notification-bot прокидывает retry_after из ответа
	// Telegram (см. telegramRetryAfter), поэтому ждём ровно столько, сколько
	// просит сам Telegram, а не фиксированную паузу.
	if retryAfter, ok := parseTelegramRetryAfter(err); ok {
		return sendOutcome{RateLimited: true, RetryAfter: retryAfter}
	}
	for _, r := range []string{"429", "too many requests", "retry after", "rate limit"} {
		if strings.Contains(errStr, r) {
			return sendOutcome{RateLimited: true}
		}
	}

	// Постоянные отказы: адресата нет, бот заблокирован, привязка мертва.
	permanent := []string{
		"некорректный chat_id",
		"не найден или не привязал",
		"chat not found",
		"bot was blocked",
		"user is deactivated",
		"peer_id_invalid",
		"bot can't initiate conversation",
	}
	for _, p := range permanent {
		if strings.Contains(errStr, p) {
			return sendOutcome{Permanent: true}
		}
	}

	return sendOutcome{}
}

// --- sms (заглушка) ---

type smsTransport struct{ ns *NotificationService }

func (t *smsTransport) Channel() string { return channelSMS }

func (t *smsTransport) Types() []NotificationType { return []NotificationType{NotificationTypeSMS} }

func (t *smsTransport) LimiterKey(n *Notification) string { return strings.TrimSpace(n.Recipient) }

func (t *smsTransport) RecipientClass(n *Notification) string { return recipientClassDefault }

func (t *smsTransport) Send(ctx context.Context, n *Notification, cfg ChannelConfig) error {
	return fmt.Errorf("отправка SMS не реализована")
}

// Канал не реализован: повторы ничего не изменят.
func (t *smsTransport) Classify(err error) sendOutcome {
	return sendOutcome{Permanent: true}
}

// --- push (заглушка) ---

type pushTransport struct{ ns *NotificationService }

func (t *pushTransport) Channel() string { return channelPush }

func (t *pushTransport) Types() []NotificationType { return []NotificationType{NotificationTypePush} }

func (t *pushTransport) LimiterKey(n *Notification) string { return strings.TrimSpace(n.Recipient) }

func (t *pushTransport) RecipientClass(n *Notification) string { return recipientClassDefault }

func (t *pushTransport) Send(ctx context.Context, n *Notification, cfg ChannelConfig) error {
	return fmt.Errorf("отправка push-уведомлений не реализована")
}

func (t *pushTransport) Classify(err error) sendOutcome {
	return sendOutcome{Permanent: true}
}
