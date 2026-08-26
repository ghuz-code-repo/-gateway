package models

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Каналы доставки, для которых умеем резолвить адрес получателя
const (
	RecipientChannelTelegram = "telegram"
	RecipientChannelEmail    = "email"
	RecipientChannelSMS      = "sms"
)

// Причины, по которым логин не превратился в адрес доставки.
// Коды машинные: по ним вызывающий сервис решает, делать ли fallback на другой канал.
const (
	RecipientReasonUserNotFound     = "user_not_found"
	RecipientReasonUserBanned       = "user_banned"
	RecipientReasonNoServiceAccess  = "no_service_access"
	RecipientReasonChannelNotLinked = "channel_not_linked"
	RecipientReasonNoAddress        = "no_address"
	RecipientReasonUnknownChannel   = "unknown_channel"
)

// RecipientResolution — результат резолва одного логина в адрес доставки
type RecipientResolution struct {
	Found            bool   `json:"found"`
	Address          string `json:"address,omitempty"`
	Reason           string `json:"reason,omitempty"`
	HasServiceAccess bool   `json:"has_service_access"`
}

// IsValidRecipientChannel сообщает, умеем ли резолвить адрес для этого канала
func IsValidRecipientChannel(channel string) bool {
	switch channel {
	case RecipientChannelTelegram, RecipientChannelEmail, RecipientChannelSMS:
		return true
	}
	return false
}

// recipientAddress достаёт адрес доставки пользователя для канала.
// Второе возвращаемое значение — причина отказа (пусто, если адрес есть).
func recipientAddress(u User, channel string) (string, string) {
	switch channel {
	case RecipientChannelTelegram:
		if u.TelegramChatID == 0 {
			return "", RecipientReasonChannelNotLinked
		}
		return strconv.FormatInt(u.TelegramChatID, 10), ""
	case RecipientChannelEmail:
		if strings.TrimSpace(u.Email) == "" {
			return "", RecipientReasonNoAddress
		}
		return strings.TrimSpace(u.Email), ""
	case RecipientChannelSMS:
		if strings.TrimSpace(u.Phone) == "" {
			return "", RecipientReasonNoAddress
		}
		return strings.TrimSpace(u.Phone), ""
	}
	return "", RecipientReasonUnknownChannel
}

// ResolveRecipients резолвит логины портала в адреса доставки для указанного канала.
//
// Матч идёт строго по username (на нём unique index): email и telegram_username в
// качестве идентификатора не годятся — email не уникален как ключ адресации, а
// telegram-ник пользователь меняет в один клик.
//
// Признак доступа вызывающего сервиса к пользователю возвращается отдельным полем
// HasServiceAccess: политику (только наблюдение или блокировка отправки) применяет
// хендлер, а не модель. serviceKey == "" => проверка доступа не выполняется.
func ResolveRecipients(serviceKey, channel string, logins []string) (map[string]RecipientResolution, error) {
	results := make(map[string]RecipientResolution, len(logins))

	if !IsValidRecipientChannel(channel) {
		for _, raw := range logins {
			results[raw] = RecipientResolution{Reason: RecipientReasonUnknownChannel}
		}
		return results, nil
	}

	// Нормализация и дедуп; ответ отдаём по исходным ключам запроса
	byLogin := make(map[string][]string, len(logins))
	uniq := make([]string, 0, len(logins))
	for _, raw := range logins {
		login := strings.TrimSpace(raw)
		if login == "" {
			results[raw] = RecipientResolution{Reason: RecipientReasonUserNotFound}
			continue
		}
		if _, seen := byLogin[login]; !seen {
			uniq = append(uniq, login)
		}
		byLogin[login] = append(byLogin[login], raw)
	}
	if len(uniq) == 0 {
		return results, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultDBTimeout)
	defer cancel()

	// Тянем только поля адресации — документы пользователей тяжёлые (documents, roles)
	projection := options.Find().SetProjection(bson.M{
		"username":         1,
		"email":            1,
		"phone":            1,
		"telegram_chat_id": 1,
		"is_banned":        1,
	})

	cursor, err := usersCol.Find(ctx, bson.M{"username": bson.M{"$in": uniq}}, projection)
	if err != nil {
		return nil, fmt.Errorf("recipient lookup failed: %v", err)
	}
	defer cursor.Close(ctx)

	var users []User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, fmt.Errorf("recipient decode failed: %v", err)
	}

	found := make(map[string]User, len(users))
	userIDs := make([]primitive.ObjectID, 0, len(users))
	for _, u := range users {
		found[u.Username] = u
		userIDs = append(userIDs, u.ID)
	}

	// Доступ к сервису — одним запросом на всю пачку (ADR-001, user_service_roles)
	checkAccess := serviceKey != ""
	access := make(map[primitive.ObjectID]bool, len(userIDs))
	if checkAccess && len(userIDs) > 0 {
		roles, rerr := GetUserServiceRolesByUserIDs(userIDs, serviceKey)
		if rerr != nil {
			return nil, fmt.Errorf("service access lookup failed: %v", rerr)
		}
		for id, list := range roles {
			for _, r := range list {
				if r.IsActive {
					access[id] = true
					break
				}
			}
		}
	}

	for _, login := range uniq {
		var res RecipientResolution

		u, ok := found[login]
		switch {
		case !ok:
			res = RecipientResolution{Reason: RecipientReasonUserNotFound}
		case u.IsBanned:
			res = RecipientResolution{Reason: RecipientReasonUserBanned}
		default:
			res.HasServiceAccess = !checkAccess || access[u.ID]
			addr, reason := recipientAddress(u, channel)
			if reason != "" {
				res.Reason = reason
			} else {
				res.Found = true
				res.Address = addr
			}
		}

		for _, original := range byLogin[login] {
			results[original] = res
		}
	}

	return results, nil
}
