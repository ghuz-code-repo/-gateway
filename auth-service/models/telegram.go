package models

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// TelegramLoginMaxRejects — после стольких отклонений вход через Telegram
// замораживается до следующего успешного входа по логину и паролю
const TelegramLoginMaxRejects = 3

// SendTelegramViaBot is set from main package (telegram_bot_client.go) to send
// messages through the notification-bot service, mirroring SendEmailNotificationViaService
var SendTelegramViaBot func(chatID int64, text string, buttons [][]TelegramButton) error

// TelegramButton is a single inline keyboard button forwarded to notification-bot
type TelegramButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// TelegramLinkToken is a one-time token for linking a Telegram account,
// delivered to the user by email as a https://t.me/<bot>?start=<token> deep link
type TelegramLinkToken struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	UserID            primitive.ObjectID `bson:"user_id" json:"user_id"`
	RequestedUsername string             `bson:"requested_username" json:"requested_username"` // введённый в профиле tg username
	Token             string             `bson:"token" json:"token"`
	ExpiresAt         time.Time          `bson:"expires_at" json:"expires_at"`
	CreatedAt         time.Time          `bson:"created_at" json:"created_at"`
}

// TelegramLoginRequest is a pending "login via Telegram" confirmation
type TelegramLoginRequest struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	RequestID string             `bson:"request_id" json:"request_id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id"`
	Status    string             `bson:"status" json:"status"` // pending | approved | rejected
	Consumed  bool               `bson:"consumed" json:"consumed"`
	IP        string             `bson:"ip" json:"ip"`
	UserAgent string             `bson:"user_agent" json:"user_agent"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expires_at"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

func getTelegramLinkTokensCollection() *mongo.Collection {
	if db == nil {
		log.Fatal("Database connection not initialized")
	}
	return db.Collection("telegram_link_tokens")
}

func getTelegramLoginRequestsCollection() *mongo.Collection {
	if db == nil {
		log.Fatal("Database connection not initialized")
	}
	return db.Collection("telegram_login_requests")
}

// NormalizeTelegramUsername strips @, t.me/ prefixes and lowercases the username
func NormalizeTelegramUsername(username string) string {
	username = strings.TrimSpace(username)
	username = strings.TrimPrefix(username, "https://t.me/")
	username = strings.TrimPrefix(username, "t.me/")
	username = strings.TrimPrefix(username, "@")
	return strings.ToLower(username)
}

// generateRandomHex returns a cryptographically random hex string of n bytes (2n chars)
func generateRandomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", buf), nil
}

// CreateTelegramLinkToken creates a one-time Telegram link token for the user.
// Any previous tokens of the user are invalidated.
// Token is 48 hex chars — fits the 64-char limit of a /start deep-link payload.
func CreateTelegramLinkToken(userID primitive.ObjectID, tgUsername string) (*TelegramLinkToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBTimeout)
	defer cancel()

	tokensCol := getTelegramLinkTokensCollection()
	if _, err := tokensCol.DeleteMany(ctx, bson.M{"user_id": userID}); err != nil {
		log.Printf("Warning: Failed to delete existing telegram link tokens for user %s: %v", userID.Hex(), err)
	}

	token, err := generateRandomHex(24)
	if err != nil {
		return nil, err
	}

	linkToken := &TelegramLinkToken{
		UserID:            userID,
		RequestedUsername: NormalizeTelegramUsername(tgUsername),
		Token:             token,
		ExpiresAt:         time.Now().Add(15 * time.Minute),
		CreatedAt:         time.Now(),
	}

	result, err := tokensCol.InsertOne(ctx, linkToken)
	if err != nil {
		return nil, err
	}
	linkToken.ID = result.InsertedID.(primitive.ObjectID)
	return linkToken, nil
}

// ConfirmTelegramLink completes the account link when the bot receives /start <token>.
// actualUsername is the username reported by Telegram (authoritative over the requested one).
func ConfirmTelegramLink(token string, chatID int64, actualUsername string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBTimeout)
	defer cancel()

	var linkToken TelegramLinkToken
	err := getTelegramLinkTokensCollection().FindOne(ctx, bson.M{
		"token":      token,
		"expires_at": bson.M{"$gt": time.Now()},
	}).Decode(&linkToken)
	if err != nil {
		return nil, fmt.Errorf("ссылка привязки недействительна или истекла. Запросите новую в личном кабинете")
	}

	// Chat must not be linked to a different account
	var existing User
	err = usersCol.FindOne(ctx, bson.M{
		"telegram_chat_id": chatID,
		"_id":              bson.M{"$ne": linkToken.UserID},
	}).Decode(&existing)
	if err == nil {
		return nil, fmt.Errorf("этот Telegram уже привязан к другому аккаунту (%s). Сначала отвяжите его в личном кабинете того аккаунта", existing.Username)
	}

	tgUsername := NormalizeTelegramUsername(actualUsername)
	if tgUsername == "" {
		tgUsername = linkToken.RequestedUsername
	}

	now := time.Now()
	_, err = usersCol.UpdateOne(ctx, bson.M{"_id": linkToken.UserID}, bson.M{
		"$set": bson.M{
			"telegram_chat_id":       chatID,
			"telegram_username":      tgUsername,
			"telegram_linked_at":     now,
			"telegram_login_rejects": 0,
			"telegram_login_frozen":  false,
			"updated_at":             now,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("не удалось сохранить привязку: %v", err)
	}

	// One-time token: remove all link tokens of the user
	if _, err := getTelegramLinkTokensCollection().DeleteMany(ctx, bson.M{"user_id": linkToken.UserID}); err != nil {
		log.Printf("Warning: Failed to clean up telegram link tokens: %v", err)
	}

	user, err := GetUserByID(linkToken.UserID.Hex())
	if err != nil {
		return nil, err
	}
	log.Printf("Telegram linked: user %s -> chat %d (@%s)", user.Username, chatID, tgUsername)
	return user, nil
}

// UnlinkTelegram removes the Telegram link from the user account
func UnlinkTelegram(userID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBTimeout)
	defer cancel()

	_, err := usersCol.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{
		"$unset": bson.M{
			"telegram_chat_id":       "",
			"telegram_username":      "",
			"telegram_linked_at":     "",
			"telegram_login_rejects": "",
			"telegram_login_frozen":  "",
		},
		"$set": bson.M{"updated_at": time.Now()},
	})
	return err
}

// GetUserByLoginIdentifier finds a user by telegram username, email or login
func GetUserByLoginIdentifier(identifier string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBTimeout)
	defer cancel()

	identifier = strings.TrimSpace(identifier)
	var user User
	err := usersCol.FindOne(ctx, bson.M{
		"$or": []bson.M{
			{"telegram_username": NormalizeTelegramUsername(identifier)},
			{"email": identifier},
			{"username": identifier},
		},
	}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// GetTelegramChatIDByUsername returns the chat_id of the user whose Telegram
// username is linked (used by notification-service to resolve alert recipients)
func GetTelegramChatIDByUsername(username string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBTimeout)
	defer cancel()

	var user User
	err := usersCol.FindOne(ctx, bson.M{
		"telegram_username": NormalizeTelegramUsername(username),
		"telegram_chat_id":  bson.M{"$ne": 0},
	}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return 0, fmt.Errorf("пользователь @%s не найден или не привязал Telegram на портале", NormalizeTelegramUsername(username))
		}
		return 0, err
	}
	return user.TelegramChatID, nil
}

// MarkTelegramLinkBroken сбрасывает привязку Telegram после того, как отправка
// упёрлась в неустранимую ошибку («bot was blocked by the user», «chat not found»).
//
// Зачем сбрасывать, а не просто логировать: пока chat_id лежит в профиле, каждый
// вызывающий сервис продолжит адресовать уведомления по нему, а каждая такая отправка
// — это круг до api.telegram.org, который держит очередь. С обнулённым chat_id резолв
// вернёт channel_not_linked, и отправка отвалится на приёме запроса, не дойдя до бота.
//
// telegram_username оставляем: по нему в личном кабинете видно, что привязку нужно
// восстановить, и пользователь не начинает с пустого места.
func MarkTelegramLinkBroken(chatID int64, reason string) (*User, error) {
	if chatID == 0 {
		return nil, fmt.Errorf("chat_id обязателен")
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultDBTimeout)
	defer cancel()

	var user User
	err := usersCol.FindOne(ctx, bson.M{"telegram_chat_id": chatID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("пользователь с chat_id %d не найден", chatID)
		}
		return nil, err
	}

	now := time.Now()
	_, err = usersCol.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$set": bson.M{
			"telegram_chat_id":    0,
			"telegram_blocked_at": now,
			"updated_at":          now,
		},
	})
	if err != nil {
		return nil, err
	}

	log.Printf("Telegram-привязка пользователя %s сброшена: %s", user.Username, reason)

	user.TelegramChatID = 0
	user.TelegramBlockedAt = &now
	return &user, nil
}

// CreateTelegramLoginRequest creates a pending login confirmation request.
// Previous pending requests of the user are invalidated.
func CreateTelegramLoginRequest(userID primitive.ObjectID, ip, userAgent string) (*TelegramLoginRequest, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBTimeout)
	defer cancel()

	requestsCol := getTelegramLoginRequestsCollection()
	if _, err := requestsCol.DeleteMany(ctx, bson.M{"user_id": userID, "status": "pending"}); err != nil {
		log.Printf("Warning: Failed to delete pending telegram login requests for user %s: %v", userID.Hex(), err)
	}

	// 16 байт = 32 hex-символа: callback_data кнопки «login:<id>:approve»
	// не должен превышать телеграмный лимит в 64 байта
	requestID, err := generateRandomHex(16)
	if err != nil {
		return nil, err
	}

	request := &TelegramLoginRequest{
		RequestID: requestID,
		UserID:    userID,
		Status:    "pending",
		Consumed:  false,
		IP:        ip,
		UserAgent: userAgent,
		ExpiresAt: time.Now().Add(3 * time.Minute),
		CreatedAt: time.Now(),
	}

	result, err := requestsCol.InsertOne(ctx, request)
	if err != nil {
		return nil, err
	}
	request.ID = result.InsertedID.(primitive.ObjectID)
	return request, nil
}

// ResolveTelegramLoginRequest applies the user's approve/reject decision coming from the bot.
// Returns the updated request and whether Telegram login got frozen by this rejection.
func ResolveTelegramLoginRequest(requestID, decision string, chatID int64) (*TelegramLoginRequest, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBTimeout)
	defer cancel()

	var request TelegramLoginRequest
	err := getTelegramLoginRequestsCollection().FindOne(ctx, bson.M{
		"request_id": requestID,
	}).Decode(&request)
	if err != nil {
		return nil, false, fmt.Errorf("запрос на вход не найден")
	}

	if request.Status != "pending" {
		return nil, false, fmt.Errorf("запрос на вход уже обработан")
	}
	if time.Now().After(request.ExpiresAt) {
		return nil, false, fmt.Errorf("запрос на вход истёк")
	}

	// The decision must come from the Telegram account linked to this user
	var user User
	err = usersCol.FindOne(ctx, bson.M{"_id": request.UserID, "telegram_chat_id": chatID}).Decode(&user)
	if err != nil {
		log.Printf("SECURITY: telegram login decision from chat %d does not match request %s owner", chatID, requestID)
		return nil, false, fmt.Errorf("этот запрос принадлежит другому аккаунту")
	}

	newStatus := "rejected"
	if decision == "approve" {
		newStatus = "approved"
	}

	_, err = getTelegramLoginRequestsCollection().UpdateOne(ctx,
		bson.M{"request_id": requestID, "status": "pending"},
		bson.M{"$set": bson.M{"status": newStatus}},
	)
	if err != nil {
		return nil, false, fmt.Errorf("не удалось обновить запрос: %v", err)
	}
	request.Status = newStatus

	frozen := false
	if newStatus == "rejected" {
		rejects := user.TelegramLoginRejects + 1
		update := bson.M{"telegram_login_rejects": rejects}
		if rejects >= TelegramLoginMaxRejects {
			update["telegram_login_frozen"] = true
			frozen = true
			log.Printf("SECURITY: Telegram login frozen for user %s after %d rejections", user.Username, rejects)
		}
		if _, err := usersCol.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": update}); err != nil {
			log.Printf("Warning: Failed to update telegram reject counter for user %s: %v", user.Username, err)
		}
	}

	log.Printf("Telegram login request %s %s by user %s (ip: %s)", requestID, newStatus, user.Username, request.IP)
	return &request, frozen, nil
}

// GetTelegramLoginRequestStatus returns the request status for browser polling.
// Unknown request IDs are reported as pending to prevent account enumeration.
func GetTelegramLoginRequestStatus(requestID string) string {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBTimeout)
	defer cancel()

	var request TelegramLoginRequest
	err := getTelegramLoginRequestsCollection().FindOne(ctx, bson.M{"request_id": requestID}).Decode(&request)
	if err != nil {
		return "pending"
	}
	if request.Status == "pending" && time.Now().After(request.ExpiresAt) {
		return "expired"
	}
	return request.Status
}

// ConsumeApprovedTelegramLoginRequest atomically consumes an approved request
// and returns its user. A request can be consumed exactly once (single session issue).
func ConsumeApprovedTelegramLoginRequest(requestID string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBTimeout)
	defer cancel()

	var request TelegramLoginRequest
	err := getTelegramLoginRequestsCollection().FindOneAndUpdate(ctx,
		bson.M{"request_id": requestID, "status": "approved", "consumed": false},
		bson.M{"$set": bson.M{"consumed": true}},
	).Decode(&request)
	if err != nil {
		return nil, fmt.Errorf("запрос не подтверждён или уже использован")
	}

	return GetUserByID(request.UserID.Hex())
}

// ResetTelegramLoginFreeze clears the freeze and reject counter
// (called after a successful password login)
func ResetTelegramLoginFreeze(userID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBTimeout)
	defer cancel()

	_, err := usersCol.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{
		"$set": bson.M{
			"telegram_login_rejects": 0,
			"telegram_login_frozen":  false,
		},
	})
	return err
}

// CreatePasswordResetTokenForUser creates a password reset token by user ID
// (used for Telegram delivery where the account may lack an email)
func CreatePasswordResetTokenForUser(user *User) (*PasswordResetToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBTimeout)
	defer cancel()

	tokensCol := getPasswordResetTokensCollection()
	if _, err := tokensCol.DeleteMany(ctx, bson.M{"user_id": user.ID}); err != nil {
		log.Printf("Warning: Failed to delete existing password reset tokens for user %s: %v", user.ID.Hex(), err)
	}

	token, err := generateRandomHex(32)
	if err != nil {
		return nil, err
	}

	resetToken := &PasswordResetToken{
		UserID:    user.ID,
		Email:     user.Email,
		Token:     token,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Used:      false,
		CreatedAt: time.Now(),
	}

	result, err := tokensCol.InsertOne(ctx, resetToken)
	if err != nil {
		return nil, err
	}
	resetToken.ID = result.InsertedID.(primitive.ObjectID)
	return resetToken, nil
}
