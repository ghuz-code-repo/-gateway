package main

import (
	"log"
	"strings"
	"time"
)

// runUpdatesLoop long-polls Telegram for updates and dispatches them
func runUpdatesLoop(bot *TelegramBot, authClient *AuthClient) {
	log.Println("Starting Telegram long-polling loop...")
	var offset int64

	for {
		updates, err := bot.GetUpdates(offset)
		if err != nil {
			log.Printf("ERROR: getUpdates failed: %v (retrying in 5s)", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for _, update := range updates {
			offset = update.UpdateID + 1

			switch {
			case update.Message != nil:
				handleMessage(bot, authClient, &update)
			case update.CallbackQuery != nil:
				handleCallbackQuery(bot, authClient, &update)
			}
		}
	}
}

// handleMessage processes incoming text messages (/start with link token)
func handleMessage(bot *TelegramBot, authClient *AuthClient, update *Update) {
	msg := update.Message
	chatID := msg.Chat.ID
	text := strings.TrimSpace(msg.Text)

	if !strings.HasPrefix(text, "/start") {
		reply(bot, chatID, "Это сервисный бот портала Golden House Analytics.\n\n"+
			"Чтобы привязать Telegram к вашему аккаунту, перейдите в Личный кабинет портала → вкладка «Безопасность» → «Подключить Telegram».")
		return
	}

	// /start <link_token> — deep-link from the account linking email
	payload := strings.TrimSpace(strings.TrimPrefix(text, "/start"))
	if payload == "" {
		reply(bot, chatID, "👋 Здравствуйте! Это бот портала Golden House Analytics.\n\n"+
			"Через него вы можете подтверждать вход на портал и получать ссылки для сброса пароля.\n\n"+
			"Чтобы привязать Telegram к аккаунту, зайдите в Личный кабинет портала → «Безопасность» → «Подключить Telegram» и перейдите по ссылке из письма.")
		return
	}

	resp, err := authClient.ConfirmLink(payload, chatID, msg.From.Username, msg.From.FirstName)
	if err != nil {
		log.Printf("ERROR: link confirmation failed for chat %d: %v", chatID, err)
		reply(bot, chatID, "⚠️ Не удалось подтвердить привязку: сервис авторизации временно недоступен. Попробуйте позже.")
		return
	}

	if resp.Success {
		log.Printf("Telegram link confirmed for chat %d (@%s)", chatID, msg.From.Username)
		reply(bot, chatID, "✅ "+resp.Message)
	} else {
		reply(bot, chatID, "❌ "+resp.Message)
	}
}

// handleCallbackQuery processes inline button presses (login approve/reject)
func handleCallbackQuery(bot *TelegramBot, authClient *AuthClient, update *Update) {
	cq := update.CallbackQuery

	// Expected format: login:<request_id>:<approve|reject>
	parts := strings.Split(cq.Data, ":")
	if len(parts) != 3 || parts[0] != "login" {
		bot.AnswerCallbackQuery(cq.ID, "Неизвестное действие")
		return
	}
	requestID, decision := parts[1], parts[2]
	if decision != "approve" && decision != "reject" {
		bot.AnswerCallbackQuery(cq.ID, "Неизвестное действие")
		return
	}

	resp, err := authClient.LoginDecision(requestID, decision, cq.From.ID)
	if err != nil {
		log.Printf("ERROR: login decision failed for chat %d: %v", cq.From.ID, err)
		bot.AnswerCallbackQuery(cq.ID, "⚠️ Сервис авторизации недоступен, попробуйте позже")
		return
	}

	bot.AnswerCallbackQuery(cq.ID, resp.Message)

	// Replace the message with the outcome so the buttons cannot be pressed twice
	if cq.Message != nil {
		var resultText string
		switch {
		case !resp.Success:
			resultText = "⚠️ " + resp.Message
		case decision == "approve":
			resultText = "✅ Вход подтверждён."
		case resp.Frozen:
			resultText = "⛔ Вход отклонён.\n\nВход через Telegram заморожен из-за повторных отклонений. Разблокировка — при следующем входе по логину и паролю."
		default:
			resultText = "🚫 Вход отклонён."
		}
		if err := bot.EditMessageText(cq.Message.Chat.ID, cq.Message.MessageID, resultText); err != nil {
			log.Printf("WARNING: failed to edit login message: %v", err)
		}
	}
}

// reply sends a plain text message, logging failures
func reply(bot *TelegramBot, chatID int64, text string) {
	if _, err := bot.SendMessage(chatID, text, "", nil); err != nil {
		log.Printf("ERROR: failed to send reply to chat %d: %v", chatID, err)
	}
}
