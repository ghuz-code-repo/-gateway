package models

import "testing"

// Резолв адреса по каналу — место, где ошибка отправит письмо не тому человеку
// или молча похоронит уведомление, поэтому проверяем все каналы и все пустые случаи.
func TestRecipientAddress(t *testing.T) {
	user := User{
		Username:       "ivanov",
		Email:          "  ivanov@gh.uz  ",
		Phone:          "+998901234567",
		TelegramChatID: 123456789,
	}

	cases := []struct {
		name        string
		user        User
		channel     string
		wantAddress string
		wantReason  string
	}{
		{
			name:        "telegram отдаёт chat_id строкой",
			user:        user,
			channel:     RecipientChannelTelegram,
			wantAddress: "123456789",
		},
		{
			name:        "email обрезается по краям",
			user:        user,
			channel:     RecipientChannelEmail,
			wantAddress: "ivanov@gh.uz",
		},
		{
			name:        "sms берёт телефон",
			user:        user,
			channel:     RecipientChannelSMS,
			wantAddress: "+998901234567",
		},
		{
			name:       "telegram не привязан",
			user:       User{Username: "petrov", Email: "petrov@gh.uz"},
			channel:    RecipientChannelTelegram,
			wantReason: RecipientReasonChannelNotLinked,
		},
		{
			name:       "email не заполнен",
			user:       User{Username: "petrov", Email: "   "},
			channel:    RecipientChannelEmail,
			wantReason: RecipientReasonNoAddress,
		},
		{
			name:       "телефон не заполнен",
			user:       User{Username: "petrov"},
			channel:    RecipientChannelSMS,
			wantReason: RecipientReasonNoAddress,
		},
		{
			name:       "неизвестный канал",
			user:       user,
			channel:    "carrier-pigeon",
			wantReason: RecipientReasonUnknownChannel,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			address, reason := recipientAddress(tc.user, tc.channel)

			if address != tc.wantAddress {
				t.Errorf("адрес = %q, ожидался %q", address, tc.wantAddress)
			}
			if reason != tc.wantReason {
				t.Errorf("причина = %q, ожидалась %q", reason, tc.wantReason)
			}
		})
	}
}

func TestIsValidRecipientChannel(t *testing.T) {
	for _, channel := range []string{RecipientChannelTelegram, RecipientChannelEmail, RecipientChannelSMS} {
		if !IsValidRecipientChannel(channel) {
			t.Errorf("канал %s должен приниматься", channel)
		}
	}
	for _, channel := range []string{"", "push", "TELEGRAM"} {
		if IsValidRecipientChannel(channel) {
			t.Errorf("канал %q не должен приниматься", channel)
		}
	}
}
