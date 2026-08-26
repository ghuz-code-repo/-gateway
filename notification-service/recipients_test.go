package main

import "testing"

// Валидация адресации — место, где ошибка уводит уведомление не тому человеку,
// поэтому проверяем таблицей все сочетания полей.
func TestResolveRecipientMode(t *testing.T) {
	cases := []struct {
		name     string
		req      SingleNotificationRequest
		wantMode string
		wantVal  string
		wantErr  bool
	}{
		{
			name:     "логин портала",
			req:      SingleNotificationRequest{Type: NotificationTypeTelegram, Login: "ivanov"},
			wantMode: recipientModeLogin,
			wantVal:  "ivanov",
		},
		{
			name:     "внешний получатель",
			req:      SingleNotificationRequest{Type: NotificationTypeEmail, ExternalRecipient: "client@mail.ru"},
			wantMode: recipientModeExternal,
			wantVal:  "client@mail.ru",
		},
		{
			name:     "легаси-поле recipient",
			req:      SingleNotificationRequest{Type: NotificationTypeEmail, Recipient: "old@mail.ru"},
			wantMode: recipientModeLegacy,
			wantVal:  "old@mail.ru",
		},
		{
			name:     "системный алерт без получателя",
			req:      SingleNotificationRequest{Type: NotificationTypeTelegramSystem},
			wantMode: recipientModeSystem,
		},
		{
			name:    "два поля сразу",
			req:     SingleNotificationRequest{Type: NotificationTypeEmail, Login: "ivanov", ExternalRecipient: "client@mail.ru"},
			wantErr: true,
		},
		{
			name:    "получатель не указан",
			req:     SingleNotificationRequest{Type: NotificationTypeEmail},
			wantErr: true,
		},
		{
			name:    "email в поле login",
			req:     SingleNotificationRequest{Type: NotificationTypeEmail, Login: "ivanov@gh.uz"},
			wantErr: true,
		},
		{
			name:    "push не резолвится по логину",
			req:     SingleNotificationRequest{Type: NotificationTypePush, Login: "ivanov"},
			wantErr: true,
		},
		{
			name:     "пробелы вокруг логина отрезаются",
			req:      SingleNotificationRequest{Type: NotificationTypeTelegram, Login: "  ivanov  "},
			wantMode: recipientModeLogin,
			wantVal:  "ivanov",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			mode, value, err := resolveRecipientMode(&req)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("ожидалась ошибка, получено mode=%s value=%s", mode, value)
				}
				return
			}
			if err != nil {
				t.Fatalf("неожиданная ошибка: %v", err)
			}
			if mode != tc.wantMode {
				t.Errorf("mode = %s, ожидался %s", mode, tc.wantMode)
			}
			if value != tc.wantVal {
				t.Errorf("value = %q, ожидалось %q", value, tc.wantVal)
			}
		})
	}
}

func TestServiceAuthKey(t *testing.T) {
	t.Setenv("SERVICE_AUTH_KEY_MAP", "apartment-finder=finder, client-service=client_service")

	if got := serviceAuthKey("apartment-finder"); got != "finder" {
		t.Errorf("apartment-finder -> %s, ожидался finder", got)
	}
	if got := serviceAuthKey("client-service"); got != "client_service" {
		t.Errorf("client-service -> %s, ожидался client_service", got)
	}
	// Сервис вне маппинга адресуется своим же именем
	if got := serviceAuthKey("referal"); got != "referal" {
		t.Errorf("referal -> %s, ожидался referal", got)
	}
}

func TestMaskRecipient(t *testing.T) {
	cases := map[string]string{
		"ivanov@gh.uz": "iv***@gh.uz",
		"a@gh.uz":      "**@gh.uz",
		"123456789":    "12***89",
		"123":          "***",
		"":             "(пусто)",
	}
	for in, want := range cases {
		if got := maskRecipient(in); got != want {
			t.Errorf("maskRecipient(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}
