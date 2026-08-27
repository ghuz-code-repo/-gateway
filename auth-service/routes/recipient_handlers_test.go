package routes

import "testing"

// Проверка доступа получателя к сервису-отправителю по умолчанию выключена:
// часть живых рассылок адресована людям без ролей в сервисе-отправителе, и
// включение флага без разбора логов обрубило бы их.
func TestRecipientAccessEnforced(t *testing.T) {
	cases := map[string]bool{
		"":      false,
		"false": false,
		"0":     false,
		"off":   false,
		"true":  true,
		"TRUE":  true,
		" yes ": true,
		"1":     true,
		"on":    true,
	}

	for value, want := range cases {
		t.Run(value, func(t *testing.T) {
			t.Setenv("RECIPIENT_ACCESS_ENFORCE", value)

			if got := recipientAccessEnforced(); got != want {
				t.Errorf("RECIPIENT_ACCESS_ENFORCE=%q -> %v, ожидалось %v", value, got, want)
			}
		})
	}
}
