package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestService собирает минимальный сервис: резолву нужны только HTTP-клиент и кэш
func newTestService() *NotificationService {
	return &NotificationService{
		httpClient:     &http.Client{Timeout: 5 * time.Second},
		recipientCache: make(map[string]recipientCacheEntry),
	}
}

func TestResolveRecipientsSuccess(t *testing.T) {
	var gotBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/recipients/resolve" {
			t.Errorf("неожиданный путь: %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&gotBody)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"results": map[string]recipientResolution{
				"ivanov": {Found: true, Address: "123456789", HasServiceAccess: true},
				"petrov": {Found: false, Reason: "channel_not_linked", HasServiceAccess: true},
			},
		})
	}))
	defer srv.Close()

	t.Setenv("AUTH_SERVICE_URL", srv.URL)
	t.Setenv("SERVICE_AUTH_KEY_MAP", "apartment-finder=finder")

	ns := newTestService()
	results, err := ns.resolveRecipients("apartment-finder", "telegram", []string{"ivanov", "petrov"})
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}

	if got := results["ivanov"]; !got.Found || got.Address != "123456789" {
		t.Errorf("ivanov = %+v, ожидался найденный адрес 123456789", got)
	}
	if got := results["petrov"]; got.Found || got.Reason != "channel_not_linked" {
		t.Errorf("petrov = %+v, ожидался отказ channel_not_linked", got)
	}

	// В auth-service уходит service_key, а не имя ключа уведомлений
	if gotBody["service"] != "finder" {
		t.Errorf("service = %v, ожидался finder", gotBody["service"])
	}
	if gotBody["channel"] != "telegram" {
		t.Errorf("channel = %v, ожидался telegram", gotBody["channel"])
	}
}

func TestResolveRecipientsUsesCache(t *testing.T) {
	calls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"results": map[string]recipientResolution{
				"ivanov": {Found: true, Address: "ivanov@gh.uz", HasServiceAccess: true},
			},
		})
	}))
	defer srv.Close()

	t.Setenv("AUTH_SERVICE_URL", srv.URL)

	ns := newTestService()
	for i := 0; i < 3; i++ {
		if _, err := ns.resolveRecipients("referal", "email", []string{"ivanov"}); err != nil {
			t.Fatalf("неожиданная ошибка: %v", err)
		}
	}

	if calls != 1 {
		t.Errorf("запросов к auth-service: %d, ожидался 1 (остальное из кэша)", calls)
	}
}

// Отрицательный ответ живёт минуту, положительный — десять: пользователь может
// привязать Telegram или получить роль в любой момент
func TestResolveRecipientsNegativeCacheExpiresSooner(t *testing.T) {
	ns := newTestService()

	ns.recipientCacheSet("referal", "email", "positive",
		recipientResolution{Found: true, Address: "a@gh.uz"})
	ns.recipientCacheSet("referal", "email", "negative",
		recipientResolution{Reason: "user_not_found"})

	// Сдвигаем обе записи на 2 минуты назад
	stale := time.Now().Add(-2 * time.Minute)
	for key, entry := range ns.recipientCache {
		entry.at = stale
		ns.recipientCache[key] = entry
	}

	if _, ok := ns.recipientCacheGet("referal", "email", "positive"); !ok {
		t.Error("положительный ответ должен жить дольше двух минут")
	}
	if _, ok := ns.recipientCacheGet("referal", "email", "negative"); ok {
		t.Error("отрицательный ответ должен протухнуть за минуту")
	}
}

// Недоступность auth-service — это 503 вызывающему, а не «получатель не найден»:
// уведомление нельзя хоронить из-за временного сбоя
func TestResolveRecipientsAuthUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()

	t.Setenv("AUTH_SERVICE_URL", srv.URL)

	ns := newTestService()
	if _, err := ns.resolveRecipients("referal", "email", []string{"ivanov"}); err == nil {
		t.Fatal("ожидалась ошибка транспорта, получен успех")
	}
}

// Логин, про который auth-service промолчал, считаем неизвестным — молча отправить
// «куда-нибудь» хуже, чем вернуть отказ
func TestResolveRecipientsMissingLoginInResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"results": map[string]recipientResolution{},
		})
	}))
	defer srv.Close()

	t.Setenv("AUTH_SERVICE_URL", srv.URL)

	ns := newTestService()
	results, err := ns.resolveRecipients("referal", "email", []string{"ivanov"})
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if got := results["ivanov"]; got.Found || got.Reason != failureUserNotFound {
		t.Errorf("ivanov = %+v, ожидался отказ %s", got, failureUserNotFound)
	}
}

// Для push резолв по логину не поддержан — канал неизвестен
func TestResolveRecipientsUnknownChannel(t *testing.T) {
	ns := newTestService()
	results, err := ns.resolveRecipients("referal", "", []string{"ivanov"})
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if got := results["ivanov"]; got.Found || got.Reason != failureUnknownChannel {
		t.Errorf("ivanov = %+v, ожидался отказ %s", got, failureUnknownChannel)
	}
}

func TestApplyRecipient(t *testing.T) {
	cases := []struct {
		name         string
		mode         string
		value        string
		resolved     recipientResolution
		wantAddress  string
		wantLogin    string
		wantExternal string
	}{
		{
			name:        "логин резолвится в адрес",
			mode:        recipientModeLogin,
			value:       "ivanov",
			resolved:    recipientResolution{Found: true, Address: "123456789"},
			wantAddress: "123456789",
			wantLogin:   "ivanov",
		},
		{
			name:        "нерезолвнутый логин остаётся опознаваемым",
			mode:        recipientModeLogin,
			value:       "ivanov",
			resolved:    recipientResolution{Reason: "user_not_found"},
			wantAddress: "ivanov",
			wantLogin:   "ivanov",
		},
		{
			name:         "внешний получатель",
			mode:         recipientModeExternal,
			value:        "client@mail.ru",
			wantAddress:  "client@mail.ru",
			wantExternal: "client@mail.ru",
		},
		{
			name:        "системный алерт",
			mode:        recipientModeSystem,
			wantAddress: systemRecipientPlaceholder,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var n Notification
			applyRecipient(&n, tc.mode, tc.value, tc.resolved)

			if n.Recipient != tc.wantAddress {
				t.Errorf("Recipient = %q, ожидался %q", n.Recipient, tc.wantAddress)
			}
			if n.RecipientLogin != tc.wantLogin {
				t.Errorf("RecipientLogin = %q, ожидался %q", n.RecipientLogin, tc.wantLogin)
			}
			if n.ExternalRecipient != tc.wantExternal {
				t.Errorf("ExternalRecipient = %q, ожидался %q", n.ExternalRecipient, tc.wantExternal)
			}
		})
	}
}

// Ошибки, после которых привязка Telegram считается мёртвой: повторять по этому
// chat_id бессмысленно, адрес надо убирать из auth-service
func TestIsDeadTelegramBinding(t *testing.T) {
	dead := []string{
		`notification-bot error: {"error":"telegram API sendMessage error: Forbidden: bot was blocked by the user"}`,
		`notification-bot error: {"error":"telegram API sendMessage error: Bad Request: chat not found"}`,
		`notification-bot error: {"error":"telegram API sendMessage error: Forbidden: user is deactivated"}`,
	}
	for _, msg := range dead {
		if !isDeadTelegramBinding(errors.New(msg)) {
			t.Errorf("должно считаться мёртвой привязкой: %s", msg)
		}
	}

	alive := []string{
		`notification-bot error: {"error":"telegram API sendMessage error: Too Many Requests: retry after 30"}`,
		"notification-bot request failed: connection refused",
		"SMTP configuration not complete",
	}
	for _, msg := range alive {
		if isDeadTelegramBinding(errors.New(msg)) {
			t.Errorf("не должно считаться мёртвой привязкой: %s", msg)
		}
	}

	if isDeadTelegramBinding(nil) {
		t.Error("nil не должен считаться мёртвой привязкой")
	}
}

// Сброс кэша по паре «канал + логин» не должен задевать другие каналы и логины:
// иначе один заблокировавший бота пользователь обнулял бы резолв всему сервису
func TestInvalidateRecipientCache(t *testing.T) {
	ns := newTestService()

	ns.recipientCacheSet("finder", "telegram", "ivanov", recipientResolution{Found: true, Address: "111"})
	ns.recipientCacheSet("referal", "telegram", "ivanov", recipientResolution{Found: true, Address: "111"})
	ns.recipientCacheSet("finder", "email", "ivanov", recipientResolution{Found: true, Address: "i@gh.uz"})
	ns.recipientCacheSet("finder", "telegram", "petrov", recipientResolution{Found: true, Address: "222"})

	ns.invalidateRecipientCache("telegram", "ivanov")

	if _, ok := ns.recipientCacheGet("finder", "telegram", "ivanov"); ok {
		t.Error("запись finder|telegram|ivanov должна быть удалена")
	}
	if _, ok := ns.recipientCacheGet("referal", "telegram", "ivanov"); ok {
		t.Error("запись referal|telegram|ivanov должна быть удалена: адрес мёртв для всех сервисов")
	}
	if _, ok := ns.recipientCacheGet("finder", "email", "ivanov"); !ok {
		t.Error("email того же пользователя трогать нельзя")
	}
	if _, ok := ns.recipientCacheGet("finder", "telegram", "petrov"); !ok {
		t.Error("другой пользователь трогать нельзя")
	}

	// Пустой логин не должен вычищать весь кэш
	ns.invalidateRecipientCache("telegram", "")
	if _, ok := ns.recipientCacheGet("finder", "telegram", "petrov"); !ok {
		t.Error("пустой логин не должен ничего удалять")
	}
}
