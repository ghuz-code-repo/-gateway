package main

import (
	"fmt"
	"testing"
	"time"
)

// Разбор ошибок раньше был общим для всех каналов: один список подстрок ловил
// и коды SMTP, и описания Telegram. Теперь у каждого канала свой разбор, и он
// обязан отличать постоянный отказ от временного — от этого зависит, повторим
// мы доставку или похороним уведомление.
func TestEmailClassify(t *testing.T) {
	tr := &emailTransport{}

	cases := []struct {
		err         string
		permanent   bool
		rateLimited bool
	}{
		{"SMTP RCPT command error: 550 5.1.1 No such user", true, false},
		{"SMTP RCPT command error: 553 mailbox name not allowed", true, false},
		{"SMTP dial error: 421 service not available", false, true},
		{"SMTP DATA command error: 451 local error in processing", false, true},
		{"exceeded sending limits for this hour", false, true},
		{"SMTP dial error: connection refused", false, false},
		{"SMTP dial error: i/o timeout", false, false},
	}

	for _, c := range cases {
		got := tr.Classify(fmt.Errorf("%s", c.err))
		if got.Permanent != c.permanent || got.RateLimited != c.rateLimited {
			t.Errorf("%q: ожидалось permanent=%v rateLimited=%v, получено permanent=%v rateLimited=%v",
				c.err, c.permanent, c.rateLimited, got.Permanent, got.RateLimited)
		}
	}
}

func TestTelegramClassify(t *testing.T) {
	tr := &telegramTransport{}

	cases := []struct {
		name        string
		err         error
		permanent   bool
		rateLimited bool
		retryAfter  time.Duration
	}{
		{
			name:        "retry_after от Telegram определяет паузу точно",
			err:         &rateLimitError{msg: "notification-bot rate limit: too many requests", retryAfter: 7 * time.Second},
			rateLimited: true,
			retryAfter:  7 * time.Second,
		},
		{
			name:        "429 без числа тоже считается лимитом темпа",
			err:         fmt.Errorf("notification-bot error: 429 Too Many Requests"),
			rateLimited: true,
		},
		{
			name:      "заблокировавший бота получатель — постоянный отказ",
			err:       fmt.Errorf("notification-bot error: Forbidden: bot was blocked by the user"),
			permanent: true,
		},
		{
			name:      "несуществующий чат — постоянный отказ",
			err:       fmt.Errorf("notification-bot error: Bad Request: chat not found"),
			permanent: true,
		},
		{
			name: "недоступный notification-bot — временный отказ",
			err:  fmt.Errorf("notification-bot request failed: connection refused"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := tr.Classify(c.err)
			if got.Permanent != c.permanent || got.RateLimited != c.rateLimited {
				t.Errorf("ожидалось permanent=%v rateLimited=%v, получено permanent=%v rateLimited=%v",
					c.permanent, c.rateLimited, got.Permanent, got.RateLimited)
			}
			if got.RetryAfter != c.retryAfter {
				t.Errorf("ожидалось retry_after=%s, получено %s", c.retryAfter, got.RetryAfter)
			}
		})
	}
}

// Один канал обслуживает несколько типов, но каждый тип принадлежит ровно
// одному каналу — иначе уведомление попало бы в две очереди сразу.
func TestTransportRegistryCoversEveryType(t *testing.T) {
	transports := buildTransports(&NotificationService{})

	owner := make(map[NotificationType]string)
	for _, tr := range transports {
		for _, nt := range tr.Types() {
			if prev, exists := owner[nt]; exists {
				t.Errorf("тип %s обслуживают два канала: %s и %s", nt, prev, tr.Channel())
			}
			owner[nt] = tr.Channel()
		}
	}

	all := []NotificationType{
		NotificationTypeEmail,
		NotificationTypeSMS,
		NotificationTypePush,
		NotificationTypeTelegram,
		NotificationTypeTelegramSystem,
	}
	for _, nt := range all {
		if _, ok := owner[nt]; !ok {
			t.Errorf("тип %s не обслуживает ни один канал — уведомление зависнет в очереди", nt)
		}
	}

	// telegram и telegram_system делят лимиты одного бота, значит и канал
	if owner[NotificationTypeTelegram] != owner[NotificationTypeTelegramSystem] {
		t.Error("telegram и telegram_system должны быть в одном канале: у них общий бот и общий лимит")
	}
}

// Каждому каналу из реестра нужен конфиг: без него канал остался бы без лимитов.
func TestEveryTransportHasDefaultConfig(t *testing.T) {
	configured := make(map[string]bool)
	for _, cfg := range defaultChannelConfigs() {
		configured[cfg.Channel] = true
	}

	for _, tr := range buildTransports(&NotificationService{}) {
		if !configured[tr.Channel()] {
			t.Errorf("канал %s зарегистрирован, но конфига по умолчанию у него нет", tr.Channel())
		}
	}
}

// Значения, при которых лимитер выродился бы, должны подтягиваться к рабочим:
// burst=0 запретил бы отправку вовсе, max_concurrent=0 остановил бы канал.
func TestApplyChannelUpdateGuardsDegenerateValues(t *testing.T) {
	cfg := emailConfigForTest()

	updated, err := applyChannelUpdate(&cfg, map[string]interface{}{
		"burst":          float64(0),
		"max_concurrent": float64(0),
		"max_attempts":   float64(0),
	})
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if len(updated) != 3 {
		t.Errorf("ожидалось 3 изменённых поля, получено %v", updated)
	}
	if cfg.Burst != 1 || cfg.MaxConcurrent != 1 || cfg.MaxAttempts != 1 {
		t.Errorf("вырожденные значения не подтянуты: burst=%d, max_concurrent=%d, max_attempts=%d",
			cfg.Burst, cfg.MaxConcurrent, cfg.MaxAttempts)
	}
}

// Битый JSON лимитов не должен попадать в БД: разобрать его потом будет некому,
// а молча проигнорированные лимиты означают отправку без лимитов.
func TestApplyChannelUpdateRejectsBadInput(t *testing.T) {
	cases := []map[string]interface{}{
		{"recipient_class_limits": "{не json"},
		{"rate_per_minute": float64(-5)},
		{"rate_per_minute": "быстро"},
		{"enabled": "да"},
	}

	for _, patch := range cases {
		cfg := telegramConfigForTest()
		if _, err := applyChannelUpdate(&cfg, patch); err == nil {
			t.Errorf("значение %v должно быть отвергнуто", patch)
		}
	}
}

// Настройки email должны укладываться в ограничение администраторов почты
// (20 сообщений в минуту) с запасом.
func TestEmailDefaultsFitAdminLimit(t *testing.T) {
	const adminLimitPerMinute = 20

	cfg := emailConfigForTest()
	if cfg.RatePerMinute > adminLimitPerMinute {
		t.Errorf("скорость %d/мин превышает лимит администраторов %d/мин", cfg.RatePerMinute, adminLimitPerMinute)
	}

	// Интервал сам по себе тоже обязан удерживать темп: если скорость снимут,
	// ограничение должно остаться
	if cfg.MinIntervalMS > 0 {
		byInterval := 60000 / cfg.MinIntervalMS
		if byInterval > adminLimitPerMinute {
			t.Errorf("интервал %d мс даёт %d сообщений в минуту при лимите %d",
				cfg.MinIntervalMS, byInterval, adminLimitPerMinute)
		}
	}

	if cfg.Burst > 1 {
		t.Errorf("всплеск %d нарушил бы равномерность отправки при жёсткой квоте", cfg.Burst)
	}
}
