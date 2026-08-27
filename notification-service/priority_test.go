package main

import (
	"testing"
)

// serviceWithChannels собирает сервис с заранее заполненным кэшем каналов:
// resolvePriority читает пер-канальные потолки из него, БД для этого не нужна.
func serviceWithChannels(global map[string]int, rows ...ChannelConfig) *NotificationService {
	ns := &NotificationService{
		channelCache: newChannelConfigCache(),
		priorities:   global,
	}
	ns.transports = buildTransports(ns)
	ns.channelCache.store(rows)
	return ns
}

func intPtr(v int) *int { return &v }

// Потолок канала важнее общего: цена задержки у каналов разная.
func TestChannelCeilingOverridesGlobal(t *testing.T) {
	ns := serviceWithChannels(
		map[string]int{"auth-service": priorityHigh},
		ChannelConfig{Channel: channelEmail, ServicePriorities: `{"auth-service":50}`},
		ChannelConfig{Channel: channelTelegram},
	)

	if got := ns.resolvePriority(channelEmail, "auth-service", nil); got != 50 {
		t.Errorf("почта: ожидался потолок канала 50, получено %d", got)
	}
	// У telegram своих потолков нет — действует общий
	if got := ns.resolvePriority(channelTelegram, "auth-service", nil); got != priorityHigh {
		t.Errorf("telegram: ожидался общий потолок %d, получено %d", priorityHigh, got)
	}
}

// Явный ноль на канале выключает приоритет отправителя именно там.
// Проверять нужно наличие ключа, а не ненулевое значение, иначе ноль был бы
// неотличим от «не задано» и молча возвращал бы общий потолок.
func TestChannelCeilingZeroDisablesPriority(t *testing.T) {
	ns := serviceWithChannels(
		map[string]int{"auth-service": priorityHigh},
		ChannelConfig{Channel: channelTelegram, ServicePriorities: `{"auth-service":0}`},
		ChannelConfig{Channel: channelEmail},
	)

	if got := ns.resolvePriority(channelTelegram, "auth-service", nil); got != priorityBulk {
		t.Errorf("telegram: приоритет должен быть выключен, получено %d", got)
	}
	if got := ns.resolvePriority(channelEmail, "auth-service", nil); got != priorityHigh {
		t.Errorf("почта: ожидался общий потолок %d, получено %d", priorityHigh, got)
	}
}

// Запрошенный приоритет режется потолком того канала, куда идёт уведомление.
func TestRequestedPriorityCappedByChannelCeiling(t *testing.T) {
	ns := serviceWithChannels(
		map[string]int{"auth-service": priorityHigh, "referal": priorityBulk},
		ChannelConfig{Channel: channelEmail, ServicePriorities: `{"auth-service":40}`},
	)

	cases := []struct {
		name      string
		service   string
		requested *int
		want      int
	}{
		{"понижение своей рассылки принимается", "auth-service", intPtr(0), priorityBulk},
		{"значение в пределах потолка принимается", "auth-service", intPtr(30), 30},
		{"значение выше потолка канала срезается", "auth-service", intPtr(100), 40},
		{"без запроса действует потолок канала", "auth-service", nil, 40},
		{"сервис без полосы не может её занять", "referal", intPtr(100), priorityBulk},
		{"отрицательное значение приводится к нулю", "auth-service", intPtr(-5), priorityBulk},
		{"неизвестный сервис остаётся в обычной очереди", "кто-то", nil, priorityBulk},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ns.resolvePriority(channelEmail, c.service, c.requested); got != c.want {
				t.Errorf("ожидалось %d, получено %d", c.want, got)
			}
		})
	}
}

// Битый JSON не должен превращаться в частично разобранные потолки: приоритет
// молча достался бы не тем отправителям. Канал откатывается на общие.
func TestParseServicePrioritiesFallsBackOnBadJSON(t *testing.T) {
	if got := parseServicePriorities(ChannelConfig{Channel: channelEmail, ServicePriorities: `{не json`}); got != nil {
		t.Errorf("битый JSON должен давать nil (общие потолки), получено %v", got)
	}
	if got := parseServicePriorities(ChannelConfig{Channel: channelEmail, ServicePriorities: `{}`}); got != nil {
		t.Errorf("пустой объект должен давать nil, получено %v", got)
	}
	if got := parseServicePriorities(ChannelConfig{Channel: channelEmail, ServicePriorities: ``}); got != nil {
		t.Errorf("пустая строка должна давать nil, получено %v", got)
	}

	parsed := parseServicePriorities(ChannelConfig{
		Channel:           channelEmail,
		ServicePriorities: `{"auth-service":100,"monitoring-service":50}`,
	})
	if parsed["auth-service"] != 100 || parsed["monitoring-service"] != 50 {
		t.Errorf("потолки разобраны неверно: %v", parsed)
	}
}

// Некорректное значение должно быть отвергнуто на записи, а не проигнорировано
// молча при чтении.
func TestValidateServicePriorities(t *testing.T) {
	valid := []string{``, `{}`, `{"auth-service":100}`, `{"auth-service":0,"referal":10}`}
	for _, raw := range valid {
		if err := validateServicePriorities(raw); err != nil {
			t.Errorf("%q должно приниматься, получена ошибка: %v", raw, err)
		}
	}

	invalid := []string{`{не json`, `{"auth-service":-1}`, `{"":100}`, `{"auth-service":"высокий"}`, `[100]`}
	for _, raw := range invalid {
		if err := validateServicePriorities(raw); err == nil {
			t.Errorf("%q должно быть отвергнуто", raw)
		}
	}
}

// Потолки канала правятся через тот же API, что и остальные его настройки.
func TestApplyChannelUpdateAcceptsServicePriorities(t *testing.T) {
	cfg := emailConfigForTest()

	updated, err := applyChannelUpdate(&cfg, map[string]interface{}{
		"service_priorities":            `{"auth-service":100}`,
		"priority_window_share_percent": float64(50),
	})
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if len(updated) != 2 {
		t.Errorf("ожидалось 2 изменённых поля, получено %v", updated)
	}
	if cfg.ServicePriorities != `{"auth-service":100}` {
		t.Errorf("потолки не сохранены: %q", cfg.ServicePriorities)
	}
	if cfg.PriorityWindowSharePercent != 50 {
		t.Errorf("доля окна не сохранена: %d", cfg.PriorityWindowSharePercent)
	}

	if _, err := applyChannelUpdate(&cfg, map[string]interface{}{"service_priorities": `{"auth-service":-1}`}); err == nil {
		t.Error("отрицательный потолок должен быть отвергнут")
	}

	// Доля выше 100 бессмысленна: резерв не может быть отрицательным
	if _, err := applyChannelUpdate(&cfg, map[string]interface{}{"priority_window_share_percent": float64(150)}); err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if cfg.PriorityWindowSharePercent != 100 {
		t.Errorf("доля выше 100 должна подтягиваться к 100, получено %d", cfg.PriorityWindowSharePercent)
	}
}

// Каждый канал считает долю окна от собственной пропускной способности.
func TestPriorityShareIsPerChannel(t *testing.T) {
	email := emailConfigForTest()
	telegram := telegramConfigForTest()

	emailShare := shareOf(email.effectivePerMinute(), email.PriorityWindowSharePercent)
	telegramShare := shareOf(telegram.effectivePerMinute(), telegram.PriorityWindowSharePercent)

	if emailShare != 11 {
		t.Errorf("почта: ожидалось 11 приоритетных в минуту, получено %d", emailShare)
	}
	if telegramShare != 1350 {
		t.Errorf("telegram: ожидалось 1350 приоритетных в минуту, получено %d", telegramShare)
	}

	// Разные каналы — разные доли: настройка одного не должна влиять на другой
	email.PriorityWindowSharePercent = 25
	if got := shareOf(email.effectivePerMinute(), email.PriorityWindowSharePercent); got != 3 {
		t.Errorf("почта при 25%%: ожидалось 3, получено %d", got)
	}
	if got := shareOf(telegram.effectivePerMinute(), telegram.PriorityWindowSharePercent); got != 1350 {
		t.Errorf("telegram не должен зависеть от настройки почты, получено %d", got)
	}
}
