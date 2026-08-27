package main

import (
	"fmt"
	"testing"
	"time"
)

// approx сравнивает ожидание с допуском: Reserve считает паузы от time.Now(),
// поэтому на исполнение теста уходят микросекунды разницы.
func approx(t *testing.T, got, want time.Duration, what string) {
	t.Helper()
	const tolerance = 50 * time.Millisecond
	diff := got - want
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance {
		t.Errorf("%s: ожидание %s, получено %s", what, want, got)
	}
}

func emailConfigForTest() ChannelConfig {
	for _, cfg := range defaultChannelConfigs() {
		if cfg.Channel == channelEmail {
			return cfg
		}
	}
	panic("нет конфига канала email")
}

func telegramConfigForTest() ChannelConfig {
	for _, cfg := range defaultChannelConfigs() {
		if cfg.Channel == channelTelegram {
			return cfg
		}
	}
	panic("нет конфига канала telegram")
}

// Ограничение администраторов почты — 20 сообщений в минуту. Заводская настройка
// (интервал 4 с, 15/мин) обязана держаться ниже него на любом отрезке.
func TestEmailLimiterHoldsAdminQuota(t *testing.T) {
	cfg := emailConfigForTest()
	if cfg.MinIntervalMS != 4000 {
		t.Fatalf("ожидался интервал 4000 мс, в конфиге %d", cfg.MinIntervalMS)
	}

	l := newChannelLimiter(cfg)
	budget := time.Hour

	var waits []time.Duration
	for i := 0; i < 6; i++ {
		wait, committed, _ := l.Reserve(reserveRequest{Recipient: "", Class: recipientClassDefault, ChannelBudget: budget, RecipientBudget: budget})
		if !committed {
			t.Fatalf("отправка %d не зарезервирована при бюджете %s", i+1, budget)
		}
		waits = append(waits, wait)
	}

	for i, wait := range waits {
		approx(t, wait, time.Duration(i)*4*time.Second, fmt.Sprintf("отправка %d", i+1))
	}

	// За минуту укладывается не более 15 отправок — с запасом к лимиту 20
	sent := 0
	for _, wait := range waits {
		if wait < time.Minute {
			sent++
		}
	}
	if sent > 15 {
		t.Errorf("за минуту разрешено %d отправок, лимит настройки — 15", sent)
	}
}

// Ожидание сверх бюджета не должно списывать ресурс: иначе отложенное
// уведомление съедало бы квоту, ничего не отправив.
func TestReserveOverBudgetDoesNotConsume(t *testing.T) {
	cfg := emailConfigForTest()
	l := newChannelLimiter(cfg)

	if _, committed, _ := l.Reserve(reserveRequest{Recipient: "", Class: recipientClassDefault, ChannelBudget: time.Hour, RecipientBudget: time.Hour}); !committed {
		t.Fatal("первая отправка должна пройти")
	}

	// Следующая требует 4 с — бюджета в 1 с не хватает
	wait, committed, scope := l.Reserve(reserveRequest{Recipient: "", Class: recipientClassDefault, ChannelBudget: time.Second, RecipientBudget: time.Second})
	if committed {
		t.Fatal("отправка сверх бюджета не должна резервироваться")
	}
	if scope != limitScopeChannel {
		t.Errorf("ожидался лимит канала, получено %q", scope)
	}
	approx(t, wait, 4*time.Second, "ожидание сверх бюджета")

	// Ресурс не списан: с полным бюджетом пауза та же самая, а не удвоенная
	wait, committed, _ = l.Reserve(reserveRequest{Recipient: "", Class: recipientClassDefault, ChannelBudget: time.Hour, RecipientBudget: time.Hour})
	if !committed {
		t.Fatal("отправка с полным бюджетом должна пройти")
	}
	approx(t, wait, 4*time.Second, "повторный резерв после отказа")
}

// Telegram разрешает 30 сообщений в секунду на бота: первые 30 уходят сразу,
// следующее ждёт свой такт.
func TestTelegramGlobalRate(t *testing.T) {
	cfg := telegramConfigForTest()
	l := newChannelLimiter(cfg)
	budget := time.Minute

	for i := 0; i < 30; i++ {
		// Разные получатели: проверяем именно общий лимит бота
		wait, committed, _ := l.Reserve(reserveRequest{Recipient: fmt.Sprintf("%d", 1000+i), Class: recipientClassDefault, ChannelBudget: budget, RecipientBudget: budget})
		if !committed {
			t.Fatalf("сообщение %d не зарезервировано", i+1)
		}
		approx(t, wait, 0, fmt.Sprintf("сообщение %d из всплеска", i+1))
	}

	wait, committed, _ := l.Reserve(reserveRequest{Recipient: "2000", Class: recipientClassDefault, ChannelBudget: budget, RecipientBudget: budget})
	if !committed {
		t.Fatal("31-е сообщение должно резервироваться с задержкой")
	}
	approx(t, wait, time.Second/30, "31-е сообщение")
}

// Telegram разрешает 1 сообщение в секунду в один чат. Ключевое требование:
// занятый чат не задерживает остальных — его сообщение откладывается в очередь,
// а канал продолжает работать.
func TestTelegramPerChatRate(t *testing.T) {
	cfg := telegramConfigForTest()
	l := newChannelLimiter(cfg)
	chanBudget, rcptBudget := cfg.maxInlineWait(), cfg.maxInlineRecipientWait()

	if _, committed, _ := l.Reserve(reserveRequest{Recipient: "111", Class: recipientClassDefault, ChannelBudget: chanBudget, RecipientBudget: rcptBudget}); !committed {
		t.Fatal("первое сообщение в чат должно пройти")
	}

	// Секунда ожидания больше бюджета получателя: сообщение откладывается,
	// ресурс канала при этом не тратится
	wait, committed, scope := l.Reserve(reserveRequest{Recipient: "111", Class: recipientClassDefault, ChannelBudget: chanBudget, RecipientBudget: rcptBudget})
	if committed {
		t.Fatal("второе сообщение в тот же чат должно откладываться, а не ждать в цикле")
	}
	if scope != limitScopeRecipient {
		t.Errorf("ожидался лимит получателя, получено %q", scope)
	}
	approx(t, wait, time.Second, "ожидание второго сообщения в тот же чат")

	// Занятый чат не должен стоить темпа остальным
	for _, chat := range []string{"222", "333", "444"} {
		wait, committed, _ = l.Reserve(reserveRequest{Recipient: chat, Class: recipientClassDefault, ChannelBudget: chanBudget, RecipientBudget: rcptBudget})
		if !committed {
			t.Fatalf("сообщение в чат %s должно пройти", chat)
		}
		approx(t, wait, 0, "сообщение в свободный чат "+chat)
	}
}

// Лимит группы (20/мин) тоже не должен останавливать канал: сообщение группе
// откладывается, личные чаты продолжают получать сообщения.
func TestGroupLimitDoesNotStallChannel(t *testing.T) {
	cfg := telegramConfigForTest()
	l := newChannelLimiter(cfg)
	chanBudget, rcptBudget := cfg.maxInlineWait(), cfg.maxInlineRecipientWait()

	const group = "-1001234567890"
	if _, committed, _ := l.Reserve(reserveRequest{Recipient: group, Class: recipientClassGroup, ChannelBudget: chanBudget, RecipientBudget: rcptBudget}); !committed {
		t.Fatal("первое сообщение в группу должно пройти")
	}

	wait, committed, scope := l.Reserve(reserveRequest{Recipient: group, Class: recipientClassGroup, ChannelBudget: chanBudget, RecipientBudget: rcptBudget})
	if committed {
		t.Fatal("второе сообщение в группу должно откладываться")
	}
	if scope != limitScopeRecipient {
		t.Errorf("ожидался лимит получателя, получено %q", scope)
	}
	approx(t, wait, 3*time.Second, "ожидание второго сообщения в группу")

	wait, committed, _ = l.Reserve(reserveRequest{Recipient: "555", Class: recipientClassDefault, ChannelBudget: chanBudget, RecipientBudget: rcptBudget})
	if !committed || wait != 0 {
		t.Errorf("личный чат должен получить сообщение сразу, получено wait=%s committed=%v", wait, committed)
	}
}

// Для групп Telegram ограничивает темп до 20 сообщений в минуту — это 3 секунды
// между сообщениями, а не 1, как в личном чате.
func TestTelegramGroupRate(t *testing.T) {
	cfg := telegramConfigForTest()
	l := newChannelLimiter(cfg)
	budget := time.Minute

	const group = "-1001234567890"
	if _, committed, _ := l.Reserve(reserveRequest{Recipient: group, Class: recipientClassGroup, ChannelBudget: budget, RecipientBudget: budget}); !committed {
		t.Fatal("первое сообщение в группу должно пройти")
	}

	wait, committed, _ := l.Reserve(reserveRequest{Recipient: group, Class: recipientClassGroup, ChannelBudget: budget, RecipientBudget: budget})
	if !committed {
		t.Fatal("второе сообщение в группу должно резервироваться с задержкой")
	}
	approx(t, wait, 3*time.Second, "второе сообщение в группу")
}

// Отрицательный chat_id — признак группы: транспорт обязан выбрать для него
// строгий набор лимитов.
func TestTelegramRecipientClass(t *testing.T) {
	tr := &telegramTransport{}

	cases := map[string]string{
		"123456789":      recipientClassDefault,
		"-1001234567890": recipientClassGroup,
	}
	for recipient, want := range cases {
		got := tr.RecipientClass(&Notification{Type: NotificationTypeTelegram, Recipient: recipient})
		if got != want {
			t.Errorf("получатель %s: ожидался класс %q, получен %q", recipient, want, got)
		}
	}
}

// Квота за окно ограничивает суммарный объём, а не только темп.
func TestQuotaPerHour(t *testing.T) {
	cfg := ChannelConfig{Channel: "test", QuotaPerHour: 3, RatePerMinute: 6000, Burst: 100}
	l := newChannelLimiter(cfg)
	budget := 24 * time.Hour

	for i := 0; i < 3; i++ {
		wait, committed, _ := l.Reserve(reserveRequest{Recipient: "", Class: recipientClassDefault, ChannelBudget: budget, RecipientBudget: budget})
		if !committed {
			t.Fatalf("отправка %d в пределах квоты должна пройти", i+1)
		}
		approx(t, wait, 0, fmt.Sprintf("отправка %d в пределах квоты", i+1))
	}

	wait, committed, scope := l.Reserve(reserveRequest{Recipient: "", Class: recipientClassDefault, ChannelBudget: budget, RecipientBudget: budget})
	if !committed {
		t.Fatal("отправка сверх квоты должна резервироваться на следующее окно")
	}
	if scope != limitScopeChannel {
		t.Errorf("ожидался лимит канала, получено %q", scope)
	}
	approx(t, wait, time.Hour, "отправка сверх часовой квоты")
}

// Лимитер без настроек не должен ничего задерживать: канал без лимитов
// провайдера обязан работать на полной скорости.
func TestUnlimitedChannel(t *testing.T) {
	l := newChannelLimiter(ChannelConfig{Channel: "test"})
	for i := 0; i < 100; i++ {
		wait, committed, _ := l.Reserve(reserveRequest{Recipient: "someone", Class: recipientClassDefault, ChannelBudget: time.Second, RecipientBudget: time.Second})
		if !committed || wait != 0 {
			t.Fatalf("отправка %d: ожидалась мгновенная выдача, получено wait=%s committed=%v", i+1, wait, committed)
		}
	}
}

// 429 от провайдера сдвигает окно: следующая отправка не должна уйти по старому
// расчёту темпа и получить тот же отказ.
func TestPenalize(t *testing.T) {
	cfg := telegramConfigForTest()
	l := newChannelLimiter(cfg)

	l.PenalizeChannel(30 * time.Second)
	wait, _, _ := l.Reserve(reserveRequest{Recipient: "999", Class: recipientClassDefault, ChannelBudget: time.Minute, RecipientBudget: time.Minute})
	approx(t, wait, 30*time.Second, "отправка после штрафа канала")

	l2 := newChannelLimiter(cfg)
	if !l2.PenalizeRecipient("777", recipientClassDefault, 20*time.Second) {
		t.Fatal("штраф получателя должен применяться, когда лимит на получателя настроен")
	}
	wait, _, scope := l2.Reserve(reserveRequest{Recipient: "777", Class: recipientClassDefault, ChannelBudget: time.Minute, RecipientBudget: time.Minute})
	approx(t, wait, 20*time.Second, "отправка после штрафа получателя")
	if scope != limitScopeRecipient {
		t.Errorf("ожидался лимит получателя, получено %q", scope)
	}

	// У канала без лимита на получателя штрафовать некого — тормозить нужно канал
	l3 := newChannelLimiter(emailConfigForTest())
	if l3.PenalizeRecipient("someone@example.com", recipientClassDefault, time.Minute) {
		t.Error("канал без лимита на получателя не должен принимать штраф получателя")
	}
}

// Классы получателей разбираются из конфига: колонки дают класс по умолчанию,
// JSON — переопределения.
func TestParseRecipientClassLimits(t *testing.T) {
	cfg := telegramConfigForTest()
	limits := parseRecipientClassLimits(cfg)

	if limits[recipientClassDefault].PerMinute != 60 {
		t.Errorf("личный чат: ожидалось 60/мин, получено %d", limits[recipientClassDefault].PerMinute)
	}
	if limits[recipientClassGroup].PerMinute != 20 {
		t.Errorf("группа: ожидалось 20/мин, получено %d", limits[recipientClassGroup].PerMinute)
	}

	// Битый JSON не должен ронять канал: остаются лимиты из колонок
	broken := cfg
	broken.RecipientClassLimits = "{не json"
	limits = parseRecipientClassLimits(broken)
	if limits[recipientClassDefault].PerMinute != 60 {
		t.Error("при битом JSON должны остаться лимиты из колонок конфига")
	}
	if _, ok := limits[recipientClassGroup]; ok {
		t.Error("битый JSON не должен давать классов")
	}
}

// Пауза перед повтором растёт экспоненциально и упирается в потолок.
func TestBackoffFor(t *testing.T) {
	cfg := ChannelConfig{BackoffBaseMS: 1000, BackoffMaxMS: 8000}

	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second}
	for i, expected := range want {
		if got := cfg.backoffFor(i + 1); got != expected {
			t.Errorf("попытка %d: ожидалось %s, получено %s", i+1, expected, got)
		}
	}
}

// Изменение лимитов в конфиге должно пересобирать лимитер, иначе новые значения
// не подействуют без рестарта сервиса.
func TestLimiterRegistryRebuildsOnConfigChange(t *testing.T) {
	reg := newLimiterRegistry()
	cfg := emailConfigForTest()

	first := reg.For(cfg)
	if second := reg.For(cfg); first != second {
		t.Error("без изменений конфига лимитер должен переиспользоваться")
	}

	cfg.MinIntervalMS = 6000
	if third := reg.For(cfg); third == first {
		t.Error("после смены лимитов должен собираться новый лимитер")
	}
}

// Приоритет не должен вытеснять обычную очередь целиком: за ней зарезервирована
// часть окна. Выбрав свою долю, приоритетная полоса ждёт следующего окна, а
// остаток окна достаётся неприоритетным уведомлениям.
func TestPriorityShareReservesWindowForBulk(t *testing.T) {
	// 12 сообщений в минуту без интервала: доля приоритета 75% = 9, обычной
	// очереди остаётся 3
	cfg := ChannelConfig{
		Channel:                    "test",
		RatePerMinute:              12,
		Burst:                      12,
		PriorityWindowSharePercent: 75,
	}
	l := newChannelLimiter(cfg)
	budget := time.Minute

	priority := func() (time.Duration, bool, string) {
		return l.Reserve(reserveRequest{Priority: priorityHigh, ChannelBudget: budget, RecipientBudget: budget})
	}
	bulk := func() (time.Duration, bool, string) {
		return l.Reserve(reserveRequest{Priority: priorityBulk, ChannelBudget: budget, RecipientBudget: budget})
	}

	for i := 0; i < 9; i++ {
		wait, committed, _ := priority()
		if !committed {
			t.Fatalf("приоритетная отправка %d в пределах доли должна пройти", i+1)
		}
		approx(t, wait, 0, fmt.Sprintf("приоритетная отправка %d", i+1))
	}

	// Доля выбрана: следующее приоритетное ждёт смены окна и ничего не списывает
	wait, committed, scope := priority()
	if committed {
		t.Fatal("приоритет сверх доли не должен резервироваться")
	}
	if scope != limitScopePriorityShare {
		t.Errorf("ожидалась область %q, получена %q", limitScopePriorityShare, scope)
	}
	approx(t, wait, time.Minute, "ожидание приоритета сверх доли")

	// Зарезервированная часть окна свободна для обычной очереди
	for i := 0; i < 3; i++ {
		wait, committed, _ = bulk()
		if !committed {
			t.Fatalf("неприоритетная отправка %d должна пройти: доля зарезервирована за ней", i+1)
		}
		approx(t, wait, 0, fmt.Sprintf("неприоритетная отправка %d", i+1))
	}

	// Окно исчерпано целиком — дальше ждут все
	if _, _, scope = bulk(); scope != limitScopeChannel {
		t.Errorf("после исчерпания окна ожидалась область %q, получена %q", limitScopeChannel, scope)
	}
}

// Отказ по доле не должен ничего списывать: иначе отложенное уведомление
// съедало бы место в окне, ничего не отправив.
func TestPriorityShareRejectionConsumesNothing(t *testing.T) {
	cfg := ChannelConfig{
		Channel:                    "test",
		RatePerMinute:              12,
		Burst:                      12,
		PriorityWindowSharePercent: 75,
	}
	l := newChannelLimiter(cfg)
	budget := time.Minute

	for i := 0; i < 9; i++ {
		l.Reserve(reserveRequest{Priority: priorityHigh, ChannelBudget: budget, RecipientBudget: budget})
	}
	for i := 0; i < 5; i++ {
		l.Reserve(reserveRequest{Priority: priorityHigh, ChannelBudget: budget, RecipientBudget: budget})
	}

	// Пять отказов подряд не должны были занять места в окне: обычной очереди
	// по-прежнему доступны все три
	for i := 0; i < 3; i++ {
		wait, committed, _ := l.Reserve(reserveRequest{Priority: priorityBulk, ChannelBudget: budget, RecipientBudget: budget})
		if !committed {
			t.Fatalf("неприоритетная отправка %d должна пройти", i+1)
		}
		approx(t, wait, 0, fmt.Sprintf("неприоритетная отправка %d", i+1))
	}
}

// Доля считается от реальной пропускной способности канала, а не от одного поля:
// у почты темп задан и интервалом, и скоростью.
func TestEffectivePerMinute(t *testing.T) {
	cases := []struct {
		cfg  ChannelConfig
		want int
	}{
		{ChannelConfig{MinIntervalMS: 4000, RatePerMinute: 15}, 15},
		{ChannelConfig{MinIntervalMS: 6000, RatePerMinute: 15}, 10}, // интервал строже
		{ChannelConfig{MinIntervalMS: 4000}, 15},
		{ChannelConfig{RatePerMinute: 1800}, 1800},
		{ChannelConfig{}, 0},
	}

	for _, c := range cases {
		if got := c.cfg.effectivePerMinute(); got != c.want {
			t.Errorf("interval=%d rate=%d: ожидалось %d/мин, получено %d",
				c.cfg.MinIntervalMS, c.cfg.RatePerMinute, c.want, got)
		}
	}
}

// Настройки почты: приоритету 11 писем в минуту, обычной очереди — 4.
func TestEmailPriorityShare(t *testing.T) {
	cfg := emailConfigForTest()

	share := shareOf(cfg.effectivePerMinute(), cfg.PriorityWindowSharePercent)
	if share != 11 {
		t.Errorf("ожидалось 11 приоритетных писем в минуту, получено %d", share)
	}
	if reserved := cfg.effectivePerMinute() - share; reserved != 4 {
		t.Errorf("обычной очереди должно оставаться 4 письма в минуту, получено %d", reserved)
	}
}

// Резерв выключается значениями 0 и 100: приоритет занимает всё окно.
func TestPriorityShareDisabled(t *testing.T) {
	for _, percent := range []int{0, 100} {
		cfg := ChannelConfig{Channel: "test", RatePerMinute: 12, Burst: 12, PriorityWindowSharePercent: percent}
		l := newChannelLimiter(cfg)

		for i := 0; i < 12; i++ {
			_, committed, scope := l.Reserve(reserveRequest{Priority: priorityHigh, ChannelBudget: time.Minute, RecipientBudget: time.Minute})
			if !committed {
				t.Fatalf("percent=%d: приоритетная отправка %d должна пройти", percent, i+1)
			}
			if scope == limitScopePriorityShare {
				t.Fatalf("percent=%d: резерв должен быть выключен", percent)
			}
		}
	}
}

// Доля не может опуститься до нуля: иначе приоритетная полоса оказалась бы
// закрыта совсем и приоритетное уведомление не ушло бы никогда.
func TestPriorityShareNeverZero(t *testing.T) {
	if got := shareOf(1, 75); got != 1 {
		t.Errorf("при пропускной способности 1/мин доля должна быть 1, получено %d", got)
	}
	if got := shareOf(0, 75); got != 0 {
		t.Errorf("без ограничения окна доли быть не должно, получено %d", got)
	}
}
