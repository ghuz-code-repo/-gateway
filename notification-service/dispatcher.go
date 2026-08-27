package main

// dispatcher.go — отдельная очередь отправки на каждый канал.
//
// Раньше уведомление отправляла горутина, которая его создала, а пачка
// обрабатывалась одним последовательным циклом по всем типам сразу. Пер-канальные
// «ворота» стояли внутри этого цикла, поэтому пауза почты фактически задерживала
// telegram, стоявший в той же пачке следом.
//
// Теперь у канала своя очередь в БД (status=pending + next_attempt_at), свой
// диспетчер-горутина, свой лимитер и свой предел параллельности. Каналы не
// пересекаются нигде, кроме общей таблицы.
//
// Очередь живёт в БД, а не в памяти:
//   - жёсткая квота означает, что всплеск нужно откладывать, а не держать в горутине
//   - рестарт сервиса не теряет принятые уведомления
//
// API-обработчик только пишет строки и будит диспетчер нужного канала.

import (
	"context"
	"log"
	"sync"
	"time"
)

// Периодический проход нужен для того, что событием не приходит: отложенных по
// лимиту уведомлений и строк, переживших рестарт.
const dispatcherPollInterval = 5 * time.Second

// Потолок отсрочки. Квота суток может дать ожидание в часы; загонять уведомление
// так далеко бессмысленно — лучше вернуться к нему раньше и пересчитать.
const maxDeferDelay = 30 * time.Minute

type channelDispatcher struct {
	ns        *NotificationService
	transport Transport
	channel   string
	types     []NotificationType

	// typeValues — те же типы строками: выборка очереди подставляет их в IN,
	// и драйверу нужен обычный []string, а не срез именованного типа.
	typeValues []string

	wake chan struct{}
	stop chan struct{}
}

func newChannelDispatcher(ns *NotificationService, t Transport) *channelDispatcher {
	types := t.Types()
	values := make([]string, 0, len(types))
	for _, nt := range types {
		values = append(values, string(nt))
	}

	return &channelDispatcher{
		ns:         ns,
		transport:  t,
		channel:    t.Channel(),
		types:      types,
		typeValues: values,
		wake:       make(chan struct{}, 1),
		stop:       make(chan struct{}),
	}
}

// run — цикл диспетчера канала.
func (d *channelDispatcher) run() {
	ticker := time.NewTicker(dispatcherPollInterval)
	defer ticker.Stop()

	log.Printf("🚚 Диспетчер канала %s запущен (типы: %v)", d.channel, d.types)

	for {
		d.drain()

		select {
		case <-d.stop:
			log.Printf("🛑 Диспетчер канала %s остановлен", d.channel)
			return
		case <-d.wake:
		case <-ticker.C:
		}
	}
}

// stopped сообщает, попросили ли диспетчер завершиться.
func (d *channelDispatcher) stopped() bool {
	select {
	case <-d.stop:
		return true
	default:
		return false
	}
}

// sleepOrStop выдерживает паузу темпа, прерываясь на остановке сервиса.
func (d *channelDispatcher) sleepOrStop(wait time.Duration) bool {
	if wait <= 0 {
		return true
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-d.stop:
		return false
	}
}

// drain разбирает очередь канала, пока в ней есть готовые к отправке уведомления.
func (d *channelDispatcher) drain() {
	for {
		cfg := d.ns.channelConfig(d.channel)
		if !cfg.Enabled {
			return
		}

		batch, err := d.fetchReady(cfg)
		if err != nil {
			log.Printf("⚠️ Канал %s: не удалось выбрать очередь: %v", d.channel, err)
			return
		}
		if len(batch) == 0 {
			return
		}

		dispatched, channelBlocked, interrupted := d.dispatch(batch, cfg)

		// Статистику пачек обновляем после прохода, а не на каждое уведомление:
		// уведомления одной пачки теперь расходятся по каналам и обрабатываются
		// параллельно, так что промежуточные значения всё равно неполны.
		d.refreshBatches(batch)

		if d.stopped() || channelBlocked || dispatched == 0 {
			return
		}
		// Пришло новое уведомление: перечитываем очередь, чтобы приоритетное
		// не ждало конца текущей порции. У медленного канала эта порция идёт
		// минутами — там разница между «сразу» и «после порции» решающая.
		if interrupted {
			continue
		}
		if len(batch) < cfg.DrainBatchSize {
			return
		}
	}
}

// fetchReady забирает готовые к отправке уведомления канала.
//
// Порядок — приоритет, затем время создания. Приоритет решает исход при жёсткой
// квоте: при 15 письмах в минуту рассылка на сотню адресов занимает семь минут,
// и без приоритетной полосы письмо со сбросом пароля ждало бы всю рассылку.
func (d *channelDispatcher) fetchReady(cfg ChannelConfig) ([]Notification, error) {
	var batch []Notification
	err := d.ns.db.
		Where("status = ? AND type IN ? AND next_attempt_at <= ?", string(StatusPending), d.typeValues, time.Now().Unix()).
		Order("priority DESC, id ASC").
		Limit(cfg.DrainBatchSize).
		Find(&batch).Error
	return batch, err
}

// dispatch проводит выборку через лимитер и отправляет то, что разрешено.
//
// channelBlocked=true — канал целиком упёрся в лимит, продолжать проход нет смысла.
// interrupted=true   — в очередь пришло новое уведомление, порцию нужно перечитать.
func (d *channelDispatcher) dispatch(batch []Notification, cfg ChannelConfig) (dispatched int, channelBlocked, interrupted bool) {
	limiter := d.ns.limiters.For(cfg)
	sem := make(chan struct{}, cfg.MaxConcurrent)
	var wg sync.WaitGroup

	// Приоритетные уведомления, отложенные из-за исчерпанной доли окна.
	// Копим и переносим одним запросом: их в проходе может быть вся выборка.
	var (
		priorityShareBlocked bool
		priorityShareWait    time.Duration
		deferPriority        []uint
	)

	for i := range batch {
		if d.stopped() {
			break
		}
		// Сигнал забираем себе: перечитать очередь мы и так собираемся, а
		// оставленный сигнал заставил бы диспетчер крутиться вхолостую.
		// Проверяем только после первой отправки, иначе проход, начавшийся
		// одновременно с сигналом, прерывался бы, не сделав ничего.
		if dispatched > 0 && d.consumeWake() {
			interrupted = true
			break
		}
		n := &batch[i]

		// Доля приоритетной полосы уже выбрана — остаток окна принадлежит
		// обычной очереди. Приоритетные уведомления пропускаем без обращения
		// к лимитеру: ответ для них тот же, а неприоритетные, стоящие ниже,
		// должны пойти.
		if priorityShareBlocked && n.Priority > priorityBulk {
			deferPriority = append(deferPriority, n.ID)
			continue
		}

		wait, committed, scope := limiter.Reserve(reserveRequest{
			Recipient:       d.transport.LimiterKey(n),
			Class:           d.transport.RecipientClass(n),
			Priority:        n.Priority,
			ChannelBudget:   cfg.maxInlineWait(),
			RecipientBudget: cfg.maxInlineRecipientWait(),
		})

		if !committed {
			switch scope {
			case limitScopeChannel:
				// Очередь упорядочена, а лимит канала общий: всё, что стоит
				// следом, упрётся в то же ограничение. Откладываем проход целиком.
				d.deferNotification(n, wait, scope)
				channelBlocked = true

			case limitScopePriorityShare:
				// Канал свободен, исчерпана именно доля полосы. Откладываем это
				// уведомление и все приоритетные за ним, а проход продолжаем:
				// ради неприоритетных доля и зарезервирована.
				priorityShareBlocked = true
				priorityShareWait = wait
				deferPriority = append(deferPriority, n.ID)

			default:
				// Лимит конкретного получателя не мешает остальным
				d.deferNotification(n, wait, scope)
			}

			if channelBlocked {
				break
			}
			continue
		}

		if !d.sleepOrStop(wait) {
			break
		}

		if !d.claim(n) {
			continue
		}

		dispatched++
		wg.Add(1)
		sem <- struct{}{}
		go func(n *Notification) {
			defer wg.Done()
			defer func() { <-sem }()
			d.send(n, cfg, limiter)
		}(n)
	}

	wg.Wait()

	if len(deferPriority) > 0 {
		d.deferPriorityBatch(deferPriority, priorityShareWait)
	}

	return dispatched, channelBlocked, interrupted
}

// deferPriorityBatch переносит на следующее окно приоритетные уведомления,
// выбравшие свою долю. Одним запросом: их может быть вся выборка прохода.
func (d *channelDispatcher) deferPriorityBatch(ids []uint, wait time.Duration) {
	if wait <= 0 {
		wait = time.Second
	}
	if wait > maxDeferDelay {
		wait = maxDeferDelay
	}
	now := time.Now()

	if err := d.ns.db.Model(&Notification{}).
		Where("id IN ?", ids).
		Updates(map[string]interface{}{
			"next_attempt_at": now.Add(wait).Unix(),
			"updated_at":      now.Unix(),
		}).Error; err != nil {
		log.Printf("⚠️ Канал %s: не удалось отложить приоритетные уведомления: %v", d.channel, err)
		return
	}

	log.Printf("⏸️ Канал %s: приоритетная полоса выбрала свою долю окна, %d уведомлений отложено на %s — "+
		"остаток окна отдан обычной очереди", d.channel, len(ids), wait.Round(time.Second))
}

// consumeWake забирает сигнал о новых уведомлениях, если он есть.
func (d *channelDispatcher) consumeWake() bool {
	select {
	case <-d.wake:
		return true
	default:
		return false
	}
}

// claim переводит уведомление в статус sending и тем самым забирает его себе.
// Условие status=pending в UPDATE защищает от повторной отправки, если строку
// параллельно подобрал кто-то ещё (ручное вмешательство в БД, восстановление).
func (d *channelDispatcher) claim(n *Notification) bool {
	res := d.ns.db.Model(&Notification{}).
		Where("id = ? AND status = ?", n.ID, StatusPending).
		Updates(map[string]interface{}{
			"status":     StatusSending,
			"updated_at": time.Now().Unix(),
		})
	if res.Error != nil {
		log.Printf("⚠️ Канал %s: не удалось занять уведомление #%d: %v", d.channel, n.ID, res.Error)
		return false
	}
	return res.RowsAffected > 0
}

// deferNotification возвращает уведомление в очередь на более позднее время.
func (d *channelDispatcher) deferNotification(n *Notification, wait time.Duration, scope string) {
	if wait <= 0 {
		wait = time.Second
	}
	if wait > maxDeferDelay {
		wait = maxDeferDelay
	}
	next := time.Now().Add(wait).Unix()

	if err := d.ns.db.Model(&Notification{}).
		Where("id = ?", n.ID).
		Updates(map[string]interface{}{
			"next_attempt_at": next,
			"updated_at":      time.Now().Unix(),
		}).Error; err != nil {
		log.Printf("⚠️ Канал %s: не удалось отложить уведомление #%d: %v", d.channel, n.ID, err)
		return
	}

	log.Printf("⏸️ Канал %s: уведомление #%d отложено на %s (лимит: %s)", d.channel, n.ID, wait.Round(time.Second), scope)
}

// send выполняет одну попытку отправки и распоряжается результатом.
func (d *channelDispatcher) send(n *Notification, cfg ChannelConfig, limiter *channelLimiter) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.sendTimeout())
	defer cancel()

	attempt := n.Attempts + 1
	err := d.transport.Send(ctx, n, cfg)
	now := time.Now().Unix()

	if err == nil {
		d.ns.db.Model(&Notification{}).Where("id = ?", n.ID).Updates(map[string]interface{}{
			"status":       StatusSent,
			"sent_at":      now,
			"attempts":     attempt,
			"last_error":   "",
			"failure_code": "",
			"updated_at":   now,
		})
		log.Printf("✅ Канал %s: уведомление #%d отправлено с попытки %d", d.channel, n.ID, attempt)
		return
	}

	outcome := d.transport.Classify(err)
	// Истёкший таймаут — это не «навсегда»: провайдер мог не ответить вовремя.
	if ctx.Err() == context.DeadlineExceeded {
		outcome.Permanent = false
	}

	switch {
	case outcome.RateLimited:
		d.handleRateLimited(n, cfg, limiter, err, outcome, attempt)
	case outcome.Permanent:
		d.fail(n, cfg, err, attempt, "постоянная ошибка")
	case attempt >= cfg.MaxAttempts:
		d.fail(n, cfg, err, attempt, "исчерпаны попытки")
	default:
		delay := cfg.backoffFor(attempt)
		d.requeue(n, delay, map[string]interface{}{
			"attempts":   attempt,
			"last_error": err.Error(),
		})
		log.Printf("🔁 Канал %s: уведомление #%d, попытка %d/%d не удалась (%v), повтор через %s",
			d.channel, n.ID, attempt, cfg.MaxAttempts, err, delay.Round(time.Second))
	}
}

// handleRateLimited обрабатывает отказ провайдера по темпу.
//
// Попытка не засчитывается: провайдер не отверг сообщение, а попросил подождать.
// Считаем такие отказы отдельным счётчиком, иначе всплеск нагрузки съел бы
// все попытки и похоронил уведомления, которые в принципе доставимы.
func (d *channelDispatcher) handleRateLimited(n *Notification, cfg ChannelConfig, limiter *channelLimiter, err error, outcome sendOutcome, attempt int) {
	hits := n.RateLimitHits + 1
	if hits > cfg.MaxRateLimitRetries {
		d.fail(n, cfg, err, attempt, "исчерпаны повторы по лимиту темпа")
		return
	}

	delay := outcome.RetryAfter
	if !cfg.RespectRetryAfter || delay <= 0 {
		delay = cfg.backoffFor(hits)
	}

	// Провайдер сообщил, что мы обгоняем его лимит — наш расчёт темпа занижен.
	// Сдвигаем окно, иначе следующая отправка уйдёт по старому расчёту и получит
	// тот же отказ. Виноват конкретный получатель — тормозим только его.
	if key := d.transport.LimiterKey(n); key != "" &&
		limiter.PenalizeRecipient(key, d.transport.RecipientClass(n), delay) {
		log.Printf("🐢 Канал %s: получатель уведомления #%d притормозен на %s", d.channel, n.ID, delay.Round(time.Second))
	} else {
		limiter.PenalizeChannel(delay)
		log.Printf("🐢 Канал %s притормозен на %s по требованию провайдера", d.channel, delay.Round(time.Second))
	}

	d.requeue(n, delay, map[string]interface{}{
		"rate_limit_hits": hits,
		"last_error":      err.Error(),
	})
	log.Printf("⏳ Канал %s: уведомление #%d отложено по лимиту темпа (%d/%d) на %s",
		d.channel, n.ID, hits, cfg.MaxRateLimitRetries, delay.Round(time.Second))
}

// requeue возвращает уведомление в очередь на повтор.
func (d *channelDispatcher) requeue(n *Notification, delay time.Duration, fields map[string]interface{}) {
	if delay < 0 {
		delay = 0
	}
	now := time.Now()
	fields["status"] = StatusPending
	fields["next_attempt_at"] = now.Add(delay).Unix()
	fields["updated_at"] = now.Unix()

	if err := d.ns.db.Model(&Notification{}).Where("id = ?", n.ID).Updates(fields).Error; err != nil {
		log.Printf("⚠️ Канал %s: не удалось вернуть уведомление #%d в очередь: %v", d.channel, n.ID, err)
	}
}

// fail окончательно помечает уведомление проваленным.
func (d *channelDispatcher) fail(n *Notification, cfg ChannelConfig, err error, attempt int, reason string) {
	failureCode := failureSendFailed
	if n.FailureCode != "" {
		failureCode = n.FailureCode
	}
	now := time.Now().Unix()

	d.ns.db.Model(&Notification{}).Where("id = ?", n.ID).Updates(map[string]interface{}{
		"status":       StatusFailed,
		"attempts":     attempt,
		"last_error":   err.Error(),
		"failure_code": failureCode,
		"updated_at":   now,
	})
	log.Printf("❌ Канал %s: уведомление #%d провалено (%s, попытка %d): %v", d.channel, n.ID, reason, attempt, err)
}

// refreshBatches пересчитывает статистику пачек, затронутых проходом.
func (d *channelDispatcher) refreshBatches(batch []Notification) {
	seen := make(map[string]struct{})
	for i := range batch {
		id := batch[i].BatchID
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		d.ns.updateBatchStats(id)
	}
}

// --- реестр диспетчеров ---

// startDispatchers поднимает по диспетчеру на канал.
func (ns *NotificationService) startDispatchers() {
	for _, t := range ns.transports {
		d := newChannelDispatcher(ns, t)
		ns.dispatchers[t.Channel()] = d

		ns.wg.Add(1)
		go func(d *channelDispatcher) {
			defer ns.wg.Done()
			d.run()
		}(d)
	}
}

// stopDispatchers просит диспетчеры завершиться.
func (ns *NotificationService) stopDispatchers() {
	for _, d := range ns.dispatchers {
		close(d.stop)
	}
}

// wakeChannel будит диспетчер канала, не дожидаясь тика.
func (ns *NotificationService) wakeChannel(channel string) {
	d, ok := ns.dispatchers[channel]
	if !ok {
		return
	}
	select {
	case d.wake <- struct{}{}:
	default: // диспетчер уже разбужен
	}
}

// wakeForType будит канал, обслуживающий тип уведомления.
func (ns *NotificationService) wakeForType(t NotificationType) {
	if channel, ok := ns.typeChannel[t]; ok {
		ns.wakeChannel(channel)
	}
}

// requeueStuckSending возвращает в очередь уведомления, застрявшие в статусе
// sending: их отправлял процесс, который не пережил рестарт. Без этого они
// остаются в очереди навсегда — диспетчер выбирает только pending.
func (ns *NotificationService) requeueStuckSending() {
	res := ns.db.Model(&Notification{}).
		Where("status = ?", string(StatusSending)).
		Updates(map[string]interface{}{
			"status":          StatusPending,
			"next_attempt_at": 0,
			"updated_at":      time.Now().Unix(),
		})
	if res.Error != nil {
		log.Printf("⚠️ Не удалось вернуть в очередь уведомления в статусе sending: %v", res.Error)
		return
	}
	if res.RowsAffected > 0 {
		log.Printf("♻️ Возвращено в очередь после рестарта: %d уведомлений в статусе sending", res.RowsAffected)
	}
}
