package main

// limiter.go — пер-канальные ограничители темпа отправки.
//
// Один лимит на весь сервис не выражает того, что от нас требуют провайдеры:
//   - почта: жёсткая квота администраторов (сообщений в минуту), одно соединение
//   - telegram: три правила одновременно — 30 сообщений/сек на бота,
//     1 сообщение/сек в личный чат, 20 сообщений/мин в группу
//
// Поэтому лимитер собирается из независимых ограничителей, а решение принимается
// по самому строгому из них:
//
//	spacing   — минимальный интервал между сообщениями канала
//	global    — устойчивая скорость канала с допуском на всплеск (GCRA)
//	recipient — та же схема, но на каждого получателя отдельно (классы: default/group/...)
//	hourly    — квота за час
//	daily     — квота за сутки
//
// Reserve() НЕ спит. Он возвращает, сколько ждать, и списывает ресурс только если
// ожидание укладывается в бюджет вызывающего. Слишком долгое ожидание — сигнал
// диспетчеру отложить уведомление в очереди (next_attempt_at), а не держать воркер.

import (
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"
)

// Область лимита, которая заблокировала отправку. Диспетчеру важно различать:
// упёрлись в лимит канала — стоит вся очередь; упёрлись в лимит получателя —
// стоит только он, остальным можно слать.
const (
	limitScopeNone      = ""
	limitScopeChannel   = "channel"
	limitScopeRecipient = "recipient"

	// limitScopePriorityShare — приоритетная полоса выбрала свою долю окна.
	// Отличается от limitScopeChannel принципиально: канал не занят, занята
	// именно полоса, и стоящие ниже неприоритетные уведомления должны пойти —
	// ради них доля и зарезервирована.
	limitScopePriorityShare = "priority_share"
)

// gcra — token bucket в формулировке GCRA (generic cell rate algorithm).
//
// Хранит одно значение — theoretical arrival time — вместо счётчика токенов,
// поэтому «сколько ждать» считается без побочных эффектов: это и позволяет
// опросить все ограничители и списать только при общем согласии.
//
// interval  = 1 / скорость
// tolerance = (burst-1) * interval — допуск на мгновенный всплеск
type gcra struct {
	interval  time.Duration
	tolerance time.Duration
	tat       time.Time
}

// newGCRA собирает ограничитель из «сообщений в минуту» и размера всплеска.
// perMinute <= 0 => ограничитель выключен.
func newGCRA(perMinute, burst int) *gcra {
	if perMinute <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	interval := time.Minute / time.Duration(perMinute)
	return &gcra{
		interval:  interval,
		tolerance: time.Duration(burst-1) * interval,
	}
}

// peek возвращает, сколько ждать до следующей разрешённой отправки. Ничего не меняет.
func (g *gcra) peek(now time.Time) time.Duration {
	if g == nil || g.interval <= 0 {
		return 0
	}
	earliest := g.tat.Add(-g.tolerance)
	if earliest.After(now) {
		return earliest.Sub(now)
	}
	return 0
}

// commit списывает одну отправку, назначенную на момент at.
func (g *gcra) commit(at time.Time) {
	if g == nil || g.interval <= 0 {
		return
	}
	if g.tat.Before(at) {
		g.tat = at
	}
	g.tat = g.tat.Add(g.interval)
}

// quotaWindow — счётчик с фиксированным окном (квота за час/сутки).
type quotaWindow struct {
	limit  int
	window time.Duration
	count  int
	start  time.Time
}

func newQuotaWindow(limit int, window time.Duration) *quotaWindow {
	if limit <= 0 {
		return nil
	}
	return &quotaWindow{limit: limit, window: window}
}

func (q *quotaWindow) peek(now time.Time) time.Duration {
	if q == nil || q.limit <= 0 {
		return 0
	}
	if q.start.IsZero() || now.Sub(q.start) >= q.window {
		return 0
	}
	if q.count < q.limit {
		return 0
	}
	return q.start.Add(q.window).Sub(now)
}

func (q *quotaWindow) commit(at time.Time) {
	if q == nil || q.limit <= 0 {
		return
	}
	if q.start.IsZero() || at.Sub(q.start) >= q.window {
		q.start = at
		q.count = 0
	}
	q.count++
}

// recipientLimits — лимит на одного получателя для конкретного класса получателей.
// Классы задаёт транспорт (telegram: "" — личный чат, "group" — группа).
type recipientLimits struct {
	PerMinute int `json:"per_minute"`
	Burst     int `json:"burst"`
}

type recipientBucket struct {
	g    *gcra
	seen time.Time
}

// Получателей у канала может быть сколько угодно, держать ведро на каждого вечно
// нельзя. Записи, к которым долго не обращались, всё равно успели восстановиться
// до полного всплеска, поэтому их удаление лимит не ослабляет.
const recipientBucketTTL = 30 * time.Minute

// channelLimiter — полный набор ограничителей одного канала.
type channelLimiter struct {
	mu sync.Mutex

	channel string
	spacing time.Duration
	last    time.Time

	global *gcra
	hourly *quotaWindow
	daily  *quotaWindow

	// priorityShare — сколько мест в каждом окне доступно приоритетной полосе.
	// Считают только приоритетные отправки; исчерпав долю, полоса ждёт смены
	// окна, а остаток окна достаётся неприоритетной очереди.
	priorityShare []*quotaWindow

	// Лимиты получателей по классам: "" — класс по умолчанию.
	recipientLimits map[string]recipientLimits
	buckets         map[string]*recipientBucket
	lastEvict       time.Time

	// Слепок конфига, из которого собран лимитер: смена конфига пересобирает его.
	fingerprint string
}

// newChannelLimiter собирает лимитер канала из его конфига.
func newChannelLimiter(cfg ChannelConfig) *channelLimiter {
	l := &channelLimiter{
		channel:         cfg.Channel,
		spacing:         time.Duration(cfg.MinIntervalMS) * time.Millisecond,
		global:          newGCRA(cfg.RatePerMinute, cfg.Burst),
		hourly:          newQuotaWindow(cfg.QuotaPerHour, time.Hour),
		daily:           newQuotaWindow(cfg.QuotaPerDay, 24*time.Hour),
		recipientLimits: parseRecipientClassLimits(cfg),
		buckets:         make(map[string]*recipientBucket),
		priorityShare:   newPriorityShare(cfg),
		fingerprint:     cfg.limiterFingerprint(),
	}
	return l
}

// newPriorityShare строит счётчики доли приоритетной полосы — по одному на каждое
// настроенное окно канала (минута темпа, час, сутки).
//
// Без такой доли приоритет означал бы полное вытеснение: пока в очереди есть
// приоритетные уведомления, неприоритетные не отправятся никогда. Резерв в
// оставшейся части окна гарантирует, что массовая рассылка продвигается всегда,
// пусть и медленно.
func newPriorityShare(cfg ChannelConfig) []*quotaWindow {
	percent := cfg.PriorityWindowSharePercent
	if percent <= 0 || percent >= 100 {
		return nil // доля не ограничена: приоритет может занять всё окно
	}

	windows := []*quotaWindow{
		newQuotaWindow(shareOf(cfg.effectivePerMinute(), percent), time.Minute),
		newQuotaWindow(shareOf(cfg.QuotaPerHour, percent), time.Hour),
		newQuotaWindow(shareOf(cfg.QuotaPerDay, percent), 24*time.Hour),
	}

	out := windows[:0]
	for _, w := range windows {
		if w != nil {
			out = append(out, w)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// shareOf — доля окна, доступная приоритету. Округление вниз: доля не должна
// превышать заданную. Ниже единицы не опускаемся — иначе приоритетная полоса
// оказалась бы закрыта совсем.
func shareOf(windowLimit, percent int) int {
	if windowLimit <= 0 {
		return 0
	}
	share := windowLimit * percent / 100
	if share < 1 {
		share = 1
	}
	return share
}

// parseRecipientClassLimits разбирает лимиты получателей: колонки конфига дают
// класс по умолчанию, JSON recipient_class_limits — переопределения по классам.
func parseRecipientClassLimits(cfg ChannelConfig) map[string]recipientLimits {
	limits := make(map[string]recipientLimits)
	if cfg.PerRecipientPerMinute > 0 {
		limits[""] = recipientLimits{PerMinute: cfg.PerRecipientPerMinute, Burst: cfg.PerRecipientBurst}
	}

	raw := strings.TrimSpace(cfg.RecipientClassLimits)
	if raw == "" || raw == "{}" {
		return limits
	}

	var byClass map[string]recipientLimits
	if err := json.Unmarshal([]byte(raw), &byClass); err != nil {
		log.Printf("⚠️ channel %s: recipient_class_limits не разобран (%v), используются лимиты по умолчанию", cfg.Channel, err)
		return limits
	}
	for class, rl := range byClass {
		if rl.PerMinute > 0 {
			limits[class] = rl
		}
	}
	return limits
}

// bucketFor возвращает ведро получателя нужного класса; nil — лимита на получателя нет.
// Вызывается под l.mu.
func (l *channelLimiter) bucketFor(recipient, class string) *gcra {
	rl, ok := l.recipientLimits[class]
	if !ok {
		// Класс без собственного лимита падает на класс по умолчанию
		rl, ok = l.recipientLimits[""]
		if !ok {
			return nil
		}
		class = ""
	}
	if recipient == "" {
		return nil
	}

	key := class + "|" + recipient
	b, exists := l.buckets[key]
	if !exists {
		b = &recipientBucket{g: newGCRA(rl.PerMinute, rl.Burst)}
		l.buckets[key] = b
	}
	b.seen = time.Now()
	return b.g
}

// evict убирает ведра получателей, к которым давно не обращались. Под l.mu.
func (l *channelLimiter) evict(now time.Time) {
	if now.Sub(l.lastEvict) < recipientBucketTTL {
		return
	}
	l.lastEvict = now
	for key, b := range l.buckets {
		if now.Sub(b.seen) > recipientBucketTTL {
			delete(l.buckets, key)
		}
	}
}

// reserveRequest — что именно резервируется. Отдельный тип, потому что
// позиционных аргументов набралось столько, что перепутать их стало легко.
type reserveRequest struct {
	Recipient string
	Class     string
	Priority  int

	// ChannelBudget — ожидание из-за лимита канала, которое вызывающий готов
	// выдержать на месте. RecipientBudget — то же для лимита получателя; он
	// заметно короче, см. ниже.
	ChannelBudget   time.Duration
	RecipientBudget time.Duration
}

// Reserve опрашивает все ограничители канала и возвращает время ожидания.
//
// committed=true  — ресурс списан, вызывающий обязан отправить через wait.
// committed=false — ожидание не укладывается в бюджет, ничего не списано;
//
//	scope говорит, что упёрлось: канал, получатель или доля приоритетной полосы.
//
// Бюджета два, и это принципиально. Ожидание из-за лимита канала касается всей
// очереди — его есть смысл выждать на месте. Ожидание из-за лимита получателя
// касается его одного: выдерживать его в цикле значило бы задержать сообщения
// всем остальным получателям канала, поэтому бюджет здесь короткий, а сверх
// него уведомление откладывается в очередь.
func (l *channelLimiter) Reserve(req reserveRequest) (wait time.Duration, committed bool, scope string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.evict(now)

	recipient, class := req.Recipient, req.Class
	isPriority := req.Priority > priorityBulk

	// Долю полосы проверяем раньше остальных лимитов и не списываем ничего:
	// исчерпавшее долю приоритетное уведомление должно уступить место
	// неприоритетным, а не занять ресурс канала «про запас».
	if isPriority {
		if shareWait := l.priorityShareWait(now); shareWait > 0 {
			return shareWait, false, limitScopePriorityShare
		}
	}

	channelWait := time.Duration(0)
	if l.spacing > 0 && !l.last.IsZero() {
		if w := l.spacing - now.Sub(l.last); w > channelWait {
			channelWait = w
		}
	}
	if w := l.global.peek(now); w > channelWait {
		channelWait = w
	}
	if w := l.hourly.peek(now); w > channelWait {
		channelWait = w
	}
	if w := l.daily.peek(now); w > channelWait {
		channelWait = w
	}

	bucket := l.bucketFor(recipient, class)
	recipientWait := bucket.peek(now)

	// Отказ проверяем до списания: не уложились в бюджет — не тронули ни один
	// ограничитель, иначе отложенное уведомление съедало бы квоту вхолостую.
	if channelWait > req.ChannelBudget {
		return channelWait, false, limitScopeChannel
	}
	if recipientWait > req.RecipientBudget {
		return recipientWait, false, limitScopeRecipient
	}

	wait = channelWait
	scope = limitScopeChannel
	if recipientWait > wait {
		wait = recipientWait
		scope = limitScopeRecipient
	}
	if wait <= 0 {
		scope = limitScopeNone
	}

	at := now.Add(wait)
	l.last = at
	l.global.commit(at)
	l.hourly.commit(at)
	l.daily.commit(at)
	bucket.commit(at)

	if isPriority {
		for _, w := range l.priorityShare {
			w.commit(at)
		}
	}

	return wait, true, scope
}

// priorityShareWait — сколько приоритетной полосе ждать освобождения доли.
// Ноль означает, что доля ещё не выбрана. Под l.mu.
func (l *channelLimiter) priorityShareWait(now time.Time) time.Duration {
	var wait time.Duration
	for _, w := range l.priorityShare {
		if w := w.peek(now); w > wait {
			wait = w
		}
	}
	return wait
}

// blockUntil сдвигает ограничитель так, чтобы ближайшая отправка была не раньше
// момента until. Допуск на всплеск учитывается: без него накопленный burst
// позволил бы отправить раньше названного провайдером срока.
func (g *gcra) blockUntil(until time.Time) {
	if g == nil || g.interval <= 0 {
		return
	}
	earliest := until.Add(g.tolerance)
	if g.tat.Before(earliest) {
		g.tat = earliest
	}
}

// PenalizeChannel сдвигает окно всего канала вперёд: провайдер прислал 429 и
// назвал, сколько ждать. Без этого следующая отправка уйдёт по нашему расчёту
// темпа и снова получит отказ.
func (l *channelLimiter) PenalizeChannel(d time.Duration) {
	if d <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	until := time.Now().Add(d)
	if l.last.Before(until.Add(-l.spacing)) {
		l.last = until.Add(-l.spacing)
	}
	l.global.blockUntil(until)
}

// PenalizeRecipient сдвигает окно одного получателя. Возвращает false, если
// лимита на получателя у канала нет — тогда тормозить нужно канал целиком.
func (l *channelLimiter) PenalizeRecipient(recipient, class string, d time.Duration) bool {
	if d <= 0 || recipient == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket := l.bucketFor(recipient, class)
	if bucket == nil {
		return false
	}
	bucket.blockUntil(time.Now().Add(d))
	return true
}

// limiterRegistry хранит лимитеры каналов и пересобирает их при смене конфига.
type limiterRegistry struct {
	mu       sync.Mutex
	limiters map[string]*channelLimiter
}

func newLimiterRegistry() *limiterRegistry {
	return &limiterRegistry{limiters: make(map[string]*channelLimiter)}
}

// For возвращает лимитер канала, соответствующий текущему конфигу.
// Смена значений темпа в конфиге пересоздаёт лимитер: накопленное состояние
// сбрасывается, зато новые лимиты вступают в силу без рестарта сервиса.
func (r *limiterRegistry) For(cfg ChannelConfig) *channelLimiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	fp := cfg.limiterFingerprint()
	l, ok := r.limiters[cfg.Channel]
	if ok && l.fingerprint == fp {
		return l
	}
	if ok {
		log.Printf("♻️ Лимиты канала %s изменены, ограничитель пересобран", cfg.Channel)
	}
	l = newChannelLimiter(cfg)
	r.limiters[cfg.Channel] = l
	return l
}
