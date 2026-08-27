package main

// limiter.go — соблюдение лимитов Telegram Bot API.
//
// Бот один на портал, а шлют через него несколько сервисов: notification-service
// (уведомления пользователям и системные алерты) и auth-service (подтверждение
// входа, привязка аккаунта) — плюс ответы самого бота на входящие сообщения.
// Лимитер в вызывающем сервисе видит только свою долю трафика, поэтому
// ограничение соблюдается здесь: через этот процесс проходит всё.
//
// Ограничения Telegram (https://core.telegram.org/bots/faq#broadcasting-to-users):
//   30 сообщений в секунду суммарно
//   1 сообщение в секунду в один чат
//   20 сообщений в минуту в одну группу
//
// Группа отличается от личного чата знаком chat_id: у групп, супергрупп и
// каналов он отрицательный.

import (
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

// gcra — token bucket в формулировке GCRA: хранит момент следующей разрешённой
// отправки, поэтому ожидание считается без списания и все ограничения можно
// опросить до принятия решения.
type gcra struct {
	interval  time.Duration
	tolerance time.Duration
	tat       time.Time
}

func newGCRA(perMinute, burst int) *gcra {
	if perMinute <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	interval := time.Minute / time.Duration(perMinute)
	return &gcra{interval: interval, tolerance: time.Duration(burst-1) * interval}
}

func (g *gcra) peek(now time.Time) time.Duration {
	if g == nil {
		return 0
	}
	if earliest := g.tat.Add(-g.tolerance); earliest.After(now) {
		return earliest.Sub(now)
	}
	return 0
}

func (g *gcra) commit(at time.Time) {
	if g == nil {
		return
	}
	if g.tat.Before(at) {
		g.tat = at
	}
	g.tat = g.tat.Add(g.interval)
}

type chatBucket struct {
	g    *gcra
	seen time.Time
}

const chatBucketTTL = 30 * time.Minute

// SendLimiter соблюдает лимиты Telegram для всего трафика бота.
type SendLimiter struct {
	mu sync.Mutex

	global *gcra

	privatePerMinute int
	privateBurst     int
	groupPerMinute   int
	groupBurst       int

	chats     map[int64]*chatBucket
	lastEvict time.Time

	maxWait time.Duration
}

// NewSendLimiter собирает лимитер из окружения. Значения по умолчанию равны
// документированным лимитам Telegram; занижать их безопасно, завышать — нет.
func NewSendLimiter() *SendLimiter {
	perSecond := envInt("TELEGRAM_RATE_PER_SECOND", 30)
	burst := envInt("TELEGRAM_BURST", 30)

	l := &SendLimiter{
		global:           newGCRA(perSecond*60, burst),
		privatePerMinute: envInt("TELEGRAM_CHAT_PER_MINUTE", 60),
		privateBurst:     envInt("TELEGRAM_CHAT_BURST", 1),
		groupPerMinute:   envInt("TELEGRAM_GROUP_PER_MINUTE", 20),
		groupBurst:       envInt("TELEGRAM_GROUP_BURST", 1),
		chats:            make(map[int64]*chatBucket),
		maxWait:          time.Duration(envInt("TELEGRAM_MAX_WAIT_MS", 10000)) * time.Millisecond,
	}

	log.Printf("🚦 Telegram limits: %d msg/s (burst %d), личный чат %d/мин, группа %d/мин, максимум ожидания %s",
		perSecond, burst, l.privatePerMinute, l.groupPerMinute, l.maxWait)
	return l
}

func envInt(name string, def int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		log.Printf("WARNING: %s=%q не число, используется %d", name, raw, def)
		return def
	}
	return v
}

// bucketFor возвращает ведро чата. Вызывается под l.mu.
func (l *SendLimiter) bucketFor(chatID int64) *gcra {
	b, ok := l.chats[chatID]
	if !ok {
		perMinute, burst := l.privatePerMinute, l.privateBurst
		if chatID < 0 { // группа, супергруппа или канал
			perMinute, burst = l.groupPerMinute, l.groupBurst
		}
		b = &chatBucket{g: newGCRA(perMinute, burst)}
		l.chats[chatID] = b
	}
	b.seen = time.Now()
	return b.g
}

// evict убирает ведра чатов, к которым давно не обращались: за время простоя
// они всё равно восстановились до полного всплеска. Под l.mu.
func (l *SendLimiter) evict(now time.Time) {
	if now.Sub(l.lastEvict) < chatBucketTTL {
		return
	}
	l.lastEvict = now
	for id, b := range l.chats {
		if now.Sub(b.seen) > chatBucketTTL {
			delete(l.chats, id)
		}
	}
}

// reserve резервирует отправку и возвращает, сколько ждать.
// ok=false — ожидание превышает бюджет, вызывающему отвечаем 429 с retry_after.
func (l *SendLimiter) reserve(chatID int64) (wait time.Duration, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.evict(now)

	bucket := l.bucketFor(chatID)

	wait = l.global.peek(now)
	if w := bucket.peek(now); w > wait {
		wait = w
	}
	if wait > l.maxWait {
		return wait, false
	}

	at := now.Add(wait)
	l.global.commit(at)
	bucket.commit(at)
	return wait, true
}

// Wait выдерживает паузу, необходимую для соблюдения лимитов Telegram.
// Второе значение — false, если ждать пришлось бы дольше бюджета; тогда
// возвращается срок, который следует передать вызывающему как retry_after.
func (l *SendLimiter) Wait(chatID int64) (retryAfter time.Duration, ok bool) {
	wait, ok := l.reserve(chatID)
	if !ok {
		return wait, false
	}
	if wait > 0 {
		time.Sleep(wait)
	}
	return 0, true
}

// Penalize сдвигает окно после 429 от Telegram: наш расчёт темпа оказался
// оптимистичнее реального лимита, и продолжать по нему — снова получить отказ.
func (l *SendLimiter) Penalize(chatID int64, d time.Duration) {
	if d <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	until := time.Now().Add(d)
	if l.global != nil && l.global.tat.Before(until) {
		l.global.tat = until
	}
	if bucket := l.bucketFor(chatID); bucket != nil && bucket.tat.Before(until) {
		bucket.tat = until
	}
}
