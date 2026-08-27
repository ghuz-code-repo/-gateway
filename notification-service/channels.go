package main

// channels.go — конфигурация каналов доставки.
//
// Раньше настройки темпа жили плоскими колонками в NotificationConfig
// (delay_between_messages_ms — почта, telegram_delay_between_messages_ms —
// telegram), а выбор значения был зашит в код. Новый канал требовал колонки,
// ветки в коде и поля в форме.
//
// Теперь у каждого канала своя строка в channel_configs с полным набором
// параметров: темп, лимиты получателей, таймауты, ретраи, очередь. Добавление
// канала = реализация Transport + строка в таблице; лимитер, диспетчер и
// страница настроек его подхватывают сами.

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ChannelConfig — параметры одного канала доставки.
type ChannelConfig struct {
	Channel string `json:"channel" gorm:"primaryKey;size:32"`
	Enabled bool   `json:"enabled" gorm:"default:true"`

	// --- Темп отправки (лимиты провайдера) ---
	// MinIntervalMS — жёсткий минимальный интервал между сообщениями канала.
	// RatePerMinute + Burst — устойчивая скорость и допустимый мгновенный всплеск.
	// Quota* — суммарный потолок за окно; 0 = без квоты.
	MinIntervalMS int `json:"min_interval_ms" gorm:"default:0"`
	RatePerMinute int `json:"rate_per_minute" gorm:"default:0"`
	Burst         int `json:"burst" gorm:"default:1"`
	QuotaPerHour  int `json:"quota_per_hour" gorm:"default:0"`
	QuotaPerDay   int `json:"quota_per_day" gorm:"default:0"`

	// --- Лимит на одного получателя ---
	// Класс получателя определяет транспорт (telegram: личный чат против группы).
	// RecipientClassLimits — JSON переопределений: {"group":{"per_minute":20,"burst":1}}
	PerRecipientPerMinute int    `json:"per_recipient_per_minute" gorm:"default:0"`
	PerRecipientBurst     int    `json:"per_recipient_burst" gorm:"default:1"`
	RecipientClassLimits  string `json:"recipient_class_limits" gorm:"type:text"`

	// ServicePriorities — потолки приоритета отправителей ДЛЯ ЭТОГО КАНАЛА,
	// JSON вида {"auth-service":100,"monitoring-service":50}. Пусто — действуют
	// общие потолки из SERVICE_PRIORITIES. Каналы различаются по цене задержки:
	// подтверждение входа в telegram уходит мгновенно, а то же письмо стоит в
	// очереди почты минутами, поэтому и полосы у каналов разные.
	// Явный ноль («auth-service»: 0) выключает приоритет отправителя на канале.
	ServicePriorities string `json:"service_priorities" gorm:"type:text"`

	// PriorityWindowSharePercent — какую часть окна вправе занять приоритетная
	// полоса. Остаток окна зарезервирован за обычной очередью: без резерва
	// поток приоритетных уведомлений вытеснял бы массовые рассылки полностью,
	// и они не отправлялись бы никогда. Выбрав долю, приоритет ждёт следующего
	// окна. 0 или 100 — резерв выключен, приоритет может занять всё окно.
	PriorityWindowSharePercent int `json:"priority_window_share_percent" gorm:"default:75"`

	// --- Таймауты (мс) ---
	// ConnectTimeoutMS — установка соединения, SendTimeoutMS — потолок всей отправки.
	ConnectTimeoutMS int `json:"connect_timeout_ms" gorm:"default:10000"`
	SendTimeoutMS    int `json:"send_timeout_ms" gorm:"default:30000"`

	// --- Повторные попытки ---
	MaxAttempts         int  `json:"max_attempts" gorm:"default:3"`
	BackoffBaseMS       int  `json:"backoff_base_ms" gorm:"default:5000"`
	BackoffMaxMS        int  `json:"backoff_max_ms" gorm:"default:300000"`
	RespectRetryAfter   bool `json:"respect_retry_after" gorm:"default:true"`
	MaxRateLimitRetries int  `json:"max_rate_limit_retries" gorm:"default:10"`

	// --- Очередь канала ---
	// MaxConcurrent — сколько отправок канала идут одновременно.
	// DrainBatchSize — сколько уведомлений диспетчер забирает из БД за проход.
	// MaxInlineWaitMS — ожидание из-за лимита канала, которое диспетчер готов
	// выдержать на месте; сверх него уведомление уходит обратно в очередь.
	// MaxInlineRecipientWaitMS — то же для лимита конкретного получателя.
	// Второй порог заметно короче: пауза из-за лимита канала касается всей
	// очереди и всё равно неизбежна, а пауза из-за одного получателя не должна
	// задерживать сообщения всем остальным.
	MaxConcurrent            int `json:"max_concurrent" gorm:"default:1"`
	DrainBatchSize           int `json:"drain_batch_size" gorm:"default:50"`
	MaxInlineWaitMS          int `json:"max_inline_wait_ms" gorm:"default:15000"`
	MaxInlineRecipientWaitMS int `json:"max_inline_recipient_wait_ms" gorm:"default:1000"`

	// Extra — параметры, специфичные для канала (JSON). Читает только его транспорт.
	Extra string `json:"extra" gorm:"type:text"`

	CreatedAt int64 `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt int64 `json:"updated_at" gorm:"autoUpdateTime"`
}

func (ChannelConfig) TableName() string { return "channel_configs" }

// limiterFingerprint — слепок полей, влияющих на темп. Меняется => лимитер канала
// пересобирается, и новые лимиты действуют без рестарта.
func (c ChannelConfig) limiterFingerprint() string {
	return fmt.Sprintf("%d|%d|%d|%d|%d|%d|%d|%d|%s",
		c.MinIntervalMS, c.RatePerMinute, c.Burst, c.QuotaPerHour, c.QuotaPerDay,
		c.PerRecipientPerMinute, c.PerRecipientBurst, c.PriorityWindowSharePercent,
		strings.TrimSpace(c.RecipientClassLimits))
}

func (c ChannelConfig) connectTimeout() time.Duration {
	return time.Duration(c.ConnectTimeoutMS) * time.Millisecond
}

func (c ChannelConfig) sendTimeout() time.Duration {
	return time.Duration(c.SendTimeoutMS) * time.Millisecond
}

func (c ChannelConfig) maxInlineWait() time.Duration {
	return time.Duration(c.MaxInlineWaitMS) * time.Millisecond
}

func (c ChannelConfig) maxInlineRecipientWait() time.Duration {
	return time.Duration(c.MaxInlineRecipientWaitMS) * time.Millisecond
}

// effectivePerMinute — сколько сообщений канал пропускает за минуту с учётом
// обоих ограничений темпа. Доля приоритетной полосы считается от реальной
// пропускной способности, а не от одного из полей.
func (c ChannelConfig) effectivePerMinute() int {
	byRate := c.RatePerMinute

	byInterval := 0
	if c.MinIntervalMS > 0 {
		byInterval = 60000 / c.MinIntervalMS
	}

	switch {
	case byRate <= 0:
		return byInterval
	case byInterval <= 0:
		return byRate
	case byInterval < byRate:
		return byInterval
	default:
		return byRate
	}
}

// backoffFor — экспоненциальная пауза перед попыткой attempt (1-based) с потолком.
func (c ChannelConfig) backoffFor(attempt int) time.Duration {
	base := time.Duration(c.BackoffBaseMS) * time.Millisecond
	if base <= 0 {
		base = time.Second
	}
	max := time.Duration(c.BackoffMaxMS) * time.Millisecond
	if max <= 0 {
		max = 5 * time.Minute
	}

	d := base
	for i := 1; i < attempt && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}

// defaultChannelConfigs — заводские настройки каналов.
//
// Значения темпа отражают ограничения провайдеров, а не наши пожелания:
// менять их без согласования с администратором почты / документацией Telegram нельзя.
func defaultChannelConfigs() []ChannelConfig {
	return []ChannelConfig{
		{
			Channel: channelEmail,
			Enabled: true,
			// Администраторы почтового сервера разрешают не более 20 сообщений в минуту.
			// Держим запас: 1 сообщение раз в 4 секунды = 15/мин, всплески запрещены.
			MinIntervalMS: 4000,
			RatePerMinute: 15,
			Burst:         1,
			// Из 15 писем в минуту приоритетной полосе достаётся 11, четыре места
			// зарезервированы за обычной очередью: поток писем auth-service иначе
			// не дал бы массовым рассылкам отправиться вовсе.
			PriorityWindowSharePercent: 75,
			ConnectTimeoutMS:           10000,
			SendTimeoutMS:              30000,
			// SMTP-соединение одно: параллельная отправка не ускорит канал,
			// зато упрётся в лимит соединений на сервере.
			MaxConcurrent:            1,
			DrainBatchSize:           50,
			MaxInlineWaitMS:          15000,
			MaxInlineRecipientWaitMS: 1000,
			MaxAttempts:              3,
			BackoffBaseMS:            5000,
			BackoffMaxMS:             300000,
			RespectRetryAfter:        true,
			MaxRateLimitRetries:      10,
		},
		{
			Channel: channelTelegram,
			Enabled: true,
			// Лимиты Telegram Bot API:
			//   30 сообщений/сек на бота        -> 1800/мин, всплеск 30
			//   1 сообщение/сек в один чат      -> 60/мин на получателя, всплеск 1
			//   20 сообщений/мин в одну группу  -> класс "group" ниже
			RatePerMinute:              1800,
			Burst:                      30,
			PriorityWindowSharePercent: 75,
			PerRecipientPerMinute:      60,
			PerRecipientBurst:          1,
			RecipientClassLimits:       `{"group":{"per_minute":20,"burst":1}}`,
			ConnectTimeoutMS:           5000,
			SendTimeoutMS:              15000,
			MaxConcurrent:              8,
			DrainBatchSize:             100,
			// Пауза из-за общего лимита бота касается всей очереди — её выжидаем.
			// Пауза из-за лимита чата (секунда в личный, три в группу) касается
			// одного получателя: выдерживать её в цикле значило бы задержать всех
			// остальных, поэтому такое уведомление уходит обратно в очередь.
			MaxInlineWaitMS:          10000,
			MaxInlineRecipientWaitMS: 250,
			MaxAttempts:              3,
			BackoffBaseMS:            2000,
			BackoffMaxMS:             120000,
			RespectRetryAfter:        true,
			MaxRateLimitRetries:      10,
		},
		{
			Channel:                    channelSMS,
			Enabled:                    false,
			MinIntervalMS:              1000,
			PriorityWindowSharePercent: 75,
			ConnectTimeoutMS:           10000,
			SendTimeoutMS:              30000,
			MaxConcurrent:              1,
			DrainBatchSize:             50,
			MaxInlineWaitMS:            15000,
			MaxInlineRecipientWaitMS:   1000,
			MaxAttempts:                3,
			BackoffBaseMS:              5000,
			BackoffMaxMS:               300000,
			RespectRetryAfter:          true,
			MaxRateLimitRetries:        5,
		},
		{
			Channel:                    channelPush,
			Enabled:                    false,
			RatePerMinute:              600,
			Burst:                      20,
			PriorityWindowSharePercent: 75,
			ConnectTimeoutMS:           5000,
			SendTimeoutMS:              15000,
			MaxConcurrent:              4,
			DrainBatchSize:             100,
			MaxInlineWaitMS:            10000,
			MaxInlineRecipientWaitMS:   1000,
			MaxAttempts:                3,
			BackoffBaseMS:              2000,
			BackoffMaxMS:               120000,
			RespectRetryAfter:          true,
			MaxRateLimitRetries:        5,
		},
	}
}

// seedChannelConfigs создаёт недостающие строки каналов.
//
// Существующие строки не трогаются: заводские значения не должны затирать то,
// что администратор выставил через интерфейс. При первом создании email/telegram
// перенимают темп из легаси-полей NotificationConfig, чтобы обновление сервиса
// не изменило поведение молча.
func seedChannelConfigs(db *gorm.DB) error {
	var legacy NotificationConfig
	hasLegacy := db.First(&legacy).Error == nil

	for _, cfg := range defaultChannelConfigs() {
		if hasLegacy {
			switch cfg.Channel {
			case channelEmail:
				if legacy.DelayBetweenMessagesMS > cfg.MinIntervalMS {
					cfg.MinIntervalMS = legacy.DelayBetweenMessagesMS
				}
				if legacy.MaxRetryAttempts > 0 {
					cfg.MaxAttempts = legacy.MaxRetryAttempts
				}
			case channelTelegram:
				if legacy.TelegramDelayBetweenMessagesMS > 0 {
					cfg.MinIntervalMS = legacy.TelegramDelayBetweenMessagesMS
				}
				if legacy.MaxRetryAttempts > 0 {
					cfg.MaxAttempts = legacy.MaxRetryAttempts
				}
			}
		}

		// DoNothing: строка канала — источник истины после первого создания
		res := db.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "channel"}}, DoNothing: true}).Create(&cfg)
		if res.Error != nil {
			return fmt.Errorf("канал %s: %w", cfg.Channel, res.Error)
		}
		if res.RowsAffected > 0 {
			log.Printf("🌱 Канал %s: создан конфиг по умолчанию (min_interval=%dms, rate=%d/мин, burst=%d)",
				cfg.Channel, cfg.MinIntervalMS, cfg.RatePerMinute, cfg.Burst)
		}
	}
	return nil
}

// channelConfigCache — кэш конфигов каналов (диспетчеры читают их на каждом проходе).
//
// Потолки приоритета хранятся в конфиге строкой JSON, а нужны на каждом принятом
// уведомлении. Разбираем их один раз при обновлении кэша, а не на каждый запрос.
type channelConfigCache struct {
	mu         sync.RWMutex
	byChannel  map[string]ChannelConfig
	priorities map[string]map[string]int // канал -> сервис -> потолок приоритета
	fetchedAt  time.Time
}

const channelConfigTTL = 30 * time.Second

func newChannelConfigCache() *channelConfigCache {
	return &channelConfigCache{
		byChannel:  make(map[string]ChannelConfig),
		priorities: make(map[string]map[string]int),
	}
}

// snapshot отдаёт копию содержимого кэша. Копия нужна, чтобы вызывающий не
// работал с картой, которую параллельно перезаписывает обновление кэша.
func (c *channelConfigCache) snapshot() map[string]ChannelConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make(map[string]ChannelConfig, len(c.byChannel))
	for k, v := range c.byChannel {
		out[k] = v
	}
	return out
}

// fresh сообщает, не истёк ли кэш.
func (c *channelConfigCache) fresh() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Since(c.fetchedAt) < channelConfigTTL && len(c.byChannel) > 0
}

// store заполняет кэш и разбирает JSON-поля, которые нужны на горячем пути.
func (c *channelConfigCache) store(rows []ChannelConfig) {
	byChannel := make(map[string]ChannelConfig, len(rows))
	priorities := make(map[string]map[string]int, len(rows))

	for _, row := range rows {
		byChannel[row.Channel] = row
		if parsed := parseServicePriorities(row); parsed != nil {
			priorities[row.Channel] = parsed
		}
	}

	c.mu.Lock()
	c.byChannel = byChannel
	c.priorities = priorities
	c.fetchedAt = time.Now()
	c.mu.Unlock()
}

// channelConfigs возвращает конфиги всех каналов (кэш 30 с).
func (ns *NotificationService) channelConfigs() map[string]ChannelConfig {
	c := ns.channelCache

	if c.fresh() {
		return c.snapshot()
	}

	var rows []ChannelConfig
	if err := ns.db.Find(&rows).Error; err != nil {
		log.Printf("⚠️ Не удалось прочитать конфиги каналов: %v (используются предыдущие значения)", err)
		if out := c.snapshot(); len(out) > 0 {
			return out
		}
		// БД недоступна и кэш пуст — работаем на заводских значениях,
		// иначе отсутствие конфига означало бы отправку без лимитов вообще
		out := make(map[string]ChannelConfig)
		for _, cfg := range defaultChannelConfigs() {
			out[cfg.Channel] = cfg
		}
		return out
	}

	c.store(rows)
	return c.snapshot()
}

// channelServicePriorities возвращает потолки приоритета, заданные каналом.
// nil — канал своих потолков не задаёт, действуют общие из SERVICE_PRIORITIES.
func (ns *NotificationService) channelServicePriorities(channel string) map[string]int {
	// Обновляем кэш тем же путём, что и конфиги: разбор JSON живёт в нём
	if !ns.channelCache.fresh() {
		ns.channelConfigs()
	}

	ns.channelCache.mu.RLock()
	defer ns.channelCache.mu.RUnlock()
	return ns.channelCache.priorities[channel]
}

// channelConfig возвращает конфиг одного канала. Если строки нет (канал добавлен
// в код, но ещё не засеян) — заводские значения этого канала.
func (ns *NotificationService) channelConfig(channel string) ChannelConfig {
	if cfg, ok := ns.channelConfigs()[channel]; ok {
		return cfg
	}
	for _, cfg := range defaultChannelConfigs() {
		if cfg.Channel == channel {
			return cfg
		}
	}
	return ChannelConfig{Channel: channel, Enabled: false}
}

func (ns *NotificationService) invalidateChannelCache() {
	ns.channelCache.mu.Lock()
	ns.channelCache.fetchedAt = time.Time{}
	ns.channelCache.mu.Unlock()
}

// validateJSONObject отвергает мусор в JSON-полях до записи в БД: разобрать их
// потом будет некому, а молча проигнорированные лимиты — это отправка без лимитов.
func validateJSONObject(field, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var probe map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		return fmt.Errorf("поле %s: некорректный JSON-объект (%v)", field, err)
	}
	return nil
}

// channelUpdatableFields — поля, которые можно менять через API.
// Channel и временные метки в список не входят намеренно.
func channelUpdatableIntFields(cfg *ChannelConfig) map[string]*int {
	return map[string]*int{
		"min_interval_ms":               &cfg.MinIntervalMS,
		"rate_per_minute":               &cfg.RatePerMinute,
		"burst":                         &cfg.Burst,
		"quota_per_hour":                &cfg.QuotaPerHour,
		"quota_per_day":                 &cfg.QuotaPerDay,
		"per_recipient_per_minute":      &cfg.PerRecipientPerMinute,
		"per_recipient_burst":           &cfg.PerRecipientBurst,
		"priority_window_share_percent": &cfg.PriorityWindowSharePercent,
		"connect_timeout_ms":            &cfg.ConnectTimeoutMS,
		"send_timeout_ms":               &cfg.SendTimeoutMS,
		"max_attempts":                  &cfg.MaxAttempts,
		"backoff_base_ms":               &cfg.BackoffBaseMS,
		"backoff_max_ms":                &cfg.BackoffMaxMS,
		"max_rate_limit_retries":        &cfg.MaxRateLimitRetries,
		"max_concurrent":                &cfg.MaxConcurrent,
		"drain_batch_size":              &cfg.DrainBatchSize,
		"max_inline_wait_ms":            &cfg.MaxInlineWaitMS,
		"max_inline_recipient_wait_ms":  &cfg.MaxInlineRecipientWaitMS,
	}
}

// applyChannelUpdate применяет частичное обновление конфига канала.
// Возвращает список изменённых полей.
func applyChannelUpdate(cfg *ChannelConfig, patch map[string]interface{}) ([]string, error) {
	updated := []string{}

	for key, ptr := range channelUpdatableIntFields(cfg) {
		val, exists := patch[key]
		if !exists {
			continue
		}
		num, ok := val.(float64)
		if !ok {
			return nil, fmt.Errorf("поле %s: ожидалось число, получено %T", key, val)
		}
		if num < 0 {
			return nil, fmt.Errorf("поле %s: отрицательное значение %v", key, num)
		}
		*ptr = int(num)
		updated = append(updated, key)
	}

	boolFields := map[string]*bool{
		"enabled":             &cfg.Enabled,
		"respect_retry_after": &cfg.RespectRetryAfter,
	}
	for key, ptr := range boolFields {
		if val, exists := patch[key]; exists {
			b, ok := val.(bool)
			if !ok {
				return nil, fmt.Errorf("поле %s: ожидалось true/false, получено %T", key, val)
			}
			*ptr = b
			updated = append(updated, key)
		}
	}

	stringFields := map[string]*string{
		"recipient_class_limits": &cfg.RecipientClassLimits,
		"service_priorities":     &cfg.ServicePriorities,
		"extra":                  &cfg.Extra,
	}
	for key, ptr := range stringFields {
		if val, exists := patch[key]; exists {
			s, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("поле %s: ожидалась строка, получено %T", key, val)
			}
			if err := validateJSONObject(key, s); err != nil {
				return nil, err
			}
			if key == "service_priorities" {
				if err := validateServicePriorities(s); err != nil {
					return nil, err
				}
			}
			*ptr = s
			updated = append(updated, key)
		}
	}

	// Значения, при которых лимитер вырождается: burst < 1 запретил бы отправку
	// вовсе, max_concurrent < 1 остановил бы канал.
	if cfg.Burst < 1 {
		cfg.Burst = 1
	}
	if cfg.PerRecipientBurst < 1 {
		cfg.PerRecipientBurst = 1
	}
	if cfg.MaxConcurrent < 1 {
		cfg.MaxConcurrent = 1
	}
	if cfg.DrainBatchSize < 1 {
		cfg.DrainBatchSize = 1
	}
	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = 1
	}
	if cfg.PriorityWindowSharePercent > 100 {
		cfg.PriorityWindowSharePercent = 100
	}

	return updated, nil
}

// channelOrder возвращает имена каналов в порядке регистрации транспортов.
// Порядок стабилен, чтобы страница настроек не переставляла секции между загрузками.
func (ns *NotificationService) channelOrder() []string {
	out := make([]string, 0, len(ns.transports))
	for _, t := range ns.transports {
		out = append(out, t.Channel())
	}
	return out
}

// channelHTTPClient возвращает HTTP-клиент канала с его таймаутами.
//
// Клиент кэшируется, чтобы не терять пул соединений на каждой отправке, и
// пересобирается, когда администратор поменял таймауты в конфиге канала.
func (ns *NotificationService) channelHTTPClient(cfg ChannelConfig) *http.Client {
	fingerprint := fmt.Sprintf("%d|%d", cfg.ConnectTimeoutMS, cfg.SendTimeoutMS)

	ns.httpClientsMu.Lock()
	defer ns.httpClientsMu.Unlock()

	if cached, ok := ns.httpClients[cfg.Channel]; ok && cached.fingerprint == fingerprint {
		return cached.client
	}

	connect := cfg.connectTimeout()
	if connect <= 0 {
		connect = 5 * time.Second
	}
	total := cfg.sendTimeout()
	if total <= 0 {
		total = 30 * time.Second
	}

	client := &http.Client{
		Timeout: total,
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: connect}).DialContext,
			TLSHandshakeTimeout:   connect,
			ResponseHeaderTimeout: total,
			MaxIdleConns:          32,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
		},
	}
	ns.httpClients[cfg.Channel] = &cachedHTTPClient{client: client, fingerprint: fingerprint}
	return client
}

// --- HTTP API конфигов каналов ---

// getChannels отдаёт конфиги всех каналов вместе с состоянием их очередей.
func (ns *NotificationService) getChannels(c *gin.Context) {
	configs := ns.channelConfigs()

	out := make([]gin.H, 0, len(configs))
	for _, name := range ns.channelOrder() {
		cfg, ok := configs[name]
		if !ok {
			continue
		}
		out = append(out, gin.H{
			"config": cfg,
			"types":  ns.typesForChannel(name),
			"queue":  ns.channelQueueStats(name),
		})
	}

	c.JSON(http.StatusOK, gin.H{"channels": out})
}

// typesForChannel — типы уведомлений, которые обслуживает канал.
func (ns *NotificationService) typesForChannel(channel string) []NotificationType {
	for _, t := range ns.transports {
		if t.Channel() == channel {
			return t.Types()
		}
	}
	return nil
}

// channelQueueStats — сколько уведомлений канала ждёт отправки. Нужно, чтобы по
// странице настроек было видно, упёрся ли канал в лимит, а не гадать по логам.
func (ns *NotificationService) channelQueueStats(channel string) gin.H {
	types := ns.typesForChannel(channel)
	if len(types) == 0 {
		return gin.H{"pending": 0, "deferred": 0, "sending": 0}
	}
	values := make([]string, 0, len(types))
	for _, nt := range types {
		values = append(values, string(nt))
	}

	now := time.Now().Unix()
	var pending, deferred, sending int64

	ns.db.Model(&Notification{}).
		Where("status = ? AND type IN ? AND next_attempt_at <= ?", string(StatusPending), values, now).
		Count(&pending)
	ns.db.Model(&Notification{}).
		Where("status = ? AND type IN ? AND next_attempt_at > ?", string(StatusPending), values, now).
		Count(&deferred)
	ns.db.Model(&Notification{}).
		Where("status = ? AND type IN ?", string(StatusSending), values).
		Count(&sending)

	return gin.H{"pending": pending, "deferred": deferred, "sending": sending}
}

// updateChannel меняет конфиг одного канала (частичное обновление).
func (ns *NotificationService) updateChannel(c *gin.Context) {
	channel := c.Param("channel")

	known := false
	for _, name := range ns.channelOrder() {
		if name == channel {
			known = true
			break
		}
	}
	if !known {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("канал «%s» не зарегистрирован", channel)})
		return
	}

	var patch map[string]interface{}
	if err := c.ShouldBindJSON(&patch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var cfg ChannelConfig
	if err := ns.db.First(&cfg, "channel = ?", channel).Error; err != nil {
		cfg = ns.channelConfig(channel)
	}

	updated, err := applyChannelUpdate(&cfg, patch)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(updated) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "не передано ни одного известного поля"})
		return
	}

	if err := ns.db.Save(&cfg).Error; err != nil {
		log.Printf("❌ Не удалось сохранить конфиг канала %s: %v", channel, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "не удалось сохранить конфигурацию канала"})
		return
	}

	// Сброс кэша: лимитер пересоберётся на следующем проходе диспетчера,
	// HTTP-клиент — при следующей отправке
	ns.invalidateChannelCache()
	log.Printf("⚙️ Канал %s: обновлены поля %v", channel, updated)

	// Изменения могли включить канал или ослабить лимит — будим диспетчер
	ns.wakeChannel(channel)

	c.JSON(http.StatusOK, gin.H{
		"message":        "Конфигурация канала обновлена",
		"channel":        channel,
		"updated_fields": updated,
		"config":         cfg,
	})
}
