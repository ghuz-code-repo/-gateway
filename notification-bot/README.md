# Notification Bot

Telegram-бот портала (https://t.me/notification_analytics_gh_uz_bot) — **единственная точка отправки в Telegram API** для всей системы. Используется для:

1. **Всех системных уведомлений** — notification-service пересылает через этот сервис типы `telegram` и `telegram_system` (алерты мониторинга, security-алерты и т.д.).
2. **Привязки Telegram к аккаунту** — пользователь в личном кабинете вводит свой username, получает на почту deep-link `https://t.me/notification_analytics_gh_uz_bot?start=<токен>`; переход по ссылке стартует бота и подтверждает привязку.
3. **Входа через Telegram** — при входе через `/login/telegram` бот присылает сообщение с кнопками «Подтвердить вход» / «Отклонить вход». 3 и более отклонений замораживают вход через Telegram до следующего входа по логину и паролю.
4. **Сброса пароля через Telegram** — на `/forgot-password` можно выбрать доставку ссылки в Telegram вместо email.

## Архитектура

```
Браузер ──► nginx ──► auth-service ─────► notification-bot ──► Telegram API
                          ▲                    ▲   │ (long polling)
                          │                    │   │
                          │    notification-service (telegram, telegram_system)
                          │                        │
                          └────────────────────────┘
                        /api/telegram/* (X-API-Key)
```

ВАЖНО: только notification-bot обращается к Telegram API. Никакой другой сервис не должен
вызывать `getUpdates` с этим же токеном — long polling двух потребителей конфликтует.

- Бот работает через **long polling** (`getUpdates`), вебхук и открытые порты наружу не нужны.
- Всё состояние (токены привязки, запросы входа, счётчики отклонений) хранится в MongoDB **auth-service**; notification-bot — stateless.
- Внутренний HTTP API (`POST /api/v1/send`) защищён заголовком `X-API-Key` (тот же `INTERNAL_API_KEY`, что и в auth-service).

## API

### POST /api/v1/send

Отправка сообщения (вызывается auth-service):

```json
{
  "chat_id": 123456789,
  "text": "Текст сообщения",
  "parse_mode": "Markdown",
  "buttons": [[
    {"text": "✅ Подтвердить вход", "callback_data": "login:<request_id>:approve"},
    {"text": "🚫 Отклонить вход",  "callback_data": "login:<request_id>:reject"}
  ]]
}
```

`parse_mode` (опционально): `Markdown` | `MarkdownV2` | `HTML`; `buttons` тоже опциональны.

Ответы:

| Код | Значение |
|---|---|
| `200` | `{"success": true, "message_id": 42}` |
| `429` | Темп превышен: `{"error": "...", "retry_after": 5}` + заголовок `Retry-After`. Сообщение **не отправлено** — вернуть его в свою очередь и повторить через `retry_after` секунд |
| `502` | Telegram отверг сообщение (нет чата, бот заблокирован, битая разметка) |

## Соблюдение лимитов Telegram

Лимиты Telegram Bot API соблюдаются **здесь**, а не в вызывающих сервисах: через
этого бота шлют и `notification-service`, и `auth-service`, и цикл ответов на
входящие сообщения. Ни один из них не видит трафик остальных, поэтому единственная
точка, где можно посчитать общий темп, — сам бот.

| Ограничение | Значение | Переменная |
|---|---|---|
| Суммарно на бота | 30 сообщений/с | `TELEGRAM_RATE_PER_SECOND`, `TELEGRAM_BURST` |
| В один личный чат | 1 сообщение/с | `TELEGRAM_CHAT_PER_MINUTE`, `TELEGRAM_CHAT_BURST` |
| В одну группу | 20 сообщений/мин | `TELEGRAM_GROUP_PER_MINUTE`, `TELEGRAM_GROUP_BURST` |

Группа отличается от личного чата знаком `chat_id`: у групп, супергрупп и каналов
он отрицательный.

Отправка, укладывающаяся в лимит, ждёт своей очереди внутри бота (до
`TELEGRAM_MAX_WAIT_MS`). Если ждать пришлось бы дольше — вызывающий получает `429`
с точным `retry_after` и возвращает сообщение в свою очередь. Если `429` пришёл от
самого Telegram, названный им `retry_after` прокидывается вызывающему без изменений
и одновременно сдвигает внутреннее окно бота.

### GET /health

Healthcheck для docker-compose.

## Вызовы в auth-service

- `POST /api/telegram/link/confirm` — при `/start <токен>` (подтверждение привязки)
- `POST /api/telegram/login/decision` — при нажатии кнопки подтверждения/отклонения входа

## Настройка

```bash
cp .env.example .env
# заполнить TELEGRAM_BOT_TOKEN и INTERNAL_API_KEY (равен ключу auth-service)
docker compose up -d --build notification-bot
```

Переменные окружения:

| Переменная | Описание |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Токен бота от @BotFather (обязательно) |
| `INTERNAL_API_KEY` | Ключ внутренних API, должен совпадать с auth-service (обязательно) |
| `AUTH_SERVICE_URL` | URL auth-service (по умолчанию `http://auth-service:80`) |
| `PORT` | Порт HTTP API (по умолчанию 80) |
| `ENVIRONMENT` | `production` отключает debug-логи gin |
| `TELEGRAM_RATE_PER_SECOND` | Суммарный лимит бота (по умолчанию 30 — лимит Telegram) |
| `TELEGRAM_BURST` | Допустимый мгновенный всплеск (по умолчанию 30) |
| `TELEGRAM_CHAT_PER_MINUTE` | Лимит личного чата (по умолчанию 60 = 1/с) |
| `TELEGRAM_CHAT_BURST` | Всплеск в личный чат (по умолчанию 1) |
| `TELEGRAM_GROUP_PER_MINUTE` | Лимит группы (по умолчанию 20) |
| `TELEGRAM_GROUP_BURST` | Всплеск в группу (по умолчанию 1) |
| `TELEGRAM_MAX_WAIT_MS` | Сколько ждать освобождения лимита до ответа `429` (по умолчанию 10000) |

Значения по умолчанию равны документированным лимитам Telegram. Занижать их
безопасно, завышать — нет: превышение даёт `429` на весь бот портала, включая
подтверждение входа.

В auth-service (`auth-service/.env`) должны быть заданы:

| Переменная | Описание |
|---|---|
| `NOTIFICATION_BOT_URL` | `http://notification-bot:80` |
| `TELEGRAM_BOT_USERNAME` | `notification_analytics_gh_uz_bot` (для deep-link) |

## Безопасность

- Токен привязки: 48 hex-символов, одноразовый, живёт 15 минут, доставляется только на подтверждённый email пользователя.
- Запрос входа: 64 hex-символа, живёт 3 минуты, потребляется ровно один раз (атомарный `FindOneAndUpdate`); решение принимается только с привязанного `chat_id`.
- Неизвестные идентификаторы при входе/сбросе получают неотличимый «generic» ответ — перебор аккаунтов невозможен.
- ≥3 отклонений входа — заморозка входа через Telegram до успешного входа по паролю.
- TTL-индексы MongoDB автоматически удаляют истёкшие токены и запросы.
