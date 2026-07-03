# Notification Bot

Telegram-бот портала (https://t.me/notification_analytics_gh_uz_bot) для:

1. **Привязки Telegram к аккаунту** — пользователь в личном кабинете вводит свой username, получает на почту deep-link `https://t.me/notification_analytics_gh_uz_bot?start=<токен>`; переход по ссылке стартует бота и подтверждает привязку.
2. **Входа через Telegram** — при входе через `/login/telegram` бот присылает сообщение с кнопками «Подтвердить вход» / «Отклонить вход». 3 и более отклонений замораживают вход через Telegram до следующего входа по логину и паролю.
3. **Сброса пароля через Telegram** — на `/forgot-password` можно выбрать доставку ссылки в Telegram вместо email.

## Архитектура

```
Браузер ──► nginx ──► auth-service ──► notification-bot ──► Telegram API
                          ▲                    │ (long polling)
                          └────────────────────┘
                        /api/telegram/* (X-API-Key)
```

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
  "buttons": [[
    {"text": "✅ Подтвердить вход", "callback_data": "login:<request_id>:approve"},
    {"text": "🚫 Отклонить вход",  "callback_data": "login:<request_id>:reject"}
  ]]
}
```

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
