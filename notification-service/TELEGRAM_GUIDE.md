# 📱 Telegram Bot Integration Guide

## Обзор

Notification Service теперь поддерживает отправку уведомлений через **два независимых Telegram бота**:

1. **Обычный бот** (`telegram`) - для уведомлений пользователям
2. **Системный бот** (`telegram_system`) - для системных алертов и мониторинга

## 🚀 Быстрый старт

### 1. Создание Telegram ботов

Создайте двух ботов через [@BotFather](https://t.me/BotFather):

```
/newbot
```

Сохраните оба токена:
- `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11` - обычный бот
- `789012:XYZ-ABC9876ghIkl-def34K8w2v789ew22` - системный бот

### 2. Получение Chat ID

Отправьте сообщение вашему боту, затем:

```bash
curl https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
```

Найдите `"chat":{"id":123456789}` в ответе.

### 3. Настройка конфигурации

#### Вариант A: Через API

```bash
docker exec notification-service-notification-service-1 wget -qO- \
  --header="Content-Type: application/json" \
  --post-data='{
    "telegram_bot_token": "YOUR_BOT_TOKEN",
    "telegram_system_bot_token": "YOUR_SYSTEM_BOT_TOKEN",
    "telegram_enabled": "true",
    "telegram_system_enabled": "true"
  }' \
  http://localhost:8082/api/v1/config
```

#### Вариант B: Через переменные окружения

Добавьте в `.env`:

```env
TELEGRAM_BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
TELEGRAM_SYSTEM_BOT_TOKEN=789012:XYZ-ABC9876ghIkl-def34K8w2v789ew22
TELEGRAM_ENABLED=true
TELEGRAM_SYSTEM_ENABLED=true
```

Перезапустите сервис:

```bash
docker compose restart notification-service
```

## 📤 Отправка уведомлений

### Через обычный бот

```bash
curl -X POST http://notification-service:8082/api/v1/notifications \
  -H "Content-Type: application/json" \
  -d '{
    "type": "telegram",
    "recipient": "123456789",
    "subject": "Новое сообщение",
    "content": "Текст уведомления с поддержкой *Markdown*"
  }'
```

### Через системный бот

```bash
curl -X POST http://notification-service:8082/api/v1/notifications \
  -H "Content-Type: application/json" \
  -d '{
    "type": "telegram_system",
    "recipient": "123456789",
    "subject": "⚠️ Системный алерт",
    "content": "Сервис *auth-service* недоступен!\n\nВремя: 2025-10-14 19:45:00"
  }'
```

## 🎨 Форматирование

Поддерживается Markdown:

```markdown
*жирный текст*
_курсив_
`код`
[ссылка](https://example.com)
```

## 🧪 Тестирование

### PowerShell (Windows)

1. Отредактируйте `test_telegram.ps1`:
   ```powershell
   $BOT_TOKEN = "ваш_токен_обычного_бота"
   $SYSTEM_BOT_TOKEN = "ваш_токен_системного_бота"
   $CHAT_ID = "ваш_chat_id"
   ```

2. Запустите:
   ```powershell
   .\test_telegram.ps1
   ```

### Bash (Linux/macOS)

1. Отредактируйте `test_telegram.sh`
2. Запустите:
   ```bash
   bash test_telegram.sh
   ```

## 🔧 API Endpoints

### POST /api/v1/notifications

Отправить одно уведомление:

**Request:**
```json
{
  "type": "telegram" | "telegram_system",
  "recipient": "123456789",
  "subject": "Заголовок (опционально)",
  "content": "Текст сообщения"
}
```

**Response:**
```json
{
  "id": 42,
  "status": "pending",
  "message": "Notification accepted for processing"
}
```

### POST /api/v1/notifications/batch

Отправить несколько уведомлений:

**Request:**
```json
{
  "notifications": [
    {
      "type": "telegram",
      "recipient": "123456789",
      "subject": "Уведомление 1",
      "content": "Текст 1"
    },
    {
      "type": "telegram_system",
      "recipient": "987654321",
      "subject": "Уведомление 2",
      "content": "Текст 2"
    }
  ]
}
```

### GET /api/v1/notifications/:id

Проверить статус:

**Response:**
```json
{
  "id": 42,
  "type": "telegram",
  "recipient": "123456789",
  "status": "sent",
  "attempts": 1,
  "sent_at": 1697312400
}
```

Возможные статусы:
- `pending` - в очереди
- `sending` - отправляется
- `sent` - отправлено успешно
- `failed` - ошибка после всех попыток

## 🔐 Безопасность

- Токены ботов хранятся в БД в открытом виде (рекомендуется шифрование в продакшене)
- API доступен только из Docker внутренних сетей (IP whitelist)
- Разрешённые сети: `172.0.0.0/8`, `192.168.0.0/16`, `10.0.0.0/8`

## 🐛 Troubleshooting

### Уведомление не отправляется

1. Проверьте логи:
   ```bash
   docker logs notification-service-notification-service-1 --tail 50
   ```

2. Проверьте статус уведомления:
   ```bash
   curl http://notification-service:8082/api/v1/notifications/42
   ```

3. Убедитесь что боты включены:
   ```bash
   docker exec notification-service-notification-service-1 \
     wget -qO- http://localhost:8082/api/v1/config
   ```

### Ошибка "telegram bot is not enabled"

Включите бота через API или переменные окружения (см. раздел "Настройка конфигурации").

### Ошибка "telegram bot token not configured"

Добавьте токен через API или `.env` файл.

### Ошибка 403 Forbidden

API защищён IP whitelist. Отправляйте запросы только из Docker контейнеров в сети `public_network`.

## 📊 Примеры использования

### Уведомление о регистрации пользователя

```json
{
  "type": "telegram",
  "recipient": "123456789",
  "subject": "🎉 Добро пожаловать!",
  "content": "Спасибо за регистрацию!\n\nВаш аккаунт успешно создан."
}
```

### Системный алерт о падении сервиса

```json
{
  "type": "telegram_system",
  "recipient": "987654321",
  "subject": "🚨 КРИТИЧЕСКАЯ ОШИБКА",
  "content": "*Сервис:* auth-service\n*Статус:* offline\n*Время:* 2025-10-14 19:45:00\n\n_Требуется немедленное вмешательство!_"
}
```

### Batch отправка

```json
{
  "notifications": [
    {
      "type": "telegram",
      "recipient": "111111111",
      "content": "Напоминание о встрече в 15:00"
    },
    {
      "type": "telegram",
      "recipient": "222222222",
      "content": "Напоминание о встрече в 15:00"
    },
    {
      "type": "telegram",
      "recipient": "333333333",
      "content": "Напоминание о встрече в 15:00"
    }
  ]
}
```

## 📝 Дополнительная информация

- **Rate limiting:** 10 сообщений за batch, 1 секунда между batches (настраивается)
- **Retry logic:** 3 попытки с экспоненциальным backoff (1s, 4s, 9s)
- **Max attempts:** Настраивается через `max_retry_attempts`
- **Timeout:** 30 секунд на каждый запрос к Telegram API
