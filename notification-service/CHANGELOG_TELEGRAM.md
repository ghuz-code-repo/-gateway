# 📋 Changelog: Telegram Bot Integration

## Версия: 2.0.0
**Дата:** 14 октября 2025

---

## ✨ Новые возможности

### 🤖 Двойная поддержка Telegram ботов

Добавлена возможность использовать **два независимых Telegram бота**:

1. **Обычный бот** (`telegram`) 
   - Для отправки уведомлений пользователям
   - Новости, напоминания, персональные сообщения

2. **Системный бот** (`telegram_system`)
   - Для системных алертов и мониторинга
   - Уведомления о падении сервисов
   - Критические ошибки и предупреждения

### 📝 Новые типы уведомлений

```go
const (
    NotificationTypeTelegram       = "telegram"        // Обычный бот
    NotificationTypeTelegramSystem = "telegram_system" // Системный бот
)
```

### 🔧 Расширенная конфигурация

Добавлены новые поля в `NotificationConfig`:

```go
type NotificationConfig struct {
    // ... существующие поля ...
    TelegramBotToken        string `json:"telegram_bot_token"`
    TelegramSystemBotToken  string `json:"telegram_system_bot_token"`
    TelegramEnabled         bool   `json:"telegram_enabled"`
    TelegramSystemEnabled   bool   `json:"telegram_system_enabled"`
}
```

### 🌐 Новые переменные окружения

```env
TELEGRAM_BOT_TOKEN=YOUR_BOT_TOKEN
TELEGRAM_SYSTEM_BOT_TOKEN=YOUR_SYSTEM_BOT_TOKEN
TELEGRAM_ENABLED=true
TELEGRAM_SYSTEM_ENABLED=true
```

### 📡 API изменения

#### Обновлен GET /api/v1/config

Теперь возвращает дополнительные поля:
```json
{
  "telegram_bot_token": "...",
  "telegram_system_bot_token": "...",
  "telegram_enabled": "true",
  "telegram_system_enabled": "true"
}
```

#### Обновлен POST /api/v1/config

Принимает новые поля для настройки Telegram ботов.

---

## 🔨 Технические изменения

### Измененные файлы

1. **main.go**
   - Добавлены константы `NotificationTypeTelegram` и `NotificationTypeTelegramSystem`
   - Расширена структура `NotificationConfig` (4 новых поля)
   - Обновлены функции `getConfig()` и `updateConfig()`
   - Обновлена функция `getConfigFromDB()` с поддержкой env переменных

2. **processors.go**
   - Добавлена функция `sendTelegram(notification *Notification, isSystemBot bool)`
   - Добавлены импорты: `bytes`, `encoding/json`, `io/ioutil`, `net/http`
   - Обновлена функция `processNotification()` с новыми case для Telegram
   - Поддержка Markdown форматирования
   - Обработка ошибок Telegram Bot API

### Новые файлы

1. **TELEGRAM_GUIDE.md**
   - Полная документация по использованию Telegram ботов
   - Примеры API запросов
   - Troubleshooting секция

2. **test_telegram.sh**
   - Bash скрипт для тестирования (Linux/macOS)

3. **test_telegram.ps1**
   - PowerShell скрипт для тестирования (Windows)

4. **test_notification.json**
   - Пример JSON для тестовых запросов

---

## 📊 База данных

### Автоматическая миграция

GORM автоматически добавляет новые колонки:
- `telegram_bot_token` (TEXT)
- `telegram_system_bot_token` (TEXT)
- `telegram_enabled` (BOOLEAN, default: false)
- `telegram_system_enabled` (BOOLEAN, default: false)

**Примечание:** Существующие данные не затрагиваются.

---

## 🎯 Примеры использования

### Отправка через обычный бот

```bash
curl -X POST http://notification-service:8082/api/v1/notifications \
  -H "Content-Type: application/json" \
  -d '{
    "type": "telegram",
    "recipient": "123456789",
    "subject": "Привет!",
    "content": "Это сообщение от обычного бота"
  }'
```

### Отправка системного алерта

```bash
curl -X POST http://notification-service:8082/api/v1/notifications \
  -H "Content-Type: application/json" \
  -d '{
    "type": "telegram_system",
    "recipient": "123456789",
    "subject": "⚠️ Алерт",
    "content": "Сервис auth-service недоступен!"
  }'
```

---

## 🔐 Безопасность

- Токены ботов хранятся в PostgreSQL
- API защищён IP whitelist (только Docker internal networks)
- Поддержка переменных окружения для конфиденциальных данных

---

## 🧪 Тестирование

### Windows (PowerShell)

```powershell
# 1. Отредактируйте test_telegram.ps1
# 2. Запустите
.\test_telegram.ps1
```

### Linux/macOS (Bash)

```bash
# 1. Отредактируйте test_telegram.sh
# 2. Запустите
bash test_telegram.sh
```

---

## ⚙️ Настройка

### Способ 1: Через API

```bash
docker exec notification-service-notification-service-1 \
  wget -qO- --header="Content-Type: application/json" \
  --post-data='{"telegram_bot_token":"TOKEN","telegram_enabled":"true"}' \
  http://localhost:8082/api/v1/config
```

### Способ 2: Через .env файл

```env
TELEGRAM_BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
TELEGRAM_SYSTEM_BOT_TOKEN=789012:XYZ-ABC9876ghIkl-def34K8w2v789ew22
TELEGRAM_ENABLED=true
TELEGRAM_SYSTEM_ENABLED=true
```

---

## 🐛 Известные ограничения

- Максимальная длина сообщения: 4096 символов (ограничение Telegram)
- Rate limit: зависит от Telegram Bot API
- Retry logic: 3 попытки с экспоненциальным backoff

---

## 📚 Дополнительные ресурсы

- [TELEGRAM_GUIDE.md](TELEGRAM_GUIDE.md) - Полное руководство
- [Telegram Bot API Documentation](https://core.telegram.org/bots/api)
- [BotFather](https://t.me/BotFather) - Создание ботов

---

## 🔄 Обратная совместимость

✅ Полная обратная совместимость
- Существующий функционал email/SMS/push не изменен
- Новые поля в конфигурации опциональны
- Старые уведомления продолжают работать без изменений

---

## 🚀 Следующие шаги

Для полноценного мониторинга рекомендуется:

1. Создать систему мониторинга в auth-service
2. Интегрировать health checks с notification-service
3. Настроить автоматические алерты при падении сервисов
4. Добавить cooldown для предотвращения спама

---

## 👨‍💻 Авторы

- Интеграция Telegram: GitHub Copilot
- Дата релиза: 14 октября 2025
