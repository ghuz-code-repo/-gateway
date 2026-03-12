# 🚀 Быстрый старт: Telegram Integration

## 📱 Два бота в одном сервисе!

- **Обычный бот** (`telegram`) → уведомления пользователям
- **Системный бот** (`telegram_system`) → мониторинг и алерты

---

## ⚡ За 3 минуты

### 1️⃣ Создайте ботов

Откройте [@BotFather](https://t.me/BotFather) и создайте два бота:

```
/newbot
```

Сохраните токены.

### 2️⃣ Узнайте свой Chat ID

```bash
curl https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
```

Найдите `"chat":{"id":123456789}`

### 3️⃣ Настройте

**Вариант A** - через .env:

```env
TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
TELEGRAM_SYSTEM_BOT_TOKEN=789012:XYZ-ABC...
TELEGRAM_ENABLED=true
TELEGRAM_SYSTEM_ENABLED=true
```

**Вариант B** - через API (внутри Docker):

```bash
docker exec notification-service-notification-service-1 sh -c \
  'wget -qO- --header="Content-Type: application/json" \
  --post-data='"'"'{"telegram_bot_token":"YOUR_TOKEN","telegram_enabled":"true"}'"'"' \
  http://localhost:8082/api/v1/config'
```

### 4️⃣ Тестируйте!

**Windows:**
```powershell
# Отредактируйте токены и chat_id в файле
.\test_telegram.ps1
```

**Linux/Mac:**
```bash
bash test_telegram.sh
```

---

## 📤 Примеры отправки

### Обычное уведомление

```bash
curl -X POST http://notification-service:8082/api/v1/notifications \
  -H "Content-Type: application/json" \
  -d '{
    "type": "telegram",
    "recipient": "123456789",
    "subject": "Привет!",
    "content": "Тестовое сообщение"
  }'
```

### Системный алерт

```bash
curl -X POST http://notification-service:8082/api/v1/notifications \
  -H "Content-Type: application/json" \
  -d '{
    "type": "telegram_system",
    "recipient": "123456789",
    "subject": "⚠️ Алерт!",
    "content": "Сервис упал!"
  }'
```

---

## 🎨 Markdown форматирование

```
*жирный текст*
_курсив_
`код`
[ссылка](https://example.com)
```

---

## 📚 Документация

- **Полное руководство:** [TELEGRAM_GUIDE.md](TELEGRAM_GUIDE.md)
- **Changelog:** [CHANGELOG_TELEGRAM.md](CHANGELOG_TELEGRAM.md)
- **Основной README:** [README.md](README.md)

---

## ❓ Проблемы?

```bash
# Проверьте логи
docker logs notification-service-notification-service-1 --tail 50

# Проверьте конфигурацию (из другого контейнера в public_network)
curl http://notification-service:8082/api/v1/config

# Проверьте статус уведомления
curl http://notification-service:8082/api/v1/notifications/42
```

---

## 🎯 Готово!

Теперь вы можете отправлять Telegram уведомления через API! 🎉
