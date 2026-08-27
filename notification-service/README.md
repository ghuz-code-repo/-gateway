# Notification Service

Микросервис для отправки уведомлений, поддерживающий email, SMS и push-уведомления.

## Модель адресации

Получателя описывает **одно именованное поле** запроса. Какое именно — определяет
`resolveRecipientMode` в [recipients.go](recipients.go) по таблице `addressingFields`:

| Поле | Режим | Что делает сервис |
|---|---|---|
| `login` | `login` | спрашивает адрес у auth-service (`POST /api/recipients/resolve`), кэширует на 10 мин |
| `external_recipient` | `external` | берёт значение как есть |
| — (только `telegram_system`) | `system` | подставляет `system_telegram_chat_id` из конфига |

Заполнено должно быть ровно одно поле. Два сразу или ни одного — `400`; угадывать по виду
строки («похоже на email») сервис не будет, потому что ошибка адресации молча уводит
уведомление не туда.

### Как добавить новый вид адресации

Например, рассылку всем обладателям права (`permission`) или всем в роли (`role`):

1. Добавить поле в `SingleNotificationRequest` ([main.go](main.go)).
2. Добавить запись в `addressingFields` ([recipients.go](recipients.go)): имя поля, режим,
   геттер значения и, если нужно, `validate`.
3. Научить `applyRecipient` раскладывать новый режим по колонкам записи.
4. Если новый вид требует обращения к auth-service — расширить его
   `POST /api/recipients/resolve`.

Разбор запроса, проверку «ровно одно поле», пакетную обработку и обработчики трогать не
нужно — они работают через таблицу.

Хранение в БД: `recipient` — фактический адрес, куда ушло уведомление (для аудита),
`recipient_login` / `external_recipient` — чем адресовали, `failure_code` — машинная
причина отказа.

## Возможности

- Отправка уведомлений пачками (batch) для оптимизации производительности
- Гарантированная доставка с повторными попытками
- Поддержка различных типов уведомлений (email, SMS, push)
- Отслеживание статуса отправки
- Настраиваемые параметры SMTP
- Обработка постоянных и временных ошибок
- Rate limiting для предотвращения перегрузки почтовых серверов

## API Endpoints

### Отправка уведомлений

#### Отправка пачки уведомлений
```http
POST /api/v1/notifications/batch
Content-Type: application/json

{
  "batch_id": "optional-batch-id",
  "notifications": [
    {
      "type": "email",
      "login": "ivanov",
      "subject": "Test Subject",
      "content": "Test content"
    }
  ]
}
```

#### Отправка одного уведомления
```http
POST /api/v1/notifications
Content-Type: application/json

{
  "type": "email",
  "login": "ivanov",
  "subject": "Test Subject",
  "content": "Test content"
}
```

### Получение статуса

#### Статус уведомления
```http
GET /api/v1/notifications/{id}
```

#### Статус пачки
```http
GET /api/v1/batches/{batch_id}
```

#### Уведомления в пачке
```http
GET /api/v1/batches/{batch_id}/notifications
```

### Конфигурация

#### Получение конфигурации
```http
GET /api/v1/config
```

#### Обновление конфигурации
```http
POST /api/v1/config
Content-Type: application/json

{
  "smtp_host": "smtp.gmail.com",
  "smtp_port": "587",
  ...
}
```

### Проверка здоровья
```http
GET /api/v1/health
```

## Переменные окружения

### Основные настройки
- `PORT` - Порт для запуска сервиса (по умолчанию: 8082)

### База данных
- `DB_HOST` - Хост базы данных PostgreSQL
- `DB_PORT` - Порт базы данных (по умолчанию: 5432)
- `DB_USER` - Пользователь базы данных
- `DB_PASSWORD` - Пароль базы данных
- `DB_NAME` - Имя базы данных
- `DB_SSLMODE` - Режим SSL (по умолчанию: disable)

### SMTP настройки
- `SMTP_HOST` - SMTP сервер (по умолчанию: smtp.gmail.com)
- `SMTP_PORT` - SMTP порт (по умолчанию: 587)
- `SMTP_USERNAME` - Имя пользователя SMTP
- `SMTP_PASSWORD` - Пароль SMTP
- `SMTP_FROM` - Адрес отправителя
- `SMTP_USE_TLS` - Использовать TLS (по умолчанию: false)
- `SMTP_USE_AUTH` - Использовать аутентификацию (по умолчанию: false)
- `SMTP_AUTH_METHOD` - Метод аутентификации (plain, login, crammd5)
- `SMTP_DEBUG` - Режим отладки (по умолчанию: false)

### Настройки обработки
- `MAX_RETRY_ATTEMPTS` - Максимальное количество попыток (по умолчанию: 3)
- `BATCH_SIZE` - Размер пачки для обработки (по умолчанию: 10)
- `DELAY_BETWEEN_BATCHES_MS` - Задержка между пачками в мс (по умолчанию: 1000)

## Запуск

### С использованием Docker Compose
```bash
docker-compose up -d
```

### Локальный запуск
1. Установите PostgreSQL
2. Скопируйте `.env.example` в `.env` и настройте переменные
3. Запустите:
```bash
go mod download
go run .
```

## Статусы уведомлений

- `pending` - Ожидает обработки
- `sending` - В процессе отправки
- `sent` - Успешно отправлено
- `failed` - Отправка не удалась
- `cancelled` - Отменено

## Типы уведомлений

- `email` - Email уведомления (реализовано)
- `sms` - SMS уведомления (заготовка)
- `push` - Push уведомления (заготовка)

## Обработка ошибок

Сервис автоматически определяет постоянные ошибки (например, "пользователь не найден") и не пытается повторить отправку. Для временных ошибок используется экспоненциальная задержка между попытками.