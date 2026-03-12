# 📊 Улучшенное логирование Notification Service

## Что добавлено

Notification Service теперь имеет подробное логирование всех операций с использованием эмодзи для быстрой визуальной идентификации типов сообщений.

## Типы логов

### 🚀 Запуск сервиса
```
========================================
🚀 Notification Service Starting...
========================================
✅ Environment variables loaded from .env
📦 Connecting to database...
✅ Database connected successfully
✅ Notification service instance created
========================================
🌐 Starting notification service on port 8082
📧 Ready to process email notifications
========================================
```

### 📦 Получение batch запросов
```
📦 Received batch notification request: batch_id=batch-123, count=5
✅ Batch batch-123 created with 5 notifications, starting processing...
```

### 📧 Получение одиночных уведомлений
```
📧 Received notification: type=email, recipient=user@example.com, subject=Test
✅ Notification #42 created, starting processing...
```

### 🔧 SMTP подключение
```
🔧 Using SMTP: smtp.gmail.com:587, auth=true, tls=true
🔐 Connecting with TLS to smtp.gmail.com:587
✅ SMTP authentication successful
```

### ✅ Успешная отправка
```
📧 Sending email to user@example.com, subject: Welcome
✅ Email successfully sent to user@example.com (notification #42)
✅ Notification 42 sent successfully on attempt 1
```

### ❌ Ошибки
```
❌ Failed to parse notification request: invalid JSON
❌ SMTP configuration incomplete: host=, port=
❌ TLS dial failed: connection refused
❌ SMTP authentication failed: invalid credentials
❌ Failed to create notification: database error
```

### ⚠️ Предупреждения
```
⚠️  No .env file found, using system environment variables
```

## Как читать логи

### В Docker
```powershell
# Следить за логами в реальном времени
docker logs -f notification-service

# Последние 100 строк
docker logs --tail 100 notification-service

# Логи за последний час
docker logs --since 1h notification-service

# Только ошибки (фильтр по эмодзи)
docker logs notification-service | Select-String "❌"

# Только успешные отправки
docker logs notification-service | Select-String "✅ Email successfully"

# Все SMTP операции
docker logs notification-service | Select-String "SMTP|smtp"
```

### В консоли (при ручном запуске)
Просто запустите сервис и наблюдайте за выводом в консоль:
```powershell
cd !gateway/notification-service
./notification-service
```

## Полезные фильтры для логов

### Все входящие запросы
```powershell
docker logs notification-service | Select-String "📦|📧"
```

### Только проблемы
```powershell
docker logs notification-service | Select-String "❌|⚠️"
```

### SMTP подключения и аутентификация
```powershell
docker logs notification-service | Select-String "🔧|🔐|🔑"
```

### Результаты отправки
```powershell
docker logs notification-service | Select-String "✅ Email successfully|✅ Notification.*sent successfully"
```

### Процесс обработки конкретного notification
```powershell
# Замените 42 на ID уведомления
docker logs notification-service | Select-String "notification.*42|#42"
```

## Структура логов

Каждое сообщение содержит:
1. **Временную метку** (добавляется Docker автоматически)
2. **Эмодзи-индикатор** для быстрой идентификации
3. **Контекст операции** (batch_id, notification_id, recipient и т.д.)
4. **Детали** (параметры, ошибки, результаты)

## Примеры использования

### 1. Отслеживание конкретного email
```powershell
# Найти все логи связанные с user@example.com
docker logs notification-service | Select-String "user@example.com"
```

### 2. Проверка всех неудачных отправок за день
```powershell
docker logs --since 24h notification-service | Select-String "❌.*failed|failed after.*attempts"
```

### 3. Статистика успешных отправок
```powershell
# Подсчет успешных отправок
(docker logs notification-service | Select-String "✅ Email successfully sent").Count
```

### 4. Проверка конфигурации при старте
```powershell
docker logs notification-service | Select-String "Environment|Database|Starting notification"
```

### 5. Отладка SMTP проблем
```powershell
docker logs notification-service | Select-String "SMTP|TLS|auth"
```

## Уровни логирования

### Информационные (ℹ️, 📧, 📦, 🔧, 🔐, 🔑)
Обычные операции, успешное выполнение

### Успех (✅)
Операции завершены успешно

### Предупреждения (⚠️)
Не критичные проблемы, сервис продолжает работать

### Ошибки (❌)
Проблемы, требующие внимания

## Интеграция с мониторингом

Вы можете настроить автоматический мониторинг:

```powershell
# Скрипт для alert на ошибки
while($true) {
    $errors = docker logs --since 5m notification-service | Select-String "❌"
    if($errors.Count -gt 10) {
        Write-Host "ALERT: Too many errors in notification service!"
        # Отправить уведомление администратору
    }
    Start-Sleep -Seconds 300
}
```

## Рекомендации

1. **Регулярно проверяйте логи** на наличие ❌ (ошибок)
2. **Настройте ротацию логов** Docker для предотвращения переполнения диска
3. **Используйте централизованное логирование** (ELK, Grafana Loki) в production
4. **Мониторьте количество ❌** - резкий рост указывает на проблемы
5. **Проверяйте SMTP логи** при изменении конфигурации

---

**Дата обновления**: 10 октября 2025  
**Версия**: 1.1
