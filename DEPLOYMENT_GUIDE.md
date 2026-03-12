# 📧 Руководство по развертыванию и настройке Email

## Настройка Email для продакшена

### 1. Переменные окружения (.env файл)

Для корректной работы системы восстановления пароля в продакшене необходимо настроить следующие переменные:

```bash
# Базовый URL для ссылок (БЕЗ порта!)
BASE_URL=https://analytics.gh.uz

# Email настройки
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=noreply@yourdomain.com
SMTP_USE_TLS=true
SMTP_USE_AUTH=true
SMTP_AUTH_METHOD=plain
SMTP_DEBUG=false

# Контакты поддержки
SUPPORT_EMAIL=support@yourdomain.com
SUPPORT_TELEGRAM=@yoursupport
```

### 2. Важные моменты для BASE_URL

**Для разработки:**
```bash
BASE_URL=http://localhost
```

**Для продакшена:**
```bash
BASE_URL=https://analytics.gh.uz
# или
BASE_URL=https://yourdomain.com  
```

⚠️ **ВАЖНО:** URL должен быть БЕЗ порта и БЕЗ trailing slash!

### 3. Настройка Gmail (пример)

1. Включите 2-факторную аутентификацию
2. Создайте пароль приложения: https://myaccount.google.com/apppasswords
3. Используйте этот пароль в `SMTP_PASSWORD`

### 4. Альтернативные SMTP провайдеры

**Yandex:**
```bash
SMTP_HOST=smtp.yandex.ru
SMTP_PORT=587
SMTP_USE_TLS=true
```

**Outlook/Hotmail:**
```bash
SMTP_HOST=smtp.live.com
SMTP_PORT=587
SMTP_USE_TLS=true
```

**Корпоративный SMTP:**
```bash
SMTP_HOST=172.16.0.201
SMTP_PORT=587
SMTP_USE_TLS=false
SMTP_AUTH_METHOD=login
```

### 5. Проверка работы

1. Перезапустите контейнеры после изменения .env
2. Откройте `/forgot-password`
3. Введите существующий email
4. Проверьте почту (и папку спам!)

### 6. Отладка

Если письма не приходят:

1. Включите отладку: `SMTP_DEBUG=true`
2. Проверьте логи: `docker compose logs auth-service`
3. Убедитесь, что SMTP настройки корректны
4. Проверьте файрволл и сетевые настройки

## 🚀 Функционал восстановления пароля

### Что работает:
✅ **Страница запроса восстановления:** `/forgot-password`  
✅ **Отправка email с ссылкой сброса**  
✅ **Страница сброса пароля:** `/reset-password?token=xxx`  
✅ **Валидация полей с красными/зелеными границами**  
✅ **Показ/скрытие пароля глазиком**  
✅ **Токены с истечением срока (1 час)**  
✅ **Защита от повторного использования токенов**  

### Безопасность:
- Токены одноразовые
- Срок действия токена: 1 час
- Хеширование паролей с bcrypt
- Валидация на клиенте и сервере
