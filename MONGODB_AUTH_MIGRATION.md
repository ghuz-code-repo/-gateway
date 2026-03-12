# MongoDB Authentication Migration Guide

## Обзор

Это руководство описывает процесс включения аутентификации MongoDB для **существующего** продакшен-деплоя gateway, где данные в `/data/db` уже есть.

> **Для новых деплоев** (пустой `mongo_data/`): просто задайте пароли в `!gateway/.env` и запустите `docker compose up -d` — init-скрипт создаст пользователей автоматически.

---

## Предварительные требования

- SSH-доступ к серверу
- Docker и docker compose установлены
- Бэкап MongoDB (обязательно!)

---

## Шаг 0: Бэкап (ОБЯЗАТЕЛЬНО)

```bash
# На сервере, в директории !gateway/
docker compose exec mongo mongodump --db authdb --out /data/db/backup_before_auth
# Скопировать бэкап с сервера на локальную машину (на всякий случай)
docker cp gateway-mongo-1:/data/db/backup_before_auth ./backup_before_auth
```

---

## Шаг 1: Создать пользователей в работающей MongoDB (БЕЗ --auth)

Пока MongoDB работает **без аутентификации**, создаём пользователей:

```bash
# Подключаемся к MongoDB
docker compose exec mongo mongosh

# В mongosh выполняем:
```

```javascript
// 1. Создаём root-администратора
use admin
db.createUser({
    user: "mongoadmin",
    pwd: "ЗАМЕНИТЕ_НА_СИЛЬНЫЙ_ПАРОЛЬ_ROOT",
    roles: [{ role: "root", db: "admin" }]
});

// 2. Создаём application-пользователя с минимальными привилегиями
use authdb
db.createUser({
    user: "authservice",
    pwd: "ЗАМЕНИТЕ_НА_СИЛЬНЫЙ_ПАРОЛЬ_APP",
    roles: [{ role: "readWrite", db: "authdb" }]
});

// 3. Проверяем
use admin
db.getUsers()
// Должен показать mongoadmin

use authdb
db.getUsers()
// Должен показать authservice

exit
```

---

## Шаг 2: Настроить .env файлы

### `!gateway/.env` (для docker-compose)

```env
MONGO_ROOT_PASSWORD=ЗАМЕНИТЕ_НА_СИЛЬНЫЙ_ПАРОЛЬ_ROOT
MONGO_APP_PASSWORD=ЗАМЕНИТЕ_НА_СИЛЬНЫЙ_ПАРОЛЬ_APP
```

> Пароли должны совпадать с теми, что вы задали в Шаге 1!

### `!gateway/auth-service/.env`

Замените строку `MONGO_URI`:

```env
MONGO_URI=mongodb://authservice:ЗАМЕНИТЕ_НА_СИЛЬНЫЙ_ПАРОЛЬ_APP@mongo:27017/authdb?authSource=authdb
```

---

## Шаг 3: Обновить docker-compose.yaml (уже сделано в коде)

`docker-compose.yaml` уже содержит:
- `command: ["--auth"]` — включает аутентификацию
- `MONGO_INITDB_ROOT_USERNAME/PASSWORD` — для новых деплоев
- Healthcheck с credentials

Убедитесь, что ваш `docker-compose.yaml` обновлён (pull последний код).

---

## Шаг 4: Перезапуск с аутентификацией

```bash
# Остановить стек
docker compose down

# Запустить с новой конфигурацией
docker compose up -d

# Проверить логи auth-service
docker compose logs auth-service --tail 50

# Должно быть:
# "Connecting to MongoDB (database: authdb)..."
# "Connected to MongoDB successfully (database: authdb)"
```

---

## Шаг 5: Проверка

```bash
# 1. Проверить healthcheck MongoDB
docker compose ps mongo
# Должен быть healthy

# 2. Проверить, что без credentials подключиться нельзя
docker compose exec mongo mongosh --eval "db.runCommand('ping')"
# Должна быть ошибка: requires authentication

# 3. Проверить, что с credentials работает
docker compose exec mongo mongosh -u mongoadmin -p "ПАРОЛЬ_ROOT" --authenticationDatabase admin --eval "db.runCommand('ping')"
# Должен вернуть { ok: 1 }

# 4. Проверить auth-service health
curl -s http://localhost/health
# Должен вернуть 200 OK

# 5. Проверить что приложение работает
curl -s http://localhost/api/v1/health
```

---

## Шаг 6: Обновить admin-скрипты

JS-скрипты (например, `restore_client_service_roles.js`) теперь требуют аутентификацию:

**Было:**
```bash
cat restore_client_service_roles.js | docker exec -i gateway-mongo-1 mongosh authdb
```

**Стало:**
```bash
cat restore_client_service_roles.js | docker exec -i gateway-mongo-1 mongosh \
    -u authservice -p "ПАРОЛЬ_APP" --authenticationDatabase authdb authdb
```

---

## Откат (если что-то пошло не так)

```bash
# 1. Остановить стек
docker compose down

# 2. Убрать --auth из docker-compose.yaml (временно)
# Закомментировать строку: command: ["--auth"]

# 3. Вернуть старый MONGO_URI в auth-service/.env
# MONGO_URI=mongodb://mongo:27017

# 4. Запустить без auth
docker compose up -d

# 5. Если нужно — восстановить из бэкапа
docker compose exec mongo mongorestore --db authdb /data/db/backup_before_auth/authdb
```

---

## Генерация паролей

```bash
# Linux/Mac
openssl rand -base64 32

# PowerShell
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Max 256 }) -as [byte[]])
```

---

## Troubleshooting

### auth-service не запускается: "MONGO_URI environment variable is required"
- Убедитесь, что `auth-service/.env` содержит `MONGO_URI`

### auth-service: "mongo ping (check credentials and network)"
- Проверьте, что пароль в `MONGO_URI` совпадает с тем, что создан в MongoDB
- Проверьте `authSource=authdb` в URI

### MongoDB healthcheck failing
- Проверьте `MONGO_ROOT_PASSWORD` в `!gateway/.env`
- Попробуйте подключиться вручную:
  ```bash
  docker compose exec mongo mongosh -u mongoadmin -p "ПАРОЛЬ" --authenticationDatabase admin
  ```

### MONGO_INITDB_* не создают пользователей
- Эти переменные работают **только при первом старте** (пустой `/data/db`)
- Для существующих баз — создавайте пользователей вручную (Шаг 1)
