# 🔧 ИНСТРУКЦИЯ: Восстановление ролей client-service на сервере

## 📋 Проблема

После последнего обновления (коммита) на сервере пропали роли для client-service.

## 🔍 Диагностика

### Причина проблемы
На основе анализа кода и истории коммитов:
- Последний коммит `06cd9f1` обновлял auth-connector, но не затрагивал роли напрямую
- Вероятно, роли были случайно удалены или не были созданы после миграции
- Согласно `MIGRATION_REPORT.md`, должно быть **5 ролей** для client-service:
  1. `admin` - Администратор
  2. `manager` - Менеджер  
  3. `viewer` - Наблюдатель
  4. `user` - Пользователь
  5. `temporary` - Временный доступ

### Разрешения (permissions) для client-service
Всего 15 разрешений, определенных в `run.py`:

**Applications (7):**
- client-service.applications.view
- client-service.applications.create
- client-service.applications.edit
- client-service.applications.delete
- client-service.applications.assign
- client-service.applications.status.change
- client-service.applications.export

**Responsible (4):**
- client-service.responsible.view
- client-service.responsible.create
- client-service.responsible.edit
- client-service.responsible.delete

**Admin (4):**
- client-service.admin.panel
- client-service.admin.users
- client-service.admin.settings
- client-service.admin.logs

## 🚀 РЕШЕНИЕ: Шаги для восстановления на сервере

### Шаг 1: Подключение к серверу
```bash
ssh user@176.126.166.84
```

### Шаг 2: Переход в директорию проекта
```bash
cd /path/to/AnalyticsRepo/!gateway/auth-service
```

### Шаг 3: Загрузка скрипта восстановления
Скопируйте файл `restore_client_service_roles.js` на сервер:
```bash
# Вариант 1: Через git pull (если файл уже закоммичен)
git pull origin migration

# Вариант 2: Через scp с локальной машины
scp restore_client_service_roles.js user@176.126.166.84:/path/to/AnalyticsRepo/!gateway/auth-service/
```

### Шаг 4: Проверка текущего состояния ролей
```bash
docker exec gateway-mongo-1 mongosh authdb --eval "db.roles.find({service_key: 'client-service'}).pretty()"
```

### Шаг 5: Запуск скрипта восстановления
```bash
cat restore_client_service_roles.js | docker exec -i gateway-mongo-1 mongosh authdb
```

### Шаг 6: Проверка результата
```bash
# Проверить количество ролей
docker exec gateway-mongo-1 mongosh authdb --eval "db.roles.countDocuments({service_key: 'client-service'})"

# Посмотреть список ролей
docker exec gateway-mongo-1 mongosh authdb --eval "db.roles.find({service_key: 'client-service'}, {name: 1, description: 1, permissions: 1}).pretty()"
```

Должно быть **5 ролей**.

### Шаг 7: Перезапуск сервисов (опционально)
```bash
cd /path/to/AnalyticsRepo/!gateway
docker compose restart auth-service nginx

cd /path/to/AnalyticsRepo/client_service
docker compose restart
```

### Шаг 8: Проверка через web-интерфейс
1. Откройте админ-панель auth-service: `http://server-ip/admin`
2. Перейдите в раздел "Сервисы" → "client-service"
3. Убедитесь, что видны все 5 ролей
4. Проверьте, что у каждой роли есть правильные разрешения

## ✅ Ожидаемый результат

После выполнения скрипта должны быть созданы/восстановлены следующие роли:

| Роль | Описание | Кол-во разрешений |
|------|----------|-------------------|
| admin | Администратор | 15 (все) |
| manager | Менеджер | 7 |
| user | Пользователь | 3 |
| viewer | Наблюдатель | 1 |
| temporary | Временный доступ | 1 |

## 🔍 Дополнительная диагностика

### Проверить разрешения сервиса
```bash
docker exec gateway-mongo-1 mongosh authdb --eval "db.services.findOne({key: 'client-service'}, {available_permissions: 1})"
```

### Проверить назначения ролей пользователям
```bash
docker exec gateway-mongo-1 mongosh authdb --eval "db.user_service_roles.find({service_key: 'client-service', is_active: true}).count()"
```

### Проверить логи client-service
```bash
docker logs client-service-service 2>&1 | grep -i "permission\|role\|auth"
```

## 📝 Примечания

1. **Скрипт безопасен**: он не удаляет существующие роли, только создает отсутствующие или обновляет существующие
2. **Разрешения пользователей**: после восстановления ролей, пользователи сохранят свои назначения
3. **Откат**: если что-то пойдет не так, роли можно удалить вручную через mongosh
4. **Логи**: скрипт выводит подробную информацию о процессе восстановления

## 🆘 Если возникли проблемы

### Проблема: Сервис client-service не найден
```bash
# Проверить наличие сервиса
docker exec gateway-mongo-1 mongosh authdb --eval "db.services.findOne({key: 'client-service'})"

# Если сервис отсутствует, создать его через админ-панель
```

### Проблема: Разрешения не синхронизированы
```bash
# Перезапустить client-service для повторной синхронизации
cd /path/to/AnalyticsRepo/client_service
docker compose restart
```

### Проблема: Пользователи не видят функционал
```bash
# Проверить назначения ролей для конкретного пользователя
docker exec gateway-mongo-1 mongosh authdb --eval "db.user_service_roles.find({user_id: 'USER_ID', service_key: 'client-service'}).pretty()"
```

## 📞 Контакты

При возникновении проблем обращайтесь к разработчику системы авторизации.
