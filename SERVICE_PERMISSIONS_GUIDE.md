# Система гранулярных разрешений для управления сервисами

## Обзор

Вместо единой роли `service-manager` с полным доступом, теперь можно создавать кастомные роли с конкретными разрешениями для управления сервисами через auth-service.

## Разрешения (Permissions)

### Управление пользователями
- `service.users.add` - добавление пользователей в сервис
- `service.users.remove` - удаление пользователей из сервиса
- `service.users.view` - просмотр списка пользователей
- `service.users.export` - экспорт списка пользователей
- `service.users.import` - импорт пользователей из Excel

### Назначение ролей
- `service.roles.assign` - назначение ролей пользователям
- `service.roles.unassign` - снятие ролей с пользователей

### Управление ролями
- `service.roles.create` - создание новых ролей для сервиса
- `service.roles.edit` - редактирование существующих ролей
- `service.roles.delete` - удаление ролей
- `service.roles.view` - просмотр списка ролей

### Управление разрешениями
- `service.permissions.manage` - управление разрешениями сервиса
- `service.permissions.sync` - синхронизация разрешений с сервисом

### Настройки сервиса
- `service.settings.edit` - изменение настроек сервиса
- `service.settings.view` - просмотр настроек сервиса

### Полный доступ
- `service.manage.full` - полный доступ ко всем операциям (эквивалент service-manager)

## Wildcard разрешения

Можно использовать wildcard `.*` для группы разрешений:
- `service.users.*` - все операции с пользователями
- `service.roles.*` - все операции с ролями
- `service.*` - все операции (полный доступ)

## Примеры ролей

### 1. HR Manager (управление пользователями)
Может добавлять пользователей и назначать им роли, но не может создавать новые роли:

```json
{
  "service": "referal",
  "name": "hr-manager",
  "permissions": [
    "service.users.add",
    "service.users.remove",
    "service.users.view",
    "service.users.export",
    "service.users.import",
    "service.roles.assign",
    "service.roles.unassign",
    "service.roles.view"
  ]
}
```

### 2. Role Designer (настройка ролей)
Может создавать и редактировать роли, но не может назначать их пользователям:

```json
{
  "service": "referal",
  "name": "role-designer",
  "permissions": [
    "service.roles.create",
    "service.roles.edit",
    "service.roles.view",
    "service.permissions.manage"
  ]
}
```

### 3. User Manager (только пользователи)
Может только просматривать и экспортировать список пользователей:

```json
{
  "service": "referal",
  "name": "user-viewer",
  "permissions": [
    "service.users.view",
    "service.users.export"
  ]
}
```

### 4. Full Service Manager (полный доступ)
Эквивалент старой роли service-manager:

```json
{
  "service": "referal",
  "name": "service-manager",
  "permissions": [
    "service.manage.full"
  ]
}
```

Или с wildcard:

```json
{
  "service": "referal",
  "name": "service-manager",
  "permissions": [
    "service.*"
  ]
}
```

## Создание ролей через MongoDB

### Создать роль HR Manager для сервиса referal:

```javascript
db.service_roles.insertOne({
  service: "referal",
  name: "hr-manager",
  description: "Может управлять пользователями и назначать роли",
  permissions: [
    "service.users.add",
    "service.users.remove",
    "service.users.view",
    "service.users.export",
    "service.users.import",
    "service.roles.assign",
    "service.roles.unassign",
    "service.roles.view"
  ],
  created_at: new Date(),
  updated_at: new Date()
})
```

### Назначить роль пользователю:

```javascript
db.user_service_roles.insertOne({
  user_id: ObjectId("USER_ID_HERE"),
  service_key: "referal",
  role_name: "hr-manager",
  is_active: true,
  assigned_at: new Date(),
  assigned_by: ObjectId("ADMIN_USER_ID")
})
```

## Проверка разрешений в коде

В хэндлерах используется функция `requireServicePermission`:

```go
func someHandler(c *gin.Context) {
    // Проверить конкретное разрешение
    if !requireServicePermission(c, models.PermServiceUsersAdd) {
        c.JSON(http.StatusForbidden, gin.H{
            "error": "У вас нет прав на добавление пользователей",
        })
        return
    }
    
    // Продолжить выполнение...
}
```

## Обратная совместимость

Роль `service-manager` продолжает работать как раньше - имеет полный доступ ко всем операциям.

Системные администраторы (с ролью `admin` в auth-service) также имеют полный доступ ко всем операциям.

## Миграция со старой системы

1. Существующая роль `service-manager` автоматически дает полный доступ
2. Создайте новые роли с гранулярными разрешениями
3. Постепенно назначайте пользователям новые роли вместо service-manager
4. Роль service-manager можно оставить для полного доступа

## UI для управления разрешениями (планируется)

В будущем будет добавлен интерфейс для:
- Создания ролей с выбором разрешений из списка
- Назначения ролей пользователям
- Просмотра текущих разрешений пользователя
- Шаблонов ролей (HR Manager, Role Designer, и т.д.)
