# Анализ: Назначение администраторов сервисов

## 🔍 Текущая ситуация

### Архитектура базы данных

**Коллекции:**
- `services` - список сервисов (auth, referal, client-service, и тд)
- `service_roles` - роли внутри каждого сервиса
- `user_service_roles` - назначение ролей пользователям в сервисах

**Структура user_service_roles:**
```json
{
  "_id": ObjectId("..."),
  "user_id": ObjectId("..."),      // ID пользователя
  "service_key": "referal",        // ключ сервиса
  "role_name": "admin",            // название роли в ЭТОМ сервисе
  "is_active": true,               // активна ли роль
  "assigned_at": ISODate("..."),
  "assigned_by": ObjectId("...")
}
```

### Текущая логика проверки прав

**1. System Admin (в auth-service с ролью GOD/admin)**
- Имеет доступ ко ВСЕМ сервисам
- Может управлять любым сервисом через `/services/:serviceKey`
- Проверяется через `hasAdminRole(user)` - проверяет роли в auth-service

**2. Service Admin (роль "admin" в конкретном сервисе)**
- Имеет доступ ТОЛЬКО к своему сервису
- Может управлять пользователями, ролями своего сервиса
- Проверяется через `hasServiceAdminRole(user, serviceKey)`
- **Пример:** пользователь с ролью "admin" в "referal" может управлять только сервисом referal

**3. Service Manager (роль "service-manager" в auth-service)**
- Может просматривать и редактировать сервисы
- **НО**: сейчас НЕ может управлять пользователями других сервисов
- Имеет разрешения: `auth.services.*`, `auth.roles.*`

## 🎯 Проблема

Пользователь говорит:
> "Я хочу назначать администраторов и менеджеров СЕРВИСАМ, не будучи администратором В САМОМ сервисе"

**Конкретно это означает:**

**Сценарий 1:** Назначить администратора сервиса "referal" через auth-service
- Сейчас: Нужно быть либо System Admin, либо иметь роль "admin" в "referal"
- Хочу: Иметь роль в auth-service (например "service-manager"), которая позволяет назначать админов ЛЮБОГО сервиса

**Сценарий 2:** Делегированное управление
- User A - менеджер сервисов в auth (роль "service-manager")
- User A хочет назначить User B администратором сервиса "client-service"
- НО User A сам НЕ является админом "client-service"
- User A не должен иметь доступ К ФУНКЦИОНАЛУ client-service, только к управлению его пользователями через auth-service

## ✅ Варианты решения

### Вариант 1: Расширить роль "service-manager" (РЕКОМЕНДУЕТСЯ)

**Суть:** Добавить разрешения для назначения администраторов сервисов

**Изменения:**

1. **Добавить новые разрешения в auth-service:**
```javascript
{
  name: "auth.services.manage_admins",
  displayName: "Управление администраторами сервисов",
  description: "Назначение и снятие администраторов для любых сервисов",
  category: "services"
},
{
  name: "auth.services.manage_users", 
  displayName: "Управление пользователями сервисов",
  description: "Назначение и снятие пользователей в любых сервисах",
  category: "services"
}
```

2. **Обновить роль service-manager:**
```javascript
permissions: [
  "auth.dashboard.view",
  "auth.services.view",
  "auth.services.edit",
  "auth.services.sync_permissions",
  "auth.services.manage_admins",    // НОВОЕ
  "auth.services.manage_users",     // НОВОЕ
  "auth.roles.view",
  "auth.roles.create",
  "auth.roles.edit",
  "auth.roles.assign_permissions",
  "auth.permissions.view",
  "auth.logs.view",
  "auth.notifications.receive"
]
```

3. **Изменить middleware `serviceAdminAuthRequired()`:**
```go
// Текущая логика
if isSystemAdmin {
    c.Set("isSystemAdmin", true)
    c.Next()
    return
}

// НОВАЯ логика
if isSystemAdmin {
    c.Set("isSystemAdmin", true)
    c.Next()
    return
}

// Проверка: если пользователь - service-manager в auth
if hasServiceManagerRole(user) {
    c.Set("isServiceManager", true)
    c.Set("canManageServices", true)
    c.Next()
    return
}

// Проверка: админ конкретного сервиса
if hasServiceAdminRole(user, serviceKey) {
    c.Set("isServiceAdmin", true)
    c.Next()
    return
}
```

**Преимущества:**
- ✅ Минимальные изменения в коде
- ✅ Использует существующую роль service-manager
- ✅ Гибкое управление через разрешения
- ✅ Не ломает существующую логику

**Недостатки:**
- ⚠️ service-manager получает доступ ко ВСЕМ сервисам
- ⚠️ Нельзя ограничить конкретными сервисами

---

### Вариант 2: Создать специальную роль для каждого сервиса

**Суть:** Создавать роли типа "referal-manager", "client-service-manager" в auth-service

**Пример структуры:**
```javascript
// Роль в auth-service
{
  service: "auth",
  name: "referal-service-manager",
  display_name: "Менеджер сервиса Referal",
  permissions: [
    "auth.services.view",
    "auth.services.manage_admins:referal",  // только для referal
    "auth.roles.view:referal",
    "auth.users.view:referal"
  ]
}
```

**Изменения:**

1. **Добавить поддержку условных разрешений:**
```go
// Формат: auth.services.manage_admins:referal
// Означает: управление админами только для referal
func hasConditionalPermission(user, permission, serviceKey) bool {
    // Проверка auth.services.manage_admins:referal
    // или auth.services.manage_admins (без ограничения)
}
```

2. **Создать роли автоматически при создании сервиса:**
```go
func CreateService(key, name string) {
    // 1. Создать сервис
    service := models.CreateService(...)
    
    // 2. Создать роль <service>-manager в auth
    role := models.CreateRole("auth", key+"-manager", ...)
    role.Permissions = []string{
        "auth.services.view",
        "auth.services.manage_admins:" + key,
        "auth.roles.view:" + key,
    }
}
```

**Преимущества:**
- ✅ Гранулярный контроль - можно ограничить конкретными сервисами
- ✅ Легко масштабируется при добавлении новых сервисов
- ✅ Следует принципу минимальных привилегий

**Недостатки:**
- ⚠️ Сложнее в реализации (нужна поддержка условных разрешений)
- ⚠️ Много ролей (по одной на сервис)
- ⚠️ Сложнее управлять

---

### Вариант 3: Назначать роль "admin" сервиса БЕЗ доступа к функционалу сервиса

**Суть:** Разделить роль "admin" на две:
- `admin` - полный доступ к функционалу сервиса
- `admin-delegated` - только управление пользователями через auth-service

**Структура:**
```javascript
// В service_roles для referal
{
  service: "referal",
  name: "admin-delegated",
  display_name: "Делегированный администратор",
  description: "Управление пользователями через auth-service без доступа к функционалу referal",
  permissions: [] // пустой массив - доступа к referal нет
}
```

**Логика:**
```go
// В middleware referal-service
func checkPermission(user, permission) {
    roles := getUserRoles(user, "referal")
    
    if hasRole(roles, "admin-delegated") {
        // Блокировать доступ к любым эндпоинтам referal
        return false
    }
    
    if hasRole(roles, "admin") {
        return true
    }
}

// В auth-service
func serviceAdminAuthRequired() {
    // Пользователь с ролью admin-delegated может управлять
    // пользователями через /services/referal/users
    if hasRole(user, serviceKey, "admin") || hasRole(user, serviceKey, "admin-delegated") {
        return true
    }
}
```

**Преимущества:**
- ✅ Четкое разделение ответственности
- ✅ Пользователь может управлять сервисом не имея к нему доступа
- ✅ Гранулярный контроль

**Недостатки:**
- ⚠️ Нужно изменять все микросервисы (referal, client-service)
- ⚠️ Сложнее понять логику (две похожих роли)

---

## 🎖️ Рекомендация

**Использовать Вариант 1 с модификациями:**

### Предлагаемая архитектура:

**1. Роли в auth-service:**

| Роль | Права | Кому назначать |
|---|---|---|
| **GOD** | Всё | Владелец системы |
| **admin** | Всё кроме GOD функций | IT-департамент |
| **service-manager** | Управление ВСЕМИ сервисами + пользователями всех сервисов | DevOps, Service Owner |
| **service-viewer** | Только просмотр всех сервисов | Аудиторы, читающие права |

**2. Роли в каждом сервисе (referal, client-service):**

| Роль | Права | Кому назначать |
|---|---|---|
| **admin** | Полный доступ к функционалу сервиса | Руководитель направления |
| **manager** | Ограниченный доступ | Менеджеры |
| **user** | Базовый доступ | Рядовые пользователи |

**3. Логика проверки:**

```
Пользователь заходит на /services/referal/users

1. Проверка: System Admin (GOD/admin в auth)? → Доступ разрешен
2. Проверка: Service Manager (service-manager в auth)? → Доступ разрешен
3. Проверка: Service Admin (admin в referal)? → Доступ разрешен
4. Иначе → Доступ запрещен
```

### Почему этот вариант:

1. **Минимальные изменения** - не нужно трогать микросервисы
2. **Простота** - всего 2 новых разрешения
3. **Гибкость** - можно дальше расширять
4. **Безопасность** - service-manager НЕ имеет доступа к данным сервисов, только к управлению через auth
5. **Масштабируемость** - легко добавлять новые сервисы

---

## 🚀 План реализации (Вариант 1)

### Этап 1: Обновить разрешения auth-service

```mongodb
db.services.updateOne(
  {key: "auth"},
  {$push: {
    availablePermissions: {
      $each: [
        {
          name: "auth.services.manage_admins",
          displayName: "Управление администраторами сервисов",
          description: "Назначение администраторов для любых сервисов через auth-service",
          category: "services"
        },
        {
          name: "auth.services.manage_users",
          displayName: "Управление пользователями сервисов",
          description: "Управление пользователями любых сервисов через auth-service",
          category: "services"
        }
      ]
    }
  }}
)
```

### Этап 2: Обновить роль service-manager

```mongodb
db.service_roles.updateOne(
  {service: "auth", name: "service-manager"},
  {$push: {
    permissions: {
      $each: [
        "auth.services.manage_admins",
        "auth.services.manage_users"
      ]
    }
  }}
)
```

### Этап 3: Добавить функцию проверки

```go
// routes/middleware.go
func hasServiceManagerRole(user *models.User) bool {
    userServiceRoles, err := models.GetUserServiceRolesByUserID(user.ID)
    if err != nil {
        return false
    }
    
    for _, role := range userServiceRoles {
        if role.ServiceKey == "auth" && role.RoleName == "service-manager" && role.IsActive {
            return true
        }
    }
    return false
}
```

### Этап 4: Обновить middleware

```go
// routes/middleware.go - функция serviceAdminAuthRequired()
// После проверки isSystemAdmin добавить:

// Check if user is service manager in auth
if hasServiceManagerRole(user) {
    c.Set("isServiceManager", true)
    c.Next()
    return
}
```

### Этап 5: Обновить handlers для учёта service-manager

```go
// routes/service_management.go
func getServiceHandlerWithAccess(c *gin.Context) {
    user := c.MustGet("user").(*models.User)
    serviceKey := c.Param("serviceKey")
    
    isSystemAdmin := c.GetBool("isSystemAdmin")
    isServiceManager := c.GetBool("isServiceManager")
    
    // Разрешить доступ если:
    // 1. System Admin
    // 2. Service Manager
    // 3. Admin конкретного сервиса
    if !isSystemAdmin && !isServiceManager && !hasServiceAdminRole(user, service.Key) {
        c.HTML(http.StatusForbidden, "error.html", gin.H{
            "error": "У вас нет прав для доступа к этому сервису",
        })
        return
    }
    
    // ...остальной код
}
```

---

## 📋 Итоговая схема ролей

```
┌─────────────────────────────────────────────────────────────┐
│                    Auth-Service Roles                        │
├─────────────────────────────────────────────────────────────┤
│ GOD                   → Всё                                  │
│ admin                 → Всё кроме GOD                        │
│ service-manager       → Управление всеми сервисами          │
│ user-manager          → Управление пользователями           │
│ viewer                → Только просмотр                      │
│ support               → Просмотр + сброс паролей            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│          Referal Service Roles (пример)                      │
├─────────────────────────────────────────────────────────────┤
│ admin                 → Полный доступ к referal             │
│ manager               → Управление рефералами               │
│ analyst               → Просмотр отчетов                    │
│ user                  → Базовый функционал                  │
└─────────────────────────────────────────────────────────────┘

Управление:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
User A: auth.service-manager
  ↓
  Может назначить User B → referal.admin
  Может назначить User C → client-service.manager
  
User B: referal.admin
  ↓
  Может работать с функционалом referal
  НЕ может назначать себе админов других сервисов
```
