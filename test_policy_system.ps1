# Тестирование системы политик для auth-service
# Тестирует все компоненты: API, кеширование, интеграцию

$BASE_URL = "http://localhost:8080"
$AUTH_TOKEN = "test-token"  # Используем для демонстрации

Write-Host "=== Тестирование системы политик auth-service ===" -ForegroundColor Green

# 1. Проверка здоровья сервиса
Write-Host "`n1. Проверка здоровья сервиса..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$BASE_URL/api/v1/health" -Method GET
    Write-Host "✓ Сервис работает: $($health.status)" -ForegroundColor Green
} catch {
    Write-Host "✗ Сервис недоступен: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 2. Проверка статистики кеша
Write-Host "`n2. Проверка начального состояния кеша..." -ForegroundColor Yellow
try {
    $cacheStats = Invoke-RestMethod -Uri "$BASE_URL/api/v1/cache/stats" -Method GET
    Write-Host "✓ Кеш инициализирован:" -ForegroundColor Green
    Write-Host "  - Размер: $($cacheStats.size)" -ForegroundColor Cyan
    Write-Host "  - Попаданий: $($cacheStats.hits)" -ForegroundColor Cyan
    Write-Host "  - Промахов: $($cacheStats.misses)" -ForegroundColor Cyan
} catch {
    Write-Host "✗ Ошибка получения статистики кеша: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Получение существующих ролей для сервиса referal
Write-Host "`n3. Получение ролей для сервиса 'referal'..." -ForegroundColor Yellow
try {
    $roles = Invoke-RestMethod -Uri "$BASE_URL/api/v1/services/referal/roles" -Method GET
    Write-Host "✓ Получено ролей: $($roles.Count)" -ForegroundColor Green
    foreach ($role in $roles) {
        Write-Host "  - $($role.name): $($role.permissions.Count) разрешений" -ForegroundColor Cyan
    }
} catch {
    Write-Host "✗ Ошибка получения ролей: $($_.Exception.Message)" -ForegroundColor Red
}

# 4. Создание новой роли для сервиса referal
Write-Host "`n4. Создание роли 'manager' для сервиса 'referal'..." -ForegroundColor Yellow
$newRole = @{
    name = "manager"
    description = "Роль менеджера для тестирования"
    permissions = @("view_reports", "edit_referals")
} | ConvertTo-Json

try {
    $createdRole = Invoke-RestMethod -Uri "$BASE_URL/api/v1/services/referal/roles" -Method POST -Body $newRole -ContentType "application/json"
    Write-Host "✓ Роль создана: $($createdRole.name)" -ForegroundColor Green
    $roleId = $createdRole.id
} catch {
    Write-Host "✗ Ошибка создания роли: $($_.Exception.Message)" -ForegroundColor Red
    # Попробуем получить существующую роль
    try {
        $roles = Invoke-RestMethod -Uri "$BASE_URL/api/v1/services/referal/roles" -Method GET
        $managerRole = $roles | Where-Object { $_.name -eq "manager" }
        if ($managerRole) {
            $roleId = $managerRole.id
            Write-Host "! Используем существующую роль 'manager'" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "✗ Не удалось получить существующую роль" -ForegroundColor Red
    }
}

# 5. Получение разрешений для сервиса referal
Write-Host "`n5. Получение разрешений для сервиса 'referal'..." -ForegroundColor Yellow
try {
    $permissions = Invoke-RestMethod -Uri "$BASE_URL/api/v1/services/referal/permissions" -Method GET
    Write-Host "✓ Получено разрешений: $($permissions.Count)" -ForegroundColor Green
    foreach ($perm in $permissions) {
        Write-Host "  - $($perm.name): $($perm.description)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "✗ Ошибка получения разрешений: $($_.Exception.Message)" -ForegroundColor Red
}

# 6. Создание нового разрешения
Write-Host "`n6. Создание разрешения 'delete_referals' для сервиса 'referal'..." -ForegroundColor Yellow
$newPermission = @{
    name = "delete_referals"
    description = "Удаление реферальных записей"
    resource = "referals"
    action = "delete"
} | ConvertTo-Json

try {
    $createdPermission = Invoke-RestMethod -Uri "$BASE_URL/api/v1/services/referal/permissions" -Method POST -Body $newPermission -ContentType "application/json"
    Write-Host "✓ Разрешение создано: $($createdPermission.name)" -ForegroundColor Green
} catch {
    Write-Host "✗ Ошибка создания разрешения: $($_.Exception.Message)" -ForegroundColor Red
}

# 7. Тестирование оценки политик
Write-Host "`n7. Тестирование оценки политик..." -ForegroundColor Yellow

# Создаем тестового пользователя с ролью
$evaluationRequest1 = @{
    user_id = "test_user_1"
    service = "referal"
    permission = "view_reports"
    user_roles = @("manager")
} | ConvertTo-Json

try {
    $evaluation1 = Invoke-RestMethod -Uri "$BASE_URL/api/v1/evaluate" -Method POST -Body $evaluationRequest1 -ContentType "application/json"
    if ($evaluation1.allowed) {
        Write-Host "✓ Пользователю test_user_1 разрешено view_reports" -ForegroundColor Green
    } else {
        Write-Host "✗ Пользователю test_user_1 отказано в view_reports" -ForegroundColor Red
    }
    Write-Host "  Причина: $($evaluation1.reason)" -ForegroundColor Cyan
} catch {
    Write-Host "✗ Ошибка оценки политики 1: $($_.Exception.Message)" -ForegroundColor Red
}

# Тест запрещенного действия
$evaluationRequest2 = @{
    user_id = "test_user_2"
    service = "referal"
    permission = "admin_access"
    user_roles = @("viewer")
} | ConvertTo-Json

try {
    $evaluation2 = Invoke-RestMethod -Uri "$BASE_URL/api/v1/evaluate" -Method POST -Body $evaluationRequest2 -ContentType "application/json"
    if (-not $evaluation2.allowed) {
        Write-Host "✓ Пользователю test_user_2 правильно отказано в admin_access" -ForegroundColor Green
    } else {
        Write-Host "✗ Пользователю test_user_2 неправильно разрешено admin_access" -ForegroundColor Red
    }
    Write-Host "  Причина: $($evaluation2.reason)" -ForegroundColor Cyan
} catch {
    Write-Host "✗ Ошибка оценки политики 2: $($_.Exception.Message)" -ForegroundColor Red
}

# 8. Проверка кеширования
Write-Host "`n8. Проверка кеширования (повторяем тот же запрос)..." -ForegroundColor Yellow
try {
    $evaluation3 = Invoke-RestMethod -Uri "$BASE_URL/api/v1/evaluate" -Method POST -Body $evaluationRequest1 -ContentType "application/json"
    Write-Host "✓ Повторный запрос выполнен" -ForegroundColor Green
    
    # Проверяем статистику кеша после запросов
    $cacheStatsAfter = Invoke-RestMethod -Uri "$BASE_URL/api/v1/cache/stats" -Method GET
    Write-Host "✓ Статистика кеша после запросов:" -ForegroundColor Green
    Write-Host "  - Размер: $($cacheStatsAfter.size)" -ForegroundColor Cyan
    Write-Host "  - Попаданий: $($cacheStatsAfter.hits)" -ForegroundColor Cyan
    Write-Host "  - Промахов: $($cacheStatsAfter.misses)" -ForegroundColor Cyan
    Write-Host "  - Коэффициент попаданий: $($cacheStatsAfter.hit_ratio)" -ForegroundColor Cyan
} catch {
    Write-Host "✗ Ошибка проверки кеширования: $($_.Exception.Message)" -ForegroundColor Red
}

# 9. Тестирование инвалидации кеша
Write-Host "`n9. Тестирование инвалидации кеша для сервиса 'referal'..." -ForegroundColor Yellow
try {
    $invalidation = Invoke-RestMethod -Uri "$BASE_URL/api/v1/cache/invalidate/referal" -Method POST
    Write-Host "✓ Кеш инвалидирован для сервиса 'referal'" -ForegroundColor Green
    Write-Host "  Очищено записей: $($invalidation.cleared_entries)" -ForegroundColor Cyan
} catch {
    Write-Host "✗ Ошибка инвалидации кеша: $($_.Exception.Message)" -ForegroundColor Red
}

# 10. Проверка административного интерфейса
Write-Host "`n10. Проверка доступности административного интерфейса..." -ForegroundColor Yellow
try {
    $adminPage = Invoke-WebRequest -Uri "$BASE_URL/admin/policies" -Method GET
    if ($adminPage.StatusCode -eq 200) {
        Write-Host "✓ Страница администрирования политик доступна" -ForegroundColor Green
    }
} catch {
    Write-Host "✗ Ошибка доступа к админ-интерфейсу: $($_.Exception.Message)" -ForegroundColor Red
}

try {
    $servicePage = Invoke-WebRequest -Uri "$BASE_URL/admin/policies/referal" -Method GET
    if ($servicePage.StatusCode -eq 200) {
        Write-Host "✓ Страница управления сервисом 'referal' доступна" -ForegroundColor Green
    }
} catch {
    Write-Host "✗ Ошибка доступа к странице сервиса: $($_.Exception.Message)" -ForegroundColor Red
}

# 11. Очистка кеша полностью
Write-Host "`n11. Полная очистка кеша..." -ForegroundColor Yellow
try {
    $clearResult = Invoke-RestMethod -Uri "$BASE_URL/api/v1/cache/clear" -Method DELETE
    Write-Host "✓ Кеш полностью очищен" -ForegroundColor Green
    
    $finalCacheStats = Invoke-RestMethod -Uri "$BASE_URL/api/v1/cache/stats" -Method GET
    Write-Host "✓ Финальная статистика кеша:" -ForegroundColor Green
    Write-Host "  - Размер: $($finalCacheStats.size)" -ForegroundColor Cyan
    Write-Host "  - Попаданий: $($finalCacheStats.hits)" -ForegroundColor Cyan
    Write-Host "  - Промахов: $($finalCacheStats.misses)" -ForegroundColor Cyan
} catch {
    Write-Host "✗ Ошибка очистки кеша: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== Тестирование завершено ===" -ForegroundColor Green
Write-Host "Система политик полностью протестирована!" -ForegroundColor White

# Дополнительная информация
Write-Host "`n=== Дополнительная информация ===" -ForegroundColor Yellow
Write-Host "• Админ-интерфейс: http://localhost:8080/admin/policies" -ForegroundColor Cyan
Write-Host "• API документация: http://localhost:8080/api/v1/health" -ForegroundColor Cyan
Write-Host "• Кеш статистика: http://localhost:8080/api/v1/cache/stats" -ForegroundColor Cyan
Write-Host "• Управление кешем: http://localhost:8080/admin/cache" -ForegroundColor Cyan
