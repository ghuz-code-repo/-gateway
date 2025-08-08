# Test Policy System
$BASE_URL = "http://localhost:8080"

Write-Host "=== Testing Policy System ===" -ForegroundColor Green

# 1. Health check
Write-Host "`n1. Health check..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$BASE_URL/api/v1/health" -Method GET
    Write-Host "OK Service is running: $($health.status)" -ForegroundColor Green
} catch {
    Write-Host "ERROR Service unavailable: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 2. Cache stats
Write-Host "`n2. Cache stats..." -ForegroundColor Yellow
try {
    $cacheStats = Invoke-RestMethod -Uri "$BASE_URL/api/v1/cache/stats" -Method GET
    Write-Host "OK Cache initialized:" -ForegroundColor Green
    Write-Host "  Size: $($cacheStats.size)" -ForegroundColor Cyan
    Write-Host "  Hits: $($cacheStats.hits)" -ForegroundColor Cyan
    Write-Host "  Misses: $($cacheStats.misses)" -ForegroundColor Cyan
} catch {
    Write-Host "ERROR Cache stats: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Get existing roles
Write-Host "`n3. Get roles for 'referal' service..." -ForegroundColor Yellow
try {
    $roles = Invoke-RestMethod -Uri "$BASE_URL/api/v1/services/referal/roles" -Method GET
    Write-Host "OK Found roles: $($roles.Count)" -ForegroundColor Green
    foreach ($role in $roles) {
        Write-Host "  - $($role.name): $($role.permissions.Count) permissions" -ForegroundColor Cyan
    }
} catch {
    Write-Host "ERROR Getting roles: $($_.Exception.Message)" -ForegroundColor Red
}

# 4. Create new role
Write-Host "`n4. Create 'manager' role for 'referal' service..." -ForegroundColor Yellow
$newRole = @{
    name = "manager"
    description = "Manager role for testing"
    permissions = @("view_reports", "edit_referals")
} | ConvertTo-Json

try {
    $createdRole = Invoke-RestMethod -Uri "$BASE_URL/api/v1/services/referal/roles" -Method POST -Body $newRole -ContentType "application/json"
    Write-Host "OK Role created: $($createdRole.name)" -ForegroundColor Green
    $roleId = $createdRole.id
} catch {
    Write-Host "ERROR Creating role: $($_.Exception.Message)" -ForegroundColor Red
    try {
        $roles = Invoke-RestMethod -Uri "$BASE_URL/api/v1/services/referal/roles" -Method GET
        $managerRole = $roles | Where-Object { $_.name -eq "manager" }
        if ($managerRole) {
            $roleId = $managerRole.id
            Write-Host "WARN Using existing 'manager' role" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "ERROR Cannot get existing role" -ForegroundColor Red
    }
}

# 5. Get permissions
Write-Host "`n5. Get permissions for 'referal' service..." -ForegroundColor Yellow
try {
    $permissions = Invoke-RestMethod -Uri "$BASE_URL/api/v1/services/referal/permissions" -Method GET
    Write-Host "OK Found permissions: $($permissions.Count)" -ForegroundColor Green
    foreach ($perm in $permissions) {
        Write-Host "  - $($perm.name): $($perm.description)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "ERROR Getting permissions: $($_.Exception.Message)" -ForegroundColor Red
}

# 6. Create new permission
Write-Host "`n6. Create 'delete_referals' permission..." -ForegroundColor Yellow
$newPermission = @{
    name = "delete_referals"
    description = "Delete referal records"
    resource = "referals"
    action = "delete"
} | ConvertTo-Json

try {
    $createdPermission = Invoke-RestMethod -Uri "$BASE_URL/api/v1/services/referal/permissions" -Method POST -Body $newPermission -ContentType "application/json"
    Write-Host "OK Permission created: $($createdPermission.name)" -ForegroundColor Green
} catch {
    Write-Host "ERROR Creating permission: $($_.Exception.Message)" -ForegroundColor Red
}

# 7. Test policy evaluation
Write-Host "`n7. Test policy evaluation..." -ForegroundColor Yellow

$evaluationRequest1 = @{
    user_id = "test_user_1"
    service = "referal"
    permission = "view_reports"
    user_roles = @("manager")
} | ConvertTo-Json

try {
    $evaluation1 = Invoke-RestMethod -Uri "$BASE_URL/api/v1/evaluate" -Method POST -Body $evaluationRequest1 -ContentType "application/json"
    if ($evaluation1.allowed) {
        Write-Host "OK User test_user_1 allowed view_reports" -ForegroundColor Green
    } else {
        Write-Host "ERROR User test_user_1 denied view_reports" -ForegroundColor Red
    }
    Write-Host "  Reason: $($evaluation1.reason)" -ForegroundColor Cyan
} catch {
    Write-Host "ERROR Policy evaluation 1: $($_.Exception.Message)" -ForegroundColor Red
}

# Test denied action
$evaluationRequest2 = @{
    user_id = "test_user_2"
    service = "referal"
    permission = "admin_access"
    user_roles = @("viewer")
} | ConvertTo-Json

try {
    $evaluation2 = Invoke-RestMethod -Uri "$BASE_URL/api/v1/evaluate" -Method POST -Body $evaluationRequest2 -ContentType "application/json"
    if (-not $evaluation2.allowed) {
        Write-Host "OK User test_user_2 correctly denied admin_access" -ForegroundColor Green
    } else {
        Write-Host "ERROR User test_user_2 incorrectly allowed admin_access" -ForegroundColor Red
    }
    Write-Host "  Reason: $($evaluation2.reason)" -ForegroundColor Cyan
} catch {
    Write-Host "ERROR Policy evaluation 2: $($_.Exception.Message)" -ForegroundColor Red
}

# 8. Test caching
Write-Host "`n8. Test caching (repeat same request)..." -ForegroundColor Yellow
try {
    $evaluation3 = Invoke-RestMethod -Uri "$BASE_URL/api/v1/evaluate" -Method POST -Body $evaluationRequest1 -ContentType "application/json"
    Write-Host "OK Repeated request executed" -ForegroundColor Green
    
    $cacheStatsAfter = Invoke-RestMethod -Uri "$BASE_URL/api/v1/cache/stats" -Method GET
    Write-Host "OK Cache stats after requests:" -ForegroundColor Green
    Write-Host "  Size: $($cacheStatsAfter.size)" -ForegroundColor Cyan
    Write-Host "  Hits: $($cacheStatsAfter.hits)" -ForegroundColor Cyan
    Write-Host "  Misses: $($cacheStatsAfter.misses)" -ForegroundColor Cyan
    Write-Host "  Hit ratio: $($cacheStatsAfter.hit_ratio)" -ForegroundColor Cyan
} catch {
    Write-Host "ERROR Testing caching: $($_.Exception.Message)" -ForegroundColor Red
}

# 9. Test cache invalidation
Write-Host "`n9. Test cache invalidation for 'referal'..." -ForegroundColor Yellow
try {
    $invalidation = Invoke-RestMethod -Uri "$BASE_URL/api/v1/cache/invalidate/referal" -Method POST
    Write-Host "OK Cache invalidated for 'referal'" -ForegroundColor Green
    Write-Host "  Cleared entries: $($invalidation.cleared_entries)" -ForegroundColor Cyan
} catch {
    Write-Host "ERROR Cache invalidation: $($_.Exception.Message)" -ForegroundColor Red
}

# 10. Test admin interface
Write-Host "`n10. Test admin interface..." -ForegroundColor Yellow
try {
    $adminPage = Invoke-WebRequest -Uri "$BASE_URL/admin/policies" -Method GET
    if ($adminPage.StatusCode -eq 200) {
        Write-Host "OK Admin policies page accessible" -ForegroundColor Green
    }
} catch {
    Write-Host "ERROR Admin interface: $($_.Exception.Message)" -ForegroundColor Red
}

try {
    $servicePage = Invoke-WebRequest -Uri "$BASE_URL/admin/policies/referal" -Method GET
    if ($servicePage.StatusCode -eq 200) {
        Write-Host "OK Service 'referal' management page accessible" -ForegroundColor Green
    }
} catch {
    Write-Host "ERROR Service page: $($_.Exception.Message)" -ForegroundColor Red
}

# 11. Clear cache
Write-Host "`n11. Clear all cache..." -ForegroundColor Yellow
try {
    $clearResult = Invoke-RestMethod -Uri "$BASE_URL/api/v1/cache/clear" -Method DELETE
    Write-Host "OK Cache cleared completely" -ForegroundColor Green
    
    $finalCacheStats = Invoke-RestMethod -Uri "$BASE_URL/api/v1/cache/stats" -Method GET
    Write-Host "OK Final cache stats:" -ForegroundColor Green
    Write-Host "  Size: $($finalCacheStats.size)" -ForegroundColor Cyan
    Write-Host "  Hits: $($finalCacheStats.hits)" -ForegroundColor Cyan
    Write-Host "  Misses: $($finalCacheStats.misses)" -ForegroundColor Cyan
} catch {
    Write-Host "ERROR Clearing cache: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== Testing Complete ===" -ForegroundColor Green
Write-Host "Policy system fully tested!" -ForegroundColor White

Write-Host "`n=== Additional Information ===" -ForegroundColor Yellow
Write-Host "Admin interface: http://localhost:8080/admin/policies" -ForegroundColor Cyan
Write-Host "API health: http://localhost:8080/api/v1/health" -ForegroundColor Cyan
Write-Host "Cache stats: http://localhost:8080/api/v1/cache/stats" -ForegroundColor Cyan
Write-Host "Cache management: http://localhost:8080/admin/cache" -ForegroundColor Cyan
