# PowerShell скрипт для удаления всех favicon тегов из HTML шаблонов
$templateDir = "templates"
$htmlFiles = Get-ChildItem -Path $templateDir -Filter "*.html" -Recurse

Write-Host "айдено файлов для обработки: $($htmlFiles.Count)"

foreach ($file in $htmlFiles) {
    $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8
    $originalContent = $content
    
    # даляем все строки с rel="icon" (включая многострочные теги)
    $content = $content -replace '(?s)<link[^>]*rel=["\'']\s*icon\s*["\'''][^>]*>', ''
    
    # даляем все строки с rel=''icon'' (одинарные кавычки)
    $content = $content -replace '(?s)<link[^>]*rel=["\'']\s*icon\s*["\'''][^>]*>', ''
    
    # даляем строки только с favicon в href
    $content = $content -replace '(?s)<link[^>]*href=["\'']\s*/static/img/favicon\.(svg|png|ico)[^"\''"]*["\'''][^>]*>', ''
    
    # даляем apple-touch-icon
    $content = $content -replace '(?s)<link[^>]*rel=["\'']\s*apple-touch-icon[^"\''"]*["\'''][^>]*>', ''
    
    # бираем лишние пустые строки
    $content = $content -replace '\n\s*\n\s*\n', "`n`n"
    
    if ($content -ne $originalContent) {
        Set-Content -Path $file.FullName -Value $content -Encoding UTF8 -NoNewline
        Write-Host "бновлён: $($file.Name)"
    } else {
        Write-Host "ез изменений: $($file.Name)"
    }
}

Write-Host "бработка завершена!"
