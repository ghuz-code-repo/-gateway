# ростой скрипт удаления favicon строк
$templateDir = "templates"
$htmlFiles = Get-ChildItem -Path $templateDir -Filter "*.html" -Recurse

Write-Host "айдено файлов: $($htmlFiles.Count)"

foreach ($file in $htmlFiles) {
    $lines = Get-Content -Path $file.FullName -Encoding UTF8
    $newLines = @()
    $changed = $false
    
    foreach ($line in $lines) {
        # ропускаем строки с favicon
        if ($line -match 'rel="icon"' -or 
            $line -match "rel='icon'" -or 
            $line -match 'favicon\.(svg|png|ico)' -or
            $line -match 'apple-touch-icon') {
            Write-Host "даляем из $($file.Name): $($line.Trim())"
            $changed = $true
        } else {
            $newLines += $line
        }
    }
    
    if ($changed) {
        Set-Content -Path $file.FullName -Value $newLines -Encoding UTF8
        Write-Host "бновлён: $($file.Name)"
    }
}

Write-Host "отово!"
