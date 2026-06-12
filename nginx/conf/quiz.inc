# ===================================================================
# QUIZ SERVICE — изолированный сервис квизов для сайта gh.uz
# ===================================================================
# Включается внутри server-блока gateway.inc.
#
# Безопасность:
#   - Доступ ТОЛЬКО для запросов с сайта gh.uz: проверка заголовков
#     Origin (fetch/XHR) и Referer (загрузка скрипта виджета).
#     Карты $quiz_gh_uz_denied / $quiz_cors_origin определены в nginx.conf.
#   - Сервис живёт в изолированной сети quiz_network (internal) и не имеет
#     доступа к auth-service, notification-service и прочим сервисам.
#   - Никакого auth_request: сервис публичный для gh.uz, авторизация
#     шлюза не используется намеренно.
# ===================================================================

# --- Admin API (вызывается админкой с analytics.gh.uz, same-origin) ---
# БЕЗ проверки gh.uz — по явному решению владельца админка публична.
# ВНИМАНИЕ: любой может редактировать квизы и читать лиды.
location ^~ /quiz/api/v1/admin/ {
    limit_req zone=quiz_api burst=20 nodelay;

    set $quiz_backend_upstream http://quiz-backend:8000;
    rewrite ^/quiz/api/(.*)$ /api/$1 break;
    proxy_pass $quiz_backend_upstream;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
}

# --- API (FastAPI backend) ---
# https://analytics.gh.uz/quiz/api/v1/... -> http://quiz-backend:8000/api/v1/...
location ^~ /quiz/api/ {
    # 444 — закрыть соединение (не 403, чтобы не срабатывал общий redirect шлюза)
    if ($quiz_gh_uz_denied) { return 444; }
    limit_req zone=quiz_api burst=20 nodelay;

    # Переменная — чтобы nginx стартовал, даже если quiz-backend не запущен
    set $quiz_backend_upstream http://quiz-backend:8000;
    rewrite ^/quiz/api/(.*)$ /api/$1 break;
    proxy_pass $quiz_backend_upstream;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
}

# --- Статика виджета (widget.js и ассеты) ---
# https://analytics.gh.uz/quiz/widget/assets/widget.js -> quiz-widget:80/assets/widget.js
location ^~ /quiz/widget/ {
    # 444 — закрыть соединение (не 403, чтобы не срабатывал общий redirect шлюза)
    if ($quiz_gh_uz_denied) { return 444; }

    set $quiz_widget_upstream http://quiz-widget:80;
    rewrite ^/quiz/widget/(.*)$ /$1 break;
    proxy_pass $quiz_widget_upstream;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;

    # CORS для <script type="module"> с gh.uz (модули загружаются в CORS-режиме)
    add_header Access-Control-Allow-Origin $quiz_cors_origin always;
    add_header Cache-Control "public, max-age=3600" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
}

# --- Админ-панель (SPA) ---
# Открывается напрямую в браузере — без проверки Origin/Referer.
location = /quiz/admin {
    return 301 /quiz/admin/;
}

location ^~ /quiz/admin/ {
    set $quiz_admin_upstream http://quiz-admin:80;
    rewrite ^/quiz/admin/(.*)$ /$1 break;
    proxy_pass $quiz_admin_upstream;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
}

# --- Всё остальное под /quiz/ закрыто ---
location /quiz/ {
    return 404;
}
