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
# ЗАКРЫТО авторизацией шлюза: /verify проверяет токен и наличие роли/разрешения
# для сервиса "quiz" (сервис определяется по первому сегменту пути). Личность
# пользователя пробрасывается в backend заголовками X-User-* (для будущего
# enforcement по разрешениям в quiz-backend).
location ^~ /quiz/api/v1/admin/ {
    auth_request /verify;
    auth_request_set $auth_user_id                  $upstream_http_x_user_id;
    auth_request_set $auth_user_name                $upstream_http_x_user_name;
    auth_request_set $auth_user_admin               $upstream_http_x_user_admin;
    auth_request_set $auth_user_service_roles       $upstream_http_x_user_service_roles;
    auth_request_set $auth_user_service_permissions $upstream_http_x_user_service_permissions;

    limit_req zone=quiz_api burst=20 nodelay;

    set $quiz_backend_upstream http://quiz-backend:8000;
    rewrite ^/quiz/api/(.*)$ /api/$1 break;
    proxy_pass $quiz_backend_upstream;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Проброс личности в backend
    proxy_set_header X-User-Id $auth_user_id;
    proxy_set_header X-User-Name $auth_user_name;
    proxy_set_header X-User-Admin $auth_user_admin;
    proxy_set_header X-User-Service-Roles $auth_user_service_roles;
    proxy_set_header X-User-Service-Permissions $auth_user_service_permissions;
    proxy_set_header X-Service-Key quiz;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
}

# --- API (FastAPI backend) ---
# https://analytics.gh.uz/quiz/api/v1/... -> http://quiz-backend:8000/api/v1/...
location ^~ /quiz/api/ {
    # ВРЕМЕННО: проверка Origin/Referer отключена для тестирования.
    # Чтобы вернуть защиту — раскомментировать строку ниже.
    # if ($quiz_gh_uz_denied) { return 444; }
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
    # ВРЕМЕННО: проверка Origin/Referer отключена для тестирования.
    # Чтобы вернуть защиту — раскомментировать строку ниже.
    # if ($quiz_gh_uz_denied) { return 444; }

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

# --- Полноразмерная страница квиза ---
# https://analytics.gh.uz/quiz/<id> -> index.html виджета (full-page режим).
# Ассеты (/quiz/widget/assets/...) и API (/quiz/api/...) обслуживаются своими
# блоками выше. Открывается напрямую в браузере как обычная страница.
# Regex-локация имеет приоритет над префиксным catch-all `location /quiz/`.
location ~ ^/quiz/(\d+)/?$ {
    # ВРЕМЕННО: проверка Origin/Referer отключена для тестирования.
    # Чтобы вернуть защиту — раскомментировать строку ниже.
    # if ($quiz_gh_uz_denied) { return 444; }

    set $quiz_widget_upstream http://quiz-widget:80;
    rewrite ^.*$ /index.html break;
    proxy_pass $quiz_widget_upstream;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;

    add_header Cache-Control "no-store" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
}

# --- Админ-панель (SPA) ---
# ЗАКРЫТО авторизацией шлюза. Неаутентифицированный пользователь получит 401 ->
# редирект на /login (error_page 401 на уровне server-блока), без роли для quiz —
# 403 -> /access-denied. Меню ведёт сюда (Service.MenuURL = /quiz/admin/).
location = /quiz/admin {
    return 301 /quiz/admin/;
}

location ^~ /quiz/admin/ {
    auth_request /verify;
    auth_request_set $auth_user_id                  $upstream_http_x_user_id;
    auth_request_set $auth_user_name                $upstream_http_x_user_name;
    auth_request_set $auth_user_admin               $upstream_http_x_user_admin;
    auth_request_set $auth_user_service_roles       $upstream_http_x_user_service_roles;
    auth_request_set $auth_user_service_permissions $upstream_http_x_user_service_permissions;

    set $quiz_admin_upstream http://quiz-admin:80;
    rewrite ^/quiz/admin/(.*)$ /$1 break;
    proxy_pass $quiz_admin_upstream;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;

    # Проброс личности в админку
    proxy_set_header X-User-Id $auth_user_id;
    proxy_set_header X-User-Name $auth_user_name;
    proxy_set_header X-User-Admin $auth_user_admin;
    proxy_set_header X-User-Service-Roles $auth_user_service_roles;
    proxy_set_header X-User-Service-Permissions $auth_user_service_permissions;
    proxy_set_header X-Service-Key quiz;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
}

# --- Всё остальное под /quiz/ закрыто ---
location /quiz/ {
    return 404;
}
