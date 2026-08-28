# ===================================================================
# СТРАНИЦЫ ОШИБОК ШЛЮЗА
# ===================================================================
# Подключается из gateway.inc внутри server-блока.
#
# Что здесь происходит:
#   1. proxy_intercept_errors on — ответы конечных сервисов с кодом 300+
#      заменяются страницей шлюза. Без этого 500 от сервиса уходил бы
#      пользователю как есть: голая страница Flask или пустое тело.
#   2. errors-pages.inc — карта «код -> файл», сгенерирована из codes.py.
#   3. location /_errors/ — internal-раздача готовых страниц с включённым SSI.
#   4. errors-preview.inc — витрина всех кодов для администратора.
#
# ВАЖНО про перехват: включая его, nginx выбрасывает тело ответа сервиса.
# Достать из него JSON с описанием ошибки нельзя — nginx тела не разбирает.
# Поэтому сервис, которому есть что сказать, кладёт текст в заголовки
# X-Error-Code и X-Error-Detail: их шлюз читает как $upstream_http_* и
# показывает в блоке «Технические подробности».
#
# Обратная сторона: ответы вида 4xx с JSON-телом до клиента больше не
# доходят — XHR получит HTML. Ветка с JSON заготовлена ниже и включается
# одной правкой, когда появится внешнее API.
# ===================================================================

proxy_intercept_errors on;

# limit_req по умолчанию отвечает 503 «сервис недоступен», хотя причина
# другая — превышен лимит частоты. 429 и точнее, и попадает на страницу
# с понятным текстом «подождите минуту».
limit_req_status 429;

# Карта кодов на файлы страниц (сгенерирована error-pages/generate.py).
include /etc/nginx/conf.d/errors-pages.inc;

# ================================================================
# РАЗДАЧА СТРАНИЦ
# ================================================================

# internal: страницы отдаются только по внутреннему редиректу error_page.
# Прямой заход на /_errors/500.html вернёт 404 — иначе ссылку на «красивую
# ошибку» начали бы слать вместо настоящей диагностики.
location ^~ /_errors/ {
    internal;
    alias /usr/share/nginx/html/errors/;
    charset utf-8;

    # SSI включён точечно, только на этой раздаче: включать его глобально
    # значило бы разбирать HTML всех проксируемых страниц портала.
    ssi on;
    ssi_types text/html;

    # add_header в location отменяет наследование серверных заголовков,
    # поэтому защиту приходится перечислить заново. Политика здесь строже
    # общей: странице нужны только свой CSS и два инлайновых скрипта.
    add_header Content-Security-Policy "default-src 'none'; style-src 'self'; script-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    # Страница несёт время, узел и идентификатор запроса — кэшировать нельзя.
    add_header Cache-Control "no-store" always;
}

# Стили страниц ошибок. Отдаются публично и самим nginx: когда лежит
# auth-service, вместе с ним недоступен /static/css/styles.css, а страница
# ошибки обязана выглядеть прилично именно в этот момент.
location = /_errors/errors.css {
    alias /usr/share/nginx/html/errors/errors.css;
    default_type text/css;
    access_log off;
    expires 1h;
    add_header Cache-Control "public, max-age=3600" always;
    add_header X-Content-Type-Options "nosniff" always;
}

# Отсутствующий ассет. Страница для человека в ответ на <script src> или
# <link rel="stylesheet"> — несколько килобайт разметки, которую браузер
# выбросит, не показав. Отдаём пустое тело с тем же кодом.
location @asset_not_found {
    return 404 "";
}

# ================================================================
# ПРЕДПРОСМОТР (только администратор)
# ================================================================
include /etc/nginx/conf.d/errors-preview.inc;

# ================================================================
# ЗАГОТОВКА: JSON ВМЕСТО СТРАНИЦЫ ДЛЯ API-КЛИЕНТОВ
# ================================================================
# Пока весь трафик шлюза — браузерный, и все клиенты получают HTML.
# Когда появится внешнее API, включаются три вещи:
#   1. map $http_accept $gw_wants_json в nginx.conf (уже описан);
#   2. блок ниже;
#   3. в errors-pages.inc коды переводятся на @error_json через
#      условие — правится генератор, а не файл.
#
# location @error_json {
#     internal;
#     default_type application/json;
#     add_header Cache-Control "no-store" always;
#     return 200 '{"error":{"status":$gw_error_code,"service":"$gw_service_key","request_id":"$request_id"}}';
# }
