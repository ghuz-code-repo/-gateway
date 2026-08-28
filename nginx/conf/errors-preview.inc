# ===================================================================
# ПРЕДПРОСМОТР СТРАНИЦ ОШИБОК — ТОЛЬКО ДЛЯ АДМИНИСТРАТОРА
# ===================================================================
# СГЕНЕРИРОВАНО error-pages/generate.py — РУКАМИ НЕ ПРАВИТЬ.
#
# Каждый location возвращает свой статус-код, а error_page из errors.inc
# подменяет ответ настоящей страницей ошибки. Так вёрстку проверяют на живом
# шлюзе, не роняя сервисы.
#
# Доступ закрыт auth_request /verify-admin: неадминистратор получит 401 и
# уйдёт на /login либо 403 и увидит обычную страницу отказа.
# ===================================================================

location = /errors-preview {
    return 301 /errors-preview/;
}

location = /errors-preview/ {
    auth_request /verify-admin;
    alias /usr/share/nginx/html/errors/preview.html;
    default_type text/html;
    ssi on;
    add_header Cache-Control "no-store" always;
}

location = /errors-preview/400 {
    auth_request /verify-admin;
    return 400;
}

location = /errors-preview/402 {
    auth_request /verify-admin;
    return 402;
}

location = /errors-preview/403 {
    auth_request /verify-admin;
    return 403;
}

location = /errors-preview/404 {
    auth_request /verify-admin;
    return 404;
}

location = /errors-preview/405 {
    auth_request /verify-admin;
    return 405;
}

location = /errors-preview/406 {
    auth_request /verify-admin;
    return 406;
}

location = /errors-preview/407 {
    auth_request /verify-admin;
    return 407;
}

location = /errors-preview/408 {
    auth_request /verify-admin;
    return 408;
}

location = /errors-preview/409 {
    auth_request /verify-admin;
    return 409;
}

location = /errors-preview/410 {
    auth_request /verify-admin;
    return 410;
}

location = /errors-preview/411 {
    auth_request /verify-admin;
    return 411;
}

location = /errors-preview/412 {
    auth_request /verify-admin;
    return 412;
}

location = /errors-preview/413 {
    auth_request /verify-admin;
    return 413;
}

location = /errors-preview/414 {
    auth_request /verify-admin;
    return 414;
}

location = /errors-preview/415 {
    auth_request /verify-admin;
    return 415;
}

location = /errors-preview/416 {
    auth_request /verify-admin;
    return 416;
}

location = /errors-preview/417 {
    auth_request /verify-admin;
    return 417;
}

location = /errors-preview/418 {
    auth_request /verify-admin;
    return 418;
}

location = /errors-preview/421 {
    auth_request /verify-admin;
    return 421;
}

location = /errors-preview/422 {
    auth_request /verify-admin;
    return 422;
}

location = /errors-preview/423 {
    auth_request /verify-admin;
    return 423;
}

location = /errors-preview/424 {
    auth_request /verify-admin;
    return 424;
}

location = /errors-preview/425 {
    auth_request /verify-admin;
    return 425;
}

location = /errors-preview/426 {
    auth_request /verify-admin;
    return 426;
}

location = /errors-preview/428 {
    auth_request /verify-admin;
    return 428;
}

location = /errors-preview/429 {
    auth_request /verify-admin;
    return 429;
}

location = /errors-preview/431 {
    auth_request /verify-admin;
    return 431;
}

location = /errors-preview/451 {
    auth_request /verify-admin;
    return 451;
}

location = /errors-preview/500 {
    auth_request /verify-admin;
    return 500;
}

location = /errors-preview/501 {
    auth_request /verify-admin;
    return 501;
}

location = /errors-preview/502 {
    auth_request /verify-admin;
    return 502;
}

location = /errors-preview/503 {
    auth_request /verify-admin;
    return 503;
}

location = /errors-preview/504 {
    auth_request /verify-admin;
    return 504;
}

location = /errors-preview/505 {
    auth_request /verify-admin;
    return 505;
}

location = /errors-preview/506 {
    auth_request /verify-admin;
    return 506;
}

location = /errors-preview/507 {
    auth_request /verify-admin;
    return 507;
}

location = /errors-preview/508 {
    auth_request /verify-admin;
    return 508;
}

location = /errors-preview/510 {
    auth_request /verify-admin;
    return 510;
}

location = /errors-preview/511 {
    auth_request /verify-admin;
    return 511;
}
