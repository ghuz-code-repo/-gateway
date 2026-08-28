# ===================================================================
# КОД ОТВЕТА -> СТРАНИЦА ОШИБКИ
# ===================================================================
# СГЕНЕРИРОВАНО error-pages/generate.py — РУКАМИ НЕ ПРАВИТЬ.
# Каталог кодов и тексты живут в error-pages/codes.py.
#
# Файл подключается из errors.inc внутри server-блока. Каждый код получает
# отдельный файл, потому что заголовок и текст у страниц разные, а $status
# внутри error_page уже равен коду обрабатываемой страницы, а не исходному.
#
# 401 и 403 здесь отсутствуют намеренно: они обрабатываются редиректами
# на /login и /access-denied в gateway.inc.
# ===================================================================

error_page 400 /_errors/400.html;
error_page 402 /_errors/402.html;
error_page 403 /_errors/403.html;
error_page 404 /_errors/404.html;
error_page 405 /_errors/405.html;
error_page 406 /_errors/406.html;
error_page 407 /_errors/407.html;
error_page 408 /_errors/408.html;
error_page 409 /_errors/409.html;
error_page 410 /_errors/410.html;
error_page 411 /_errors/411.html;
error_page 412 /_errors/412.html;
error_page 413 /_errors/413.html;
error_page 414 /_errors/414.html;
error_page 415 /_errors/415.html;
error_page 416 /_errors/416.html;
error_page 417 /_errors/417.html;
error_page 418 /_errors/418.html;
error_page 421 /_errors/421.html;
error_page 422 /_errors/422.html;
error_page 423 /_errors/423.html;
error_page 424 /_errors/424.html;
error_page 425 /_errors/425.html;
error_page 426 /_errors/426.html;
error_page 428 /_errors/428.html;
error_page 429 /_errors/429.html;
error_page 431 /_errors/431.html;
error_page 451 /_errors/451.html;
error_page 500 /_errors/500.html;
error_page 501 /_errors/501.html;
error_page 502 /_errors/502.html;
error_page 503 /_errors/503.html;
error_page 504 /_errors/504.html;
error_page 505 /_errors/505.html;
error_page 506 /_errors/506.html;
error_page 507 /_errors/507.html;
error_page 508 /_errors/508.html;
error_page 510 /_errors/510.html;
error_page 511 /_errors/511.html;
