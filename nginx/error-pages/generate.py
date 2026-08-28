# -*- coding: utf-8 -*-
"""Генератор статических страниц ошибок шлюза.

Запуск:
    python !gateway/nginx/error-pages/generate.py

Складывает в nginx/html/errors/:
    <код>.html    — по странице на каждый код из codes.CODES;
    errors.css    — копия error-pages/errors.css;
    preview.html  — витрина всех кодов (только для администратора).

И в nginx/conf/:
    errors-pages.inc   — директивы error_page: код -> файл страницы;
    errors-preview.inc — location-блоки, отдающие каждый код по запросу.

Страницы генерируются, а не пишутся руками, по трём причинам: их 38, каждая
обязана быть самодостаточной (прод в изолированной сети, CDN нет), и текст
должен лежать в одном месте — в codes.py, а не быть размазанным по HTML.

Правку вносят в codes.py / errors.css / шаблон здесь, потом перезапускают
генератор. Файлы в html/errors/ руками не редактируют: test_error_pages.py
проверяет, что они совпадают с выводом генератора.

Динамику подставляет SSI на стороне nginx. Важно: <!--# echo --> по умолчанию
экранирует значение (encoding="entity"), поэтому $request_uri и заголовки
сервиса попадают на страницу безопасно. Атрибут encoding="none" здесь не
использовать — это дыра для XSS.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from codes import CODES  # noqa: E402

SRC_DIR = Path(__file__).resolve().parent
NGINX_DIR = SRC_DIR.parent
OUT_DIR = NGINX_DIR / "html" / "errors"
CONF_DIR = NGINX_DIR / "conf"
PAGES_CONF = CONF_DIR / "errors-pages.inc"
PREVIEW_CONF = CONF_DIR / "errors-preview.inc"

# ---------------------------------------------------------------------------
# Иллюстрации. Линейная графика в currentColor, без заливок и растра:
# так одна и та же картинка читается в светлой и тёмной теме.
# ---------------------------------------------------------------------------

_SVG_OPEN = ('<svg viewBox="0 0 64 64" fill="none" stroke="currentColor" '
             'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" '
             'role="img" aria-hidden="true">')

ART = {
    "question": (
        '<circle cx="32" cy="32" r="24"/>'
        '<path d="M25 25a7 7 0 0 1 13 3c0 5-6 5-6 10"/>'
        '<circle cx="32" cy="45" r="1.6" fill="currentColor"/>'
    ),
    "warning": (
        '<path d="M32 10 58 54H6z"/>'
        '<path d="M32 26v14"/>'
        '<circle cx="32" cy="47" r="1.6" fill="currentColor"/>'
    ),
    "compass": (
        '<circle cx="32" cy="32" r="24"/>'
        '<path d="M42 22 36 36l-14 6 6-14z"/>'
        '<circle cx="32" cy="32" r="2.2" fill="currentColor"/>'
    ),
    "clock": (
        '<circle cx="32" cy="32" r="23"/>'
        '<path d="M32 17v16l11 7"/>'
    ),
    "hourglass": (
        '<path d="M18 8h28M18 56h28"/>'
        '<path d="M22 8v8c0 8 10 12 10 16s-10 8-10 16v8"/>'
        '<path d="M42 8v8c0 8-10 12-10 16s10 8 10 16v8"/>'
        '<path d="M25 48h14"/>'
    ),
    "box": (
        '<path d="M8 22 32 10l24 12v22L32 56 8 44z"/>'
        '<path d="M8 22l24 12 24-12M32 34v22"/>'
    ),
    "lock": (
        '<rect x="14" y="28" width="36" height="26" rx="4"/>'
        '<path d="M23 28v-7a9 9 0 0 1 18 0v7"/>'
        '<circle cx="32" cy="40" r="3"/>'
    ),
    "teapot": (
        '<path d="M14 28h30v10a13 13 0 0 1-13 13h-4a13 13 0 0 1-13-13z"/>'
        '<path d="M44 32h5a5 5 0 0 1 0 10h-5"/>'
        '<path d="M14 32 5 26"/>'
        '<path d="M22 28V24h14v4"/>'
        '<path d="M29 20c0-3 3-3 3-6M36 20c0-3 3-3 3-6"/>'
        '<path d="M12 56h34"/>'
    ),
    "coin": (
        '<circle cx="32" cy="32" r="22"/>'
        '<path d="M32 20v24M38 25c-2-2-5-3-8-2-4 1-5 6 0 8 5 2 8 3 8 7 0 3-4 5-8 4-2 0-4-1-5-2"/>'
    ),
    "shrug": (
        '<circle cx="32" cy="20" r="8"/>'
        '<path d="M20 52c0-7 5-12 12-12s12 5 12 12"/>'
        '<path d="M14 34c-2 4-2 8-1 12M50 34c2 4 2 8 1 12"/>'
    ),
    "book": (
        '<path d="M12 12h16a8 8 0 0 1 8 8v32a8 8 0 0 0-8-8H12z"/>'
        '<path d="M52 12H36a8 8 0 0 0-8 8v32a8 8 0 0 1 8-8h16z"/>'
        '<path d="M40 24c3 4 3 8 0 12M46 22c4 6 4 12 0 18"/>'
    ),
    "server": (
        '<rect x="10" y="12" width="44" height="16" rx="3"/>'
        '<rect x="10" y="36" width="44" height="16" rx="3"/>'
        '<path d="M18 20h.01M18 44h.01"/>'
        '<path d="M40 20h8M40 44h8"/>'
    ),
    "plug": (
        '<path d="M24 10v14M40 10v14"/>'
        '<path d="M16 24h32v6a16 16 0 0 1-16 16 16 16 0 0 1-16-16z"/>'
        '<path d="M32 46v8"/>'
    ),
    "loop": (
        '<path d="M20 24h20a12 12 0 0 1 0 24H24"/>'
        '<path d="M30 16l-10 8 10 8"/>'
        '<path d="M18 40l6 8 6-8"/>'
    ),
}

DEFAULT_ART = {4: "question", 5: "warning"}

# ---------------------------------------------------------------------------
# Шаблон страницы
# ---------------------------------------------------------------------------

# Класс темы ставит SSI из cookie gh_theme — той же, что читает портал
# (auth-service/templates/theme-init-script.html). Серверная подстановка
# убирает мигание светлым фоном до выполнения скрипта и работает без JS.
#
# Директива сидит ВНУТРИ значения атрибута, а атрибут взят в одинарные
# кавычки. Это не косметика: если SSI вдруг окажется выключен, страница
# отрендерится с бессмысленным классом «dark-themelight-theme» — браузер
# его молча проигнорирует и покажет системную тему. При подстановке же
# самого атрибута (class="…") незакрытый тег вывалил бы кусок разметки
# видимым текстом поверх страницы.
THEME_CLASS = (
    "class='"
    '<!--# if expr="$cookie_gh_theme = /^dark$/" -->dark-theme'
    '<!--# elif expr="$cookie_gh_theme = /^light$/" -->light-theme'
    "<!--# endif -->'"
)

# Фолбэк на localStorage: портал дублирует выбор темы туда, и у части
# пользователей cookie может быть не выставлена (вход по старой сессии).
# Системную тему при отсутствии обоих источников доигрывает CSS.
THEME_SCRIPT = """    <script>
        (function () {
            var root = document.documentElement;
            if (root.className) { return; }
            try {
                var stored = localStorage.getItem('theme');
                if (stored === 'dark' || stored === 'light') {
                    root.className = stored + '-theme';
                }
            } catch (e) { /* приватный режим — остаётся системная тема */ }
        })();
    </script>"""

# Технические поля. Каждое показывается, только если nginx его заполнил:
# при ошибке самого шлюза upstream'а нет, и пустые строки лишь мешают.
DETAILS = """        <dl class="err-meta">
            <dt>Раздел</dt>
            <dd><!--# if expr="$gw_service_key" --><!--# echo var="gw_service_key" -->\
<!--# elif expr="$gw_path_service" --><!--# echo var="gw_path_service" -->\
<!--# else -->шлюз портала<!--# endif --></dd>
<!--# if expr="$upstream_status" -->
            <dt>Ответ раздела</dt>
            <dd><!--# echo var="upstream_status" --></dd>
<!--# endif -->
<!--# if expr="$upstream_http_x_error_code" -->
            <dt>Код ошибки</dt>
            <dd><!--# echo var="upstream_http_x_error_code" --></dd>
<!--# endif -->
<!--# if expr="$upstream_http_x_error_detail" -->
            <dt>Подробности</dt>
            <dd><!--# echo var="upstream_http_x_error_detail" --></dd>
<!--# endif -->
<!--# if expr="$upstream_addr" -->
            <dt>Узел</dt>
            <dd><!--# echo var="upstream_addr" --></dd>
<!--# endif -->
            <dt>Запрос</dt>
            <dd><!--# echo var="request_method" default="" --> <!--# echo var="request_uri" default="—" --></dd>
            <dt>Время</dt>
            <dd><!--# echo var="time_iso8601" default="—" --></dd>
            <dt>Идентификатор</dt>
            <dd><!--# echo var="request_id" default="—" --></dd>
        </dl>"""

PAGE = """<!DOCTYPE html>
<html lang="ru" {theme_class}>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta name="robots" content="noindex, nofollow">
    <title>{code} — {title} · Golden House</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <link rel="stylesheet" href="/_errors/errors.css">
{theme_script}
</head>
<body>
    <main class="err-card">
        <div class="err-art">{art}</div>
        <p class="err-code">{code}</p>
{badge}        <h1 class="err-title">{title}</h1>
        <p class="err-text">{text}</p>
{hint}        <details class="err-details">
            <summary>Технические подробности</summary>
{details}
        </details>
        <div class="err-actions">
            <a class="err-btn" href="/menu">В меню портала</a>
            <button type="button" class="err-btn err-btn--ghost" id="err-back">Назад</button>
        </div>
        <p class="err-foot">Идентификатор запроса помогает найти эту ошибку в логах —
            приложите его к обращению в поддержку.</p>
    </main>
    <script>
        (function () {{
            var back = document.getElementById('err-back');
            // История пуста, когда страницу открыли по прямой ссылке:
            // кнопка «Назад» в этом случае ничего бы не сделала.
            if (!back) {{ return; }}
            if (window.history.length > 1) {{
                back.addEventListener('click', function () {{ window.history.back(); }});
            }} else {{
                back.remove();
            }}
        }})();
    </script>
</body>
</html>
"""

BADGE = '        <p class="err-badge">{label}</p>\n'
HINT = '        <p class="err-hint">{hint}</p>\n'


def render(code, spec):
    art_key = spec.get("art") or DEFAULT_ART[code // 100]
    if art_key not in ART:
        raise KeyError("нет иллюстрации %r для кода %s" % (art_key, code))

    badge = ""
    if spec.get("fun"):
        badge = BADGE.format(label="редкий код")

    hint = ""
    if spec.get("hint"):
        hint = HINT.format(hint=spec["hint"])

    return PAGE.format(
        code=code,
        title=spec["title"],
        text=spec["text"],
        art=_SVG_OPEN + ART[art_key] + "</svg>",
        badge=badge,
        hint=hint,
        theme_class=THEME_CLASS,
        theme_script=THEME_SCRIPT,
        details=DETAILS,
    )


# ---------------------------------------------------------------------------
# Витрина и конфиг предпросмотра
# ---------------------------------------------------------------------------

PREVIEW = """<!DOCTYPE html>
<html lang="ru" {theme_class}>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Страницы ошибок · Golden House</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="stylesheet" href="/_errors/errors.css">
{theme_script}
</head>
<body class="err-preview">
    <main class="err-card">
        <h1 class="err-title">Страницы ошибок шлюза</h1>
        <p class="err-text">Ссылка возвращает настоящий статус-код, а не имитацию:
            nginx отдаёт ровно то, что увидит пользователь. Раздел доступен только
            администраторам.</p>
        <p class="err-text"><b>401</b> и <b>403</b> в списке отсутствуют — они
            обрабатываются редиректами на <code>/login</code> и
            <code>/access-denied</code>.</p>
        <div class="err-preview-grid">
{items}
        </div>
    </main>
</body>
</html>
"""

PREVIEW_ITEM = '            <a href="/errors-preview/{code}"><b>{code}</b>{title}</a>'

PREVIEW_CONF_HEAD = """# ===================================================================
# ПРЕДПРОСМОТР СТРАНИЦ ОШИБОК — ТОЛЬКО ДЛЯ АДМИНИСТРАТОРА
# ===================================================================
# СГЕНЕРИРОВАНО error-pages/generate.py — РУКАМИ НЕ ПРАВИТЬ.
#
# Каждый location возвращает свой статус-код, а error_page из errors.inc
# подменяет ответ настоящей страницей ошибки. Так вёрстку проверяют на живом
# шлюзе, не роняя сервисы.
#
# Доступ закрыт auth_request /verify-admin: неадминистратор получит 401 или
# 403 и уйдёт по обычным редиректам на /login и /access-denied.
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
"""

PREVIEW_CONF_ITEM = """
location = /errors-preview/{code} {{
    auth_request /verify-admin;
    return {code};
}}
"""


def build_preview_page():
    items = "\n".join(
        PREVIEW_ITEM.format(code=code, title=spec["title"])
        for code, spec in sorted(CODES.items())
    )
    return PREVIEW.format(
        items=items,
        theme_class=THEME_CLASS,
        theme_script=THEME_SCRIPT,
    )


def build_preview_conf():
    body = "".join(PREVIEW_CONF_ITEM.format(code=code) for code in sorted(CODES))
    return PREVIEW_CONF_HEAD + body


PAGES_CONF_HEAD = """# ===================================================================
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

"""

PAGES_CONF_ITEM = "error_page {code} /_errors/{code}.html;\n"


def build_pages_conf():
    body = "".join(PAGES_CONF_ITEM.format(code=code) for code in sorted(CODES))
    return PAGES_CONF_HEAD + body


# ---------------------------------------------------------------------------

def expected_files():
    """Что генератор обязан положить в html/errors/. Используется тестами."""
    files = {"%d.html" % code: render(code, spec) for code, spec in CODES.items()}
    files["preview.html"] = build_preview_page()
    files["errors.css"] = (SRC_DIR / "errors.css").read_text(encoding="utf-8")
    return files


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    written = 0
    for name, content in expected_files().items():
        (OUT_DIR / name).write_text(content, encoding="utf-8", newline="\n")
        written += 1

    PAGES_CONF.write_text(build_pages_conf(), encoding="utf-8", newline="\n")
    PREVIEW_CONF.write_text(build_preview_conf(), encoding="utf-8", newline="\n")

    # Старые страницы удаляются: код мог исчезнуть из каталога, а файл — остаться
    # и продолжить отдаваться по error_page из чужой ветки конфига.
    known = set(expected_files())
    for stale in OUT_DIR.iterdir():
        if stale.is_file() and stale.name not in known:
            stale.unlink()
            print("удалено лишнее: %s" % stale.name)

    print("страниц: %d, файлов: %d -> %s" % (len(CODES), written, OUT_DIR))
    print("карта error_page -> %s" % PAGES_CONF)
    print("конфиг предпросмотра -> %s" % PREVIEW_CONF)


if __name__ == "__main__":
    main()
