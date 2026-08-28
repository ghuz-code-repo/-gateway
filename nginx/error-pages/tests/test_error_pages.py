# -*- coding: utf-8 -*-
"""Тесты страниц ошибок шлюза.

Сети и докера не требуют — читают файлы репозитория. Запуск:

    cd '!gateway/nginx/error-pages' && pytest

Что проверяется:
  * файлы в html/errors/ совпадают с выводом генератора (руками не правили);
  * карта error_page покрывает ровно каталог кодов;
  * 401 и 403 остались редиректами и своей страницы не получили;
  * страницы самодостаточны: ни одной внешней загрузки (прод без CDN);
  * SSI не экранирует значения только там, где это безопасно;
  * конфиг шлюза подключает всё, что страницам нужно.
"""

import re
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SRC_DIR))

import generate  # noqa: E402
from codes import CODES, REDIRECT_CODES  # noqa: E402

NGINX_DIR = SRC_DIR.parent
OUT_DIR = NGINX_DIR / "html" / "errors"
CONF_DIR = NGINX_DIR / "conf"

PAGES_INC = CONF_DIR / "errors-pages.inc"
PREVIEW_INC = CONF_DIR / "errors-preview.inc"
ERRORS_INC = CONF_DIR / "errors.inc"
GATEWAY_INC = CONF_DIR / "gateway.inc"
NGINX_CONF = CONF_DIR / "nginx.conf"

ALL_CODES = sorted(CODES)


def read(path):
    return path.read_text(encoding="utf-8")


def page(code):
    return read(OUT_DIR / ("%d.html" % code))


# ---------------------------------------------------------------------------
# Генерация
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(generate.expected_files()))
def test_файл_совпадает_с_выводом_генератора(name):
    """Правки вносят в codes.py и перезапускают generate.py, а не наоборот."""
    path = OUT_DIR / name
    assert path.exists(), "нет %s — запустите generate.py" % name
    assert read(path) == generate.expected_files()[name], (
        "%s разошёлся с генератором: запустите error-pages/generate.py" % name
    )


def test_лишних_файлов_в_каталоге_нет():
    lying = {p.name for p in OUT_DIR.iterdir() if p.is_file()}
    assert lying == set(generate.expected_files())


def test_карта_error_page_совпадает_с_каталогом():
    listed = [int(m) for m in re.findall(r"error_page (\d{3}) ", read(PAGES_INC))]
    assert sorted(listed) == ALL_CODES
    assert len(listed) == len(set(listed)), "код указан дважды"


def test_карта_ссылается_на_существующие_файлы():
    for code, name in re.findall(r"error_page (\d{3}) /_errors/(\S+);", read(PAGES_INC)):
        assert (OUT_DIR / name).exists()
        assert name == "%s.html" % code


def test_конфиг_предпросмотра_покрывает_все_коды():
    body = read(PREVIEW_INC)
    for code in ALL_CODES:
        assert "location = /errors-preview/%d {" % code in body
    # Витрина обязана быть закрыта: она позволяет дёргать произвольные коды.
    assert body.count("auth_request /verify-admin;") == len(ALL_CODES) + 1


# ---------------------------------------------------------------------------
# Коды-редиректы
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code", REDIRECT_CODES)
def test_редиректные_коды_не_получили_страницу(code):
    """401 и 403 — часть контракта авторизации, страницей их не подменяют."""
    assert code not in CODES
    assert not (OUT_DIR / ("%d.html" % code)).exists()
    assert "error_page %d " % code not in read(PAGES_INC)


def test_редиректы_401_и_403_на_месте():
    body = read(GATEWAY_INC)
    assert "error_page 401 = @error401;" in body
    assert "return 302 /login?redirect=$request_uri;" in body
    assert "error_page 403 = @error403;" in body
    assert "return 302 /access-denied?service=$request_uri;" in body


# ---------------------------------------------------------------------------
# Самодостаточность страниц
# ---------------------------------------------------------------------------

EXTERNAL = re.compile(r"""(?:src|href)\s*=\s*["'](?:https?:)?//""")


@pytest.mark.parametrize("code", ALL_CODES)
def test_страница_без_внешних_загрузок(code):
    """Прод в изолированной сети: любая внешняя ссылка — пустой квадрат."""
    assert not EXTERNAL.search(page(code))


@pytest.mark.parametrize("code", ALL_CODES)
def test_страница_подключает_только_свой_css(code):
    body = page(code)
    links = re.findall(r'<link[^>]+rel="stylesheet"[^>]+href="([^"]+)"', body)
    assert links == ["/_errors/errors.css"]


@pytest.mark.parametrize("code", ALL_CODES)
def test_страница_показывает_код_и_заголовок(code):
    body = page(code)
    assert '<p class="err-code">%d</p>' % code in body
    assert "<title>%d — %s · Golden House</title>" % (code, CODES[code]["title"]) in body
    assert body.count("<h1") == 1
    assert body.rstrip().endswith("</html>")


@pytest.mark.parametrize("code", ALL_CODES)
def test_страница_знает_тему_портала(code):
    """Тема берётся из той же cookie, что и на остальных страницах портала."""
    body = page(code)
    assert '$cookie_gh_theme = /^dark$/' in body
    assert '$cookie_gh_theme = /^light$/' in body
    assert "localStorage.getItem('theme')" in body


@pytest.mark.parametrize("code", ALL_CODES)
def test_страница_называет_виновника_и_запрос(code):
    body = page(code)
    assert 'echo var="gw_service_key"' in body
    assert 'echo var="gw_path_service"' in body
    assert 'echo var="upstream_status"' in body
    assert 'echo var="request_id"' in body
    # Детали от сервиса приходят заголовками: тело ответа перехват выбрасывает.
    assert 'echo var="upstream_http_x_error_detail"' in body


@pytest.mark.parametrize("code", ALL_CODES)
def test_ssi_не_отключает_экранирование(code):
    """encoding="none" вернул бы $request_uri в разметку сырым — это XSS."""
    assert 'encoding="none"' not in page(code)


# ---------------------------------------------------------------------------
# Обвязка nginx
# ---------------------------------------------------------------------------

def test_errors_inc_включает_перехват_и_страницы():
    body = read(ERRORS_INC)
    assert "proxy_intercept_errors on;" in body
    assert "include /etc/nginx/conf.d/errors-pages.inc;" in body
    assert "include /etc/nginx/conf.d/errors-preview.inc;" in body
    # Раздача только по внутреннему редиректу.
    assert "internal;" in body
    assert "ssi on;" in body
    # Собственные заголовки безопасности: add_header в location отменяет
    # наследование серверных.
    assert "add_header Content-Security-Policy" in body
    assert "add_header X-Frame-Options" in body


def test_gateway_inc_подключает_страницы_ошибок():
    body = read(GATEWAY_INC)
    assert "include /etc/nginx/conf.d/errors.inc;" in body
    assert 'set $gw_service_key "";' in body
    assert "/404.html" not in body, "остался старый обработчик 404"


# Блоки, где HTML-страница вместо ответа сломает вызывающий код: ассеты,
# служебные проверки прав и вебсокеты Dozzle. Ключ — начало location.
NO_INTERCEPT = (
    "= /vite.svg",
    "/static/",
    "/data/",
    "/avatar/",
    "/logs ",
    "~ ^/services/([^/]+)/logs",
    "= /verify",
    "= /verify-admin",
    "= /verify-logs-auth",
    "= /verify-service-logs-auth",
    # JSON-эндпоинты портала: их читает JS, а не человек.
    "^~ /api/",
    "/check-user-exists",
)


def gateway_blocks():
    """Разбирает gateway.inc на пары (заголовок location, тело блока)."""
    body = read(GATEWAY_INC)
    for match in re.finditer(r"\n    location ([^\n{]*)\{", body):
        start = match.end()
        depth = 1
        i = start
        while depth and i < len(body):
            if body[i] == "{":
                depth += 1
            elif body[i] == "}":
                depth -= 1
            i += 1
        yield match.group(1).strip(), body[start:i]


@pytest.mark.parametrize("prefix", NO_INTERCEPT)
def test_ассеты_и_проверки_прав_не_перехватываются(prefix):
    """HTML-страница вместо ассета или ответа auth_request ломает клиента."""
    blocks = [b for head, b in gateway_blocks() if head.startswith(prefix.strip())]
    assert blocks, "нет блока location %s" % prefix
    for block in blocks:
        assert "proxy_intercept_errors off;" in block


def test_заблокированные_ассеты_отдают_пустое_тело():
    """return 404 без тела ушёл бы в error_page и вернул страницу на 6 КБ."""
    body = read(GATEWAY_INC)
    assert "return 404;" not in body
    assert "error_page 404 = @asset_not_found;" in body
    assert "location @asset_not_found {" in read(ERRORS_INC)


def test_nginx_conf_определяет_раздел_по_пути():
    body = read(NGINX_CONF)
    assert "map $request_uri $gw_path_service {" in body
    # Собственные разделы шлюза сервисами не считаются.
    assert "login|logout|menu" in body


def test_шаблон_конфига_сервиса_передаёт_ключ():
    """Имя сервиса на странице ошибки берётся из сгенерированного конфига."""
    tmpl = (NGINX_DIR.parent / "auth-service" / "routes" / "nginx_config.go").read_text(
        encoding="utf-8"
    )
    assert "set $gw_service_key {{.ServiceKey}};" in tmpl
    set_at = tmpl.index("set $gw_service_key {{.ServiceKey}};")
    rewrite_at = tmpl.index("rewrite ^{{.ExternalPrefix}}/(.*) /$1 break;")
    assert set_at < rewrite_at, "rewrite ... break обрывает фазу rewrite: set не выполнится"
    assert tmpl.count("proxy_intercept_errors off;") == 2, "статика и health"
