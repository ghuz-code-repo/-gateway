/* ═══ МОБИЛЬНЫЕ ДОВОДКИ КЛИЕНТСКОЙ ЧАСТИ ПОРТАЛА ═══════════════════════════
   Чинит то, что чистым CSS не закрывается:

   1. Широкие таблицы оборачиваются в горизонтальный скролл-контейнер —
      иначе на 360px они либо выезжают за экран, либо обрезаются
      overflow-x: hidden у .container.
   2. Активная вкладка подкручивается в видимую часть горизонтальной ленты.
   3. На мобильном режется плотность фона из частиц: line_linked считается
      за O(n²) на каждый кадр и роняет скролл на средних телефонах.
   4. Утилита блокировки скролла страницы под оверлеями (window.ghScrollLock).

   Подключается в <head> без defer, но вся работа — по DOMContentLoaded.
   Ничего не ломает, если элемента нет: каждый шаг проверяет наличие.
   ────────────────────────────────────────────────────────────────────── */
(function () {
    'use strict';

    var MOBILE_QUERY = '(max-width: 768px)';

    function isMobile() {
        return window.matchMedia && window.matchMedia(MOBILE_QUERY).matches;
    }

    /* ── 1. Блокировка скролла под оверлеями ──────────────────────────────
       Через класс, а не через инлайновый style.overflow: инлайн проигрывает
       !important-правилам легаси, и блокировка местами не срабатывала.
       Счётчик нужен, потому что модалка может открыться поверх меню. */
    var lockDepth = 0;

    function lockScroll() {
        lockDepth += 1;
        if (lockDepth === 1) {
            document.documentElement.classList.add('gh-scroll-lock');
            document.body.classList.add('gh-scroll-lock');
        }
    }

    function unlockScroll() {
        lockDepth = Math.max(0, lockDepth - 1);
        if (lockDepth === 0) {
            document.documentElement.classList.remove('gh-scroll-lock');
            document.body.classList.remove('gh-scroll-lock');
        }
    }

    function resetScrollLock() {
        lockDepth = 0;
        document.documentElement.classList.remove('gh-scroll-lock');
        document.body.classList.remove('gh-scroll-lock');
    }

    window.ghScrollLock = {
        lock: lockScroll,
        unlock: unlockScroll,
        reset: resetScrollLock
    };

    /* ── 2. Обёртка таблиц в горизонтальный скролл ──────────────────────── */
    function wrapTables(root) {
        var scope = root && root.querySelectorAll ? root : document;
        var tables = scope.querySelectorAll('table');

        for (var i = 0; i < tables.length; i++) {
            var table = tables[i];
            var parent = table.parentNode;

            if (!parent || parent.classList && parent.classList.contains('gh-table-scroll')) {
                continue;
            }
            // Таблицы внутри модалок и уже прокручиваемых блоков не трогаем:
            // двойной скролл-контейнер хуже, чем один.
            if (table.closest && table.closest('.gh-table-scroll')) {
                continue;
            }

            var wrapper = document.createElement('div');
            wrapper.className = 'gh-table-scroll';
            // tabindex делает контейнер доступным для скролла с клавиатуры.
            wrapper.setAttribute('tabindex', '0');
            wrapper.setAttribute('role', 'region');
            wrapper.setAttribute('aria-label', 'Таблица, прокручивается по горизонтали');
            parent.insertBefore(wrapper, table);
            wrapper.appendChild(table);
        }
    }

    /* ── 3. Активная вкладка — в видимую часть ленты ──────────────────────
       Лента вкладок скроллится по горизонтали; после перезагрузки страницы
       или переключения активная вкладка может оказаться за кадром. */
    function revealActiveTab(nav) {
        var active = nav.querySelector('.active');
        if (!active || typeof active.getBoundingClientRect !== 'function') {
            return;
        }

        var navBox = nav.getBoundingClientRect();
        var tabBox = active.getBoundingClientRect();

        if (tabBox.left < navBox.left) {
            nav.scrollLeft -= (navBox.left - tabBox.left) + 12;
        } else if (tabBox.right > navBox.right) {
            nav.scrollLeft += (tabBox.right - navBox.right) + 12;
        }
    }

    function initTabStrips() {
        var navs = document.querySelectorAll('.tabs-nav');

        for (var i = 0; i < navs.length; i++) {
            (function (nav) {
                revealActiveTab(nav);
                nav.addEventListener('click', function () {
                    // Класс .active переставляет чужой обработчик — ждём его.
                    window.setTimeout(function () {
                        revealActiveTab(nav);
                    }, 0);
                });
            })(navs[i]);
        }
    }

    /* ── 4. Разгрузка фона из частиц ──────────────────────────────────────
       particles.js пересчитывает связи между частицами попарно каждый кадр.
       120 частиц с line_linked на телефоне — это дёргающийся скролл поверх
       fixed-канваса. Убавляем количество и радиус связей, интерактивность
       на тач-устройстве всё равно не используется. */
    function tameParticles() {
        if (!isMobile() || !window.pJSDom || !window.pJSDom.length) {
            return;
        }

        for (var i = 0; i < window.pJSDom.length; i++) {
            try {
                var pJS = window.pJSDom[i].pJS;
                if (!pJS || !pJS.particles || !pJS.particles.array) {
                    continue;
                }

                var target = Math.max(18, Math.round(pJS.particles.array.length * 0.3));
                if (pJS.particles.array.length > target) {
                    pJS.particles.array.splice(target);
                }
                pJS.particles.number.value = target;
                pJS.particles.line_linked.distance = 110;

                if (pJS.interactivity && pJS.interactivity.events) {
                    if (pJS.interactivity.events.onhover) {
                        pJS.interactivity.events.onhover.enable = false;
                    }
                    if (pJS.interactivity.events.onclick) {
                        pJS.interactivity.events.onclick.enable = false;
                    }
                }
            } catch (e) {
                // Фон — украшение: молча оставляем как есть.
            }
        }
    }

    /* ── 5. Цвет системной строки под текущую тему ────────────────────────
       Тема выбирается пользователем через cookie, а не системной настройкой,
       поэтому <meta name="theme-color" media="(prefers-color-scheme…)"> не
       подходит — цвет надо ставить по фактически применённому классу. */
    var THEME_COLORS = {
        light: '#ffffff',
        dark: '#1e1e1e'
    };

    function syncThemeColor() {
        var meta = document.querySelector('meta[name="theme-color"]');
        if (!meta) {
            return;
        }
        var isDark = document.documentElement.classList.contains('dark-theme');
        meta.setAttribute('content', isDark ? THEME_COLORS.dark : THEME_COLORS.light);
    }

    function watchThemeColor() {
        syncThemeColor();

        if (!window.MutationObserver) {
            return;
        }
        // Переключатель темы меняет класс на <html> — реагируем на это.
        new MutationObserver(syncThemeColor).observe(document.documentElement, {
            attributes: true,
            attributeFilter: ['class']
        });
    }

    /* ── 6. Запуск ───────────────────────────────────────────────────────── */
    function init() {
        wrapTables(document);
        initTabStrips();
        tameParticles();
        watchThemeColor();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Таблицы и вкладки часть страниц дорисовывает из JS уже после
    // DOMContentLoaded — добираем их отложенным проходом.
    window.addEventListener('load', function () {
        wrapTables(document);
        tameParticles();
    });

    var rescanTimer = null;

    function scheduleRescan() {
        if (rescanTimer) {
            window.clearTimeout(rescanTimer);
        }
        rescanTimer = window.setTimeout(function () {
            rescanTimer = null;
            wrapTables(document);
        }, 250);
    }

    if (window.MutationObserver) {
        document.addEventListener('DOMContentLoaded', function () {
            var observer = new MutationObserver(function (records) {
                for (var i = 0; i < records.length; i++) {
                    if (records[i].addedNodes && records[i].addedNodes.length) {
                        scheduleRescan();
                        return;
                    }
                }
            });
            observer.observe(document.body, { childList: true, subtree: true });
        });
    }
})();
