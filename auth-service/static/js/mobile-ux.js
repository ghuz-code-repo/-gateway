/* ═══ МОБИЛЬНЫЕ ДОВОДКИ КЛИЕНТСКОЙ ЧАСТИ ПОРТАЛА ═══════════════════════════
   Чинит то, что чистым CSS не закрывается:

   1. Широкие таблицы оборачиваются в горизонтальный скролл-контейнер —
      иначе на 360px они либо выезжают за экран, либо обрезаются
      overflow-x: hidden у .container.
   2. Активная вкладка подкручивается в видимую часть горизонтальной ленты.
   3. На мобильном режется плотность фона из частиц: line_linked считается
      за O(n²) на каждый кадр и роняет скролл на средних телефонах.
   4. Утилита блокировки скролла страницы под оверлеями (window.ghScrollLock).
   5. Вкладке «Логи» считается высота, чтобы iframe со сторонним просмотрщиком
      доходил ровно до нижнего края экрана.

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

    /* ── 3a. Высота вкладки «Логи» ────────────────────────────────────────
       Во вкладке логов лежит iframe со сторонним просмотрщиком. Он должен
       доходить ровно до нижнего края экрана, а сколько занято сверху
       (шапка, заголовок, флеш-сообщения, лента вкладок) в CSS не выразить:
       высота зависит от контента. Поэтому меряем и отдаём в CSS-переменную
       --gh-logs-h, а правило в mobile.css её использует. */
    /* Два разных порога, их нельзя путать:
       MIN_AVAIL — минимум доступной высоты, когда сверху занято почти всё
       (альбомная ориентация): лучше пусть страница прокрутится, чем полоска
       логов в 90px;
       MIN_FIT — минимум при подгонке под короткое содержимое, чтобы страница
       ошибки не превращалась в узкую щель. */
    var LOGS_MIN_AVAIL = 260;
    var LOGS_MIN_FIT = 120;

    /* Высота содержимого внутри фрейма. Просмотрщик лежит на том же хосте
       (`/services/<key>/logs/`), поэтому документ доступен. Если вдруг нет —
       возвращаем null, и фрейм остаётся во всю доступную высоту. */
    function logsContentHeight(frame) {
        try {
            var doc = frame.contentDocument;
            if (!doc || !doc.body) {
                return null;
            }
            // Именно body: у короткой страницы documentElement.scrollHeight
            // равен высоте окна фрейма, а не содержимого, и подгонка
            // «подтверждала» бы любую выставленную высоту.
            return Math.max(
                doc.body.scrollHeight,
                Math.round(doc.body.getBoundingClientRect().height)
            );
        } catch (e) {
            return null;
        }
    }

    /* Сколько места от верха вкладки до нижнего края экрана. */
    function logsAvailableHeight(tab) {
        // Неактивная вкладка скрыта и размеров не имеет — тогда отсчитываем
        // от низа ленты вкладок, сразу под которой она и появится.
        var anchorEl = tab.classList.contains('active') ? tab : document.querySelector('.tabs-nav');
        if (!anchorEl) {
            return null;
        }
        var box = anchorEl.getBoundingClientRect();
        // Координата верха блока в документе — не зависит от текущей прокрутки.
        var topInDoc = (anchorEl === tab ? box.top : box.bottom) + window.pageYOffset;
        var height = Math.round(window.innerHeight - topInDoc);
        return isFinite(height) ? Math.max(height, LOGS_MIN_AVAIL) : null;
    }

    function sizeLogsFrame() {
        var tab = document.getElementById('logs');
        if (!tab) {
            return;
        }

        var root = document.documentElement;
        if (!isMobile()) {
            // На десктопе работает штатная одноэкранная раскладка.
            root.style.removeProperty('--gh-logs-h');
            tab.classList.remove('gh-logs-flush');
            return;
        }

        var avail = logsAvailableHeight(tab);
        if (avail === null) {
            return;
        }

        // Сначала разворачиваем на всю доступную высоту и только потом меряем
        // содержимое. Порядок важен: просмотрщик обычно тянется на 100% своего
        // окна, и если мерить его в уже сжатом фрейме, он «подтвердит» любую
        // высоту — получится схлопывание с каждым проходом.
        root.style.setProperty('--gh-logs-h', avail + 'px');
        tab.classList.add('gh-logs-flush');

        var frame = tab.querySelector('.logs-iframe');
        if (!frame) {
            return;
        }

        // Чтение scrollHeight ниже само вызывает пересчёт раскладки, поэтому
        // значение уже учитывает выставленную высоту.
        var inner = logsContentHeight(frame);
        if (inner === null || inner <= 0) {
            return;
        }

        // Пустой список или короткая страница ошибки не должны разворачиваться
        // в чёрный прямоугольник на пол-экрана: подгоняем фрейм по содержимому.
        var fit = Math.min(avail, Math.max(LOGS_MIN_FIT, inner + 2));
        root.style.setProperty('--gh-logs-h', fit + 'px');
        tab.classList.toggle('gh-logs-flush', fit >= avail - 2);
    }

    var logsResizeTimer = null;

    function scheduleLogsResize() {
        if (logsResizeTimer) {
            window.clearTimeout(logsResizeTimer);
        }
        logsResizeTimer = window.setTimeout(function () {
            logsResizeTimer = null;
            sizeLogsFrame();
        }, 120);
    }

    function initLogsFrame() {
        var tab = document.getElementById('logs');
        if (!tab) {
            return;
        }
        sizeLogsFrame();

        // Фрейм помечен loading="lazy" и грузится уже после открытия вкладки —
        // до этого мерить внутри нечего.
        var frame = tab.querySelector('.logs-iframe');
        if (frame) {
            frame.addEventListener('load', sizeLogsFrame);
        }

        // Переключение вкладок меняет высоту контента над фреймом.
        document.addEventListener('click', function (event) {
            if (event.target && event.target.closest && event.target.closest('.tabs-nav')) {
                window.setTimeout(sizeLogsFrame, 0);
            }
        });
        window.addEventListener('resize', scheduleLogsResize);
        window.addEventListener('orientationchange', scheduleLogsResize);

        // Просмотрщик дорисовывает интерфейс асинхронно — добираем несколько
        // отложенных проходов, дальше высота уже не меняется.
        [500, 2000, 5000].forEach(function (delay) {
            window.setTimeout(sizeLogsFrame, delay);
        });
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
        initLogsFrame();
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
        // К моменту load шрифты и иконки уже разложены — высота над фреймом
        // окончательная.
        sizeLogsFrame();
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
