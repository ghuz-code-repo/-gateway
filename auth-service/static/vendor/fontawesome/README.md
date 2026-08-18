# Font Awesome Free 6.0.0 (vendored)

Прод в изолированной сети — CDN оттуда не виден, поэтому шрифты и стили
лежат локально. Шаблоны подключают `/static/vendor/fontawesome/css/all.min.css`,
ссылок на `cdnjs.cloudflare.com` в сервисе быть не должно.

Источник: https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/
Лицензия: https://fontawesome.com/license/free
  - иконки (SVG/шрифты) — CC BY 4.0
  - код (CSS) — MIT

## Отличия от оригинала

Из `css/all.min.css` удалены `src`-фолбэки на `.ttf` (10 штук): woff2
поддерживают все браузеры с 2016 года, а лишние файлы в каталоге привели бы
к 404 при попытке фолбэка. Больше файл ничем не отличается — версия та же.

## Версия

6.0.0 выбрана намеренно: ровно она стояла на CDN до вендоринга. Имена иконок
для карточек сервисов админ задаёт в БД (`fa-{{ .service.Icon }}` в
`menu.html` и `admin_service_form.html`), поэтому любая смена версии — это
риск, что уже заведённая иконка перестанет резолвиться. Обновлять только
вверх (6.x — надмножество) и после проверки списка иконок сервисов.

## Обновление

    BASE=https://cdnjs.cloudflare.com/ajax/libs/font-awesome/<версия>
    curl -o css/all.min.css $BASE/css/all.min.css
    for f in fa-solid-900 fa-brands-400 fa-regular-400 fa-v4compatibility; do
        curl -o webfonts/$f.woff2 $BASE/webfonts/$f.woff2
    done

затем снова убрать ttf-фолбэки:

    sed -i 's|,url(\.\./webfonts/[^)]*\.ttf) format("truetype")||g' css/all.min.css
