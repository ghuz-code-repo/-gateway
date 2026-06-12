# Guard watchdog — авто-карантин по бинарным индикаторам компрометации.
# Минимальный образ: docker CLI + bash/jq/curl, ни одного слушающего порта.
FROM docker:27-cli

RUN apk add --no-cache bash curl jq coreutils

COPY watchdog.sh /usr/local/bin/watchdog.sh
# Гарантируем LF и бит исполнения вне зависимости от ОС, где собирали
RUN sed -i 's/\r$//' /usr/local/bin/watchdog.sh && chmod +x /usr/local/bin/watchdog.sh

ENTRYPOINT ["/usr/local/bin/watchdog.sh"]
