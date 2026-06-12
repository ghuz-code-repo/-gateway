#!/bin/bash
# watchdog.sh — авто-карантин по бинарным индикаторам компрометации (Plan D, ступень 2).
#
# Бинарный индикатор = событие, которое в норме НЕ происходит никогда,
# поэтому реакция автоматическая и необратимая (в отличие от поведенческих
# порогов guard'а в notification-service, где авто-ответ только обратимый).
#
# Индикаторы:
#   1. Контейнер НЕ из allowlist обратился к docker-socket-proxy
#      (источник: haproxy-логи gateway-docker-proxy, клиентский IP в начале строки)
#   2. Срабатывание ханипота в notification-service
#      (источник: строка "GUARD TRIPWIRE: ip=..." в его логах)
#
# Реакция:
#   - бизнес-сервис      -> scripts/quarantine.sh (улики -> отключение сетей -> pause) + алерт
#   - core-инфраструктура (WATCHDOG_PROTECTED) -> ТОЛЬКО алерт "нужен ручной карантин".
#     Авто-pause nginx/auth/mongo/notification = готовый DoS-рычаг для атакующего
#     и полный отказ платформы при ложном срабатывании — поэтому только вручную.
#
# Контейнер watchdog держит настоящий /var/run/docker.sock — это точка принуждения.
# У него нет ни одного слушающего порта (нулевая входящая поверхность атаки),
# наружу он ходит только в notification-service за алертами.

set -uo pipefail

# --- Конфигурация (env) ---
PROXY_CONTAINER="${WATCHDOG_PROXY_CONTAINER:-gateway-docker-proxy}"
# Compose-сервисы, которым разрешён доступ к docker-socket-proxy
PROXY_ALLOWED="${WATCHDOG_PROXY_ALLOWED:-auth-service,dozzle}"
# Core-инфраструктура: никогда не карантинится автоматически (только алерт)
PROTECTED="${WATCHDOG_PROTECTED:-nginx,auth-service,mongo,docker-socket-proxy,dozzle,monitoring-service,notification-service,notification-postgres,guard-watchdog}"
# Compose-сервис, чьи логи слушаем на предмет TRIPWIRE-маркеров
TRIPWIRE_SERVICE="${WATCHDOG_TRIPWIRE_SERVICE:-notification-service}"
# true => только алерты, без реального карантина (обкатка)
DRY_RUN="${WATCHDOG_DRY_RUN:-false}"
# Куда слать алерты
NOTIFY_URL="${WATCHDOG_NOTIFY_URL:-http://notification-service:80/api/v1/security/alert}"
NOTIFY_API_KEY="${WATCHDOG_API_KEY:-}"
# Повторный инцидент по тому же контейнеру не обрабатываем чаще (сек)
INCIDENT_COOLDOWN="${WATCHDOG_INCIDENT_COOLDOWN:-900}"
QUARANTINE_SCRIPT="${WATCHDOG_QUARANTINE_SCRIPT:-/scripts/quarantine.sh}"

STATE_DIR=/run/watchdog
mkdir -p "$STATE_DIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

in_list() { # in_list <item> <comma-separated-list>
    local item="$1" IFS=','
    for x in $2; do [ "$item" = "$x" ] && return 0; done
    return 1
}

# IP (вида 172.18.0.5) -> имя контейнера; смотрит все docker-сети
resolve_ip() {
    local ip="$1"
    # shellcheck disable=SC2046
    docker network inspect $(docker network ls -q) --format '{{json .}}' 2>/dev/null \
        | jq -r --arg ip "$ip" \
            '.Containers // {} | to_entries[] | select(.value.IPv4Address | startswith($ip + "/")) | .value.Name' \
        | head -n1
}

compose_service_of() { # имя compose-сервиса контейнера (или само имя контейнера)
    local svc
    svc=$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.service" }}' "$1" 2>/dev/null)
    echo "${svc:-$1}"
}

container_by_service() {
    docker ps --filter "label=com.docker.compose.service=$1" --format '{{.Names}}' | head -n1
}

alert() { # alert <subject> <content>
    local subject="$1" content="$2"
    log "ALERT: $subject"
    if [ -z "$NOTIFY_API_KEY" ]; then
        log "WATCHDOG_API_KEY не задан — алерт только в лог: $content"
        return
    fi
    jq -n --arg s "$subject" --arg c "$content" '{subject: $s, content: $c}' \
        | curl -sS -m 10 -X POST "$NOTIFY_URL" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: $NOTIFY_API_KEY" \
            -d @- >/dev/null \
        || log "Не удалось отправить алерт в notification-service (см. лог выше)"
}

# Кулдаун инцидентов через файлы — состояние общее для обоих мониторов
on_cooldown() {
    local key="$1" f="$STATE_DIR/incident-$1" now last
    now=$(date +%s)
    last=$(cat "$f" 2>/dev/null || echo 0)
    if [ $((now - last)) -lt "$INCIDENT_COOLDOWN" ]; then
        return 0
    fi
    echo "$now" > "$f"
    return 1
}

handle_incident() { # handle_incident <container> <reason>
    local container="$1" reason="$2" svc
    svc=$(compose_service_of "$container")

    on_cooldown "$container" && return

    if in_list "$svc" "$PROTECTED" || in_list "$container" "$PROTECTED"; then
        alert "🚨 ИНДИКАТОР КОМПРОМЕТАЦИИ: $container — НУЖЕН РУЧНОЙ КАРАНТИН" \
"Контейнер: $container (сервис: $svc)
Индикатор: $reason

Это core-инфраструктура — авто-карантин отключён (риск полного отказа платформы).
Проверьте НЕМЕДЛЕННО:
  docker logs --tail 200 $container
Если компрометация подтверждена:
  ./scripts/quarantine.sh $container"
        return
    fi

    if [ "$DRY_RUN" = "true" ]; then
        alert "🧪 [DRY-RUN] Авто-карантин НЕ выполнен: $container" \
"Контейнер: $container (сервис: $svc)
Индикатор: $reason

WATCHDOG_DRY_RUN=true — карантин не выполнялся. Для боевого режима уберите флаг."
        return
    fi

    if [ "$(docker inspect -f '{{.State.Paused}}' "$container" 2>/dev/null)" = "true" ]; then
        log "$container уже в карантине (paused) — пропуск"
        return
    fi

    log "QUARANTINE: $container — $reason"
    local out rc=0
    out=$("$QUARANTINE_SCRIPT" "$container" 2>&1) || rc=$?

    if [ "$rc" -eq 0 ]; then
        alert "🔒 АВТО-КАРАНТИН: контейнер $container изолирован" \
"Контейнер: $container (сервис: $svc)
Индикатор: $reason

Выполнено автоматически: сбор улик -> отключение от всех сетей -> docker pause.
Контейнер НЕ удалён, память сохранена для форензики.

$out

Восстановление (после расследования):
  ./scripts/quarantine.sh --release $container
  затем в директории сервиса: docker compose up -d --force-recreate"
    else
        alert "❌ АВТО-КАРАНТИН НЕ УДАЛСЯ: $container — вмешайтесь вручную" \
"Контейнер: $container (сервис: $svc)
Индикатор: $reason

quarantine.sh завершился с ошибкой (код $rc):
$out

Выполните вручную: ./scripts/quarantine.sh $container"
    fi
}

# --- Монитор 1: несанкционированный доступ к docker-socket-proxy ---
monitor_proxy() {
    while true; do
        if ! docker inspect "$PROXY_CONTAINER" >/dev/null 2>&1; then
            log "Контейнер $PROXY_CONTAINER не найден — повтор через 30с"
            sleep 30
            continue
        fi
        log "Слежу за логами $PROXY_CONTAINER (allowlist: $PROXY_ALLOWED)"
        docker logs -f --tail 0 "$PROXY_CONTAINER" 2>&1 | while IFS= read -r line; do
            # haproxy httplog (format raw): строка начинается с "<client_ip>:<port> "
            [[ $line =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):[0-9]+[[:space:]] ]] || continue
            ip="${BASH_REMATCH[1]}"
            [ "$ip" = "127.0.0.1" ] && continue  # собственный healthcheck proxy

            # Кэш разрешённых IP, чтобы не дёргать docker на каждый легитимный запрос
            now=$(date +%s)
            if [ "${ALLOW_CACHE[$ip]:-0}" -gt "$now" ] 2>/dev/null; then
                continue
            fi

            container=$(resolve_ip "$ip")
            if [ -z "$container" ]; then
                on_cooldown "unknown-ip-$ip" && continue
                alert "⚠️ Неопознанный клиент docker-socket-proxy: $ip" \
"К docker-socket-proxy обратился IP $ip, который не удалось сопоставить ни с одним контейнером.
Строка лога: $line
Проверьте: docker network inspect service_network"
                continue
            fi

            svc=$(compose_service_of "$container")
            if in_list "$svc" "$PROXY_ALLOWED" || in_list "$container" "$PROXY_ALLOWED"; then
                ALLOW_CACHE[$ip]=$((now + 60))
                continue
            fi

            handle_incident "$container" \
                "обращение к docker-socket-proxy с IP $ip — сервису '$svc' доступ к Docker API не положен (allowlist: $PROXY_ALLOWED)"
        done
        log "Поток логов $PROXY_CONTAINER оборвался — переподключение через 5с"
        sleep 5
    done
}

# --- Монитор 2: ханипот-маркеры в логах notification-service ---
monitor_tripwire() {
    while true; do
        local target
        target=$(container_by_service "$TRIPWIRE_SERVICE")
        if [ -z "$target" ]; then
            log "Контейнер сервиса $TRIPWIRE_SERVICE не найден — повтор через 30с"
            sleep 30
            continue
        fi
        log "Слежу за TRIPWIRE-маркерами в логах $target"
        docker logs -f --tail 0 "$target" 2>&1 | while IFS= read -r line; do
            [[ $line == *"GUARD TRIPWIRE:"* ]] || continue
            [[ $line =~ ip=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]] || continue
            ip="${BASH_REMATCH[1]}"

            container=$(resolve_ip "$ip")
            if [ -z "$container" ]; then
                on_cooldown "unknown-ip-$ip" && continue
                alert "⚠️ TRIPWIRE от неопознанного IP: $ip" \
"Ханипот в $TRIPWIRE_SERVICE сработал от IP $ip, контейнер не определён.
Строка лога: $line"
                continue
            fi

            handle_incident "$container" \
                "срабатывание ханипота в $TRIPWIRE_SERVICE с IP $ip ($line)"
        done
        log "Поток логов $target оборвался — переподключение через 5с"
        sleep 5
    done
}

log "🛡️ Guard watchdog запущен (dry_run=$DRY_RUN, protected: $PROTECTED)"
declare -A ALLOW_CACHE

monitor_proxy &
monitor_tripwire &
wait
