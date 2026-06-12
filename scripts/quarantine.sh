#!/bin/bash
# quarantine.sh — ручной карантин скомпрометированного контейнера.
#
# Что делает:
#   1. Сохраняет логи и сетевую конфигурацию контейнера для расследования
#   2. Отключает контейнер от ВСЕХ docker-сетей (полная сетевая изоляция)
#   3. Приостанавливает процессы контейнера (docker pause) — состояние памяти
#      сохраняется для форензики, но код больше не исполняется
#
# Контейнер НЕ удаляется и НЕ останавливается — улики сохраняются.
#
# Использование:
#   ./quarantine.sh <container_name>          # карантин
#   ./quarantine.sh --release <container_name> # снять карантин (unpause; сети
#                                                восстанавливаются перезапуском
#                                                compose: docker compose up -d)
#
# Запускать на хосте (нужны полные права на docker).

set -euo pipefail

EVIDENCE_DIR="${QUARANTINE_EVIDENCE_DIR:-/var/log/quarantine}"

usage() {
    grep '^#' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

[ $# -ge 1 ] || usage

RELEASE=false
if [ "$1" = "--release" ]; then
    RELEASE=true
    shift
fi

[ $# -eq 1 ] || usage
CONTAINER="$1"

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
    echo "[FAIL] Контейнер '$CONTAINER' не найден" >&2
    exit 1
fi

if $RELEASE; then
    echo ">> Снятие карантина с '$CONTAINER'..."
    docker unpause "$CONTAINER" 2>/dev/null || true
    echo "[OK] Контейнер возобновлён."
    echo "    Сети НЕ восстановлены автоматически — пересоздайте контейнер:"
    echo "    cd <директория сервиса> && docker compose up -d --force-recreate $CONTAINER"
    exit 0
fi

TS=$(date +%Y%m%d-%H%M%S)
CASE_DIR="$EVIDENCE_DIR/$CONTAINER-$TS"
mkdir -p "$CASE_DIR"

echo "============================================"
echo "  QUARANTINE: $CONTAINER"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Evidence: $CASE_DIR"
echo "============================================"

# -- 1. Сбор улик ДО изоляции --
echo ">> Сохранение улик..."
docker logs --timestamps "$CONTAINER" > "$CASE_DIR/container.log" 2>&1 || true
docker inspect "$CONTAINER" > "$CASE_DIR/inspect.json" 2>/dev/null || true
docker top "$CONTAINER" > "$CASE_DIR/processes.txt" 2>/dev/null || true
docker port "$CONTAINER" > "$CASE_DIR/ports.txt" 2>/dev/null || true
docker diff "$CONTAINER" > "$CASE_DIR/fs_changes.txt" 2>/dev/null || true
echo "[OK] Улики сохранены в $CASE_DIR"

# -- 2. Отключение от всех сетей --
echo ">> Отключение от сетей..."
NETWORKS=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$CONTAINER")
if [ -z "$NETWORKS" ]; then
    echo "   (контейнер уже не подключён ни к одной сети)"
else
    for net in $NETWORKS; do
        if docker network disconnect -f "$net" "$CONTAINER" 2>/dev/null; then
            echo "[OK] Отключён от: $net"
        else
            echo "[FAIL] Не удалось отключить от: $net" >&2
        fi
    done
fi

# -- 3. Заморозка процессов --
echo ">> Приостановка контейнера (docker pause)..."
if docker pause "$CONTAINER" 2>/dev/null; then
    echo "[OK] Контейнер приостановлен (память сохранена для форензики)"
else
    echo "[WARN] pause не удался (возможно, уже приостановлен)"
fi

echo ""
echo "============================================"
echo "  Карантин завершён."
echo "  - Логи и конфигурация: $CASE_DIR"
echo "  - Контейнер изолирован от сети и заморожен"
echo "  - Восстановление: ./quarantine.sh --release $CONTAINER"
echo "    затем: docker compose up -d --force-recreate"
echo "============================================"
