#!/bin/sh
set -e

echo "🚀 Starting Gateway Nginx..."

# Create dynamic config directory if it doesn't exist
mkdir -p /etc/nginx/conf.d/dynamic

# Create empty services.conf if it doesn't exist
# This ensures nginx can always start even without any registered services
if [ ! -f /etc/nginx/conf.d/dynamic/services.conf ]; then
    echo "📝 Creating initial empty services.conf..."
    cat > /etc/nginx/conf.d/dynamic/services.conf << 'EOF'
# AUTO-GENERATED SERVICE DISCOVERY CONFIG
# Generated at: $(date -Iseconds)
# DO NOT EDIT MANUALLY - Changes will be overwritten
#
# This file is initially empty. Services will be added here
# automatically when they register with the auth-service.
#
# Gateway is designed to start and run even without any registered services.
# The auth-service and admin panel will always be available.

# No services registered yet
EOF
    echo "✅ Initial services.conf created"
fi

# ---------------------------------------------------------------------------
# Контакт поддержки для страниц ошибок
# ---------------------------------------------------------------------------
# nginx не умеет читать переменные окружения в конфиге, поэтому значение
# SUPPORT_TELEGRAM превращается в директиву set здесь, на старте контейнера.
#
# Значение чистится до символов, допустимых в telegram-логине: подставлять
# в конфиг сырую переменную окружения нельзя — кавычка или перевод строки
# в ней сломали бы конфиг и не дали шлюзу подняться.
SUPPORT_TELEGRAM_CLEAN=$(printf '%s' "${SUPPORT_TELEGRAM:-}" | tr -cd 'A-Za-z0-9_')

cat > /etc/nginx/conf.d/errors-contact.inc <<EOF
# АВТОГЕНЕРАЦИЯ docker-entrypoint.sh из SUPPORT_TELEGRAM — руками не править.
# Пустое значение прячет ссылку на странице ошибки целиком.
set \$gw_support_telegram "${SUPPORT_TELEGRAM_CLEAN}";
EOF

if [ -n "$SUPPORT_TELEGRAM_CLEAN" ]; then
    echo "📨 Контакт поддержки на страницах ошибок: t.me/${SUPPORT_TELEGRAM_CLEAN}"
else
    echo "📨 SUPPORT_TELEGRAM не задан — ссылка на поддержку скрыта"
fi

# Test nginx configuration (optional - for logging only)
echo "🔍 Testing nginx configuration..."
nginx -t 2>&1 || echo "⚠️  Configuration has issues with unreachable upstreams - this is normal during startup"

echo "🌐 Starting nginx with resolver..."
echo "✨ Gateway will start even if registered services are not yet available"
echo "📡 Services will be accessible once they start and send heartbeats"

# Execute the default nginx entrypoint
# This will start nginx even if some upstreams are not reachable
exec /docker-entrypoint.sh nginx -g 'daemon off;'
