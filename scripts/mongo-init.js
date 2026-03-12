// ============================================================
// MongoDB Init Script — создаёт application-пользователя
// ============================================================
// Этот скрипт выполняется ТОЛЬКО при первой инициализации MongoDB
// (когда /data/db пуст и MONGO_INITDB_ROOT_USERNAME задан).
//
// Для СУЩЕСТВУЮЩИХ баз (прод) — используйте ручную миграцию,
// см. MONGODB_AUTH_MIGRATION.md
// ============================================================

// Переключаемся на authdb (целевая БД приложения)
db = db.getSiblingDB("authdb");

// Пароль приложения берётся из переменной окружения MONGO_APP_PASSWORD,
// которая передаётся в docker-compose.yaml → environment.
// В init-скрипте MongoDB переменные окружения доступны через process.env.
const appPassword = process.env.MONGO_APP_PASSWORD;

if (!appPassword) {
    print("ERROR: MONGO_APP_PASSWORD environment variable is not set!");
    print("Set MONGO_APP_PASSWORD in !gateway/.env file.");
    quit(1);
}

// Создаём пользователя с минимальными привилегиями (readWrite на authdb)
db.createUser({
    user: "authservice",
    pwd: appPassword,
    roles: [
        { role: "readWrite", db: "authdb" }
    ]
});

print("✅ Application user 'authservice' created with readWrite access on 'authdb'");
