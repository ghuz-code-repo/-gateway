# Документация шлюза переехала

Описание сервисов шлюза (nginx, auth-service, mongo, notification-service,
notification-bot, monitoring-service, dozzle, docker-socket-proxy,
guard-watchdog, quiz) живёт в отдельном репозитории документации,
подключённом сабмодулем в AnalyticsRepo:

**`AnalyticsRepo/docs/`** — https://github.com/ghuz-code-repo/docs

Точка входа:

- `docs/AGENTS.md` — брифинг для ИИ-агента: инварианты платформы, обязательные
  тесты, требования к документации, правила работы со шлюзом
- `docs/README.md` — оглавление
- `docs/gateway/README.md` — карта сервисов шлюза
- `docs/gateway/architecture.md` — сети, `auth_request`, service discovery

Из рабочей копии: [../../docs/README.md](../../docs/README.md)

---

## Правишь код в этом репозитории — обнови `docs/`

**Обязательно, в том же заходе.** Документации шлюза здесь больше нет, и
правка кода без правки `docs/` оставляет описание системы неверным для всех,
кто читает его следующим — включая ИИ-агентов, которые действуют по нему
без перепроверки.

Что и куда — таблица «изменил в шлюзе → обнови в `docs/`» в разделе 8.2
`docs/AGENTS.md`. Коротко:

| Изменил здесь | Правь там |
|---|---|
| роут, middleware, модель прав auth-service | `docs/gateway/auth-service.md` |
| заголовки `X-User-*`, коды `/verify`, API реестра, шаблон конфига nginx | `docs/gateway/architecture.md` + `docs/integration/GATEWAY_SERVICE_INTEGRATION_API.md` + разделы 3–4 `docs/AGENTS.md`. **Ломающее для всех сервисов** |
| `nginx/conf/*` | `docs/gateway/nginx.md`, блоки quiz — `docs/gateway/quiz.md` |
| каналы, лимиты, контракт уведомлений | `docs/gateway/notification-service.md` |
| `notification-bot` | `docs/gateway/notification-bot.md` |
| `docker-compose.yaml`, сети, новый контейнер | `docs/gateway/README.md` + `docs/gateway/architecture.md`; новый контейнер = новый файл в `docs/gateway/` |
| любой `.env.example` | таблица переменных в профильном файле |

Правки шлюза — это **два коммита в двух репозиториях**: код в `!gateway`,
документация в `docs`.

---

Решения и руководства, относящиеся только к этому репозиторию
(`ADR-001-...`, `SERVICE_*`, `MONGODB_AUTH_MIGRATION.md`, `DEPLOYMENT_GUIDE.md`
и прочие), остаются в корне `!gateway/`.
