-- Скрипт для получения статистики по email-уведомлениям за сегодня
-- Использование: psql -U <user> -d <database> -f email_stats_today.sql

-- Подсчет количества email по статусам, созданных сегодня
SELECT 
    status,
    COUNT(*) as count
FROM 
    notifications
WHERE 
    type = 'email'
    AND created_at >= EXTRACT(EPOCH FROM DATE_TRUNC('day', CURRENT_DATE))::bigint
    AND created_at < EXTRACT(EPOCH FROM DATE_TRUNC('day', CURRENT_DATE + INTERVAL '1 day'))::bigint
GROUP BY 
    status
ORDER BY 
    CASE status
        WHEN 'pending' THEN 1
        WHEN 'sending' THEN 2
        WHEN 'sent' THEN 3
        WHEN 'failed' THEN 4
        WHEN 'cancelled' THEN 5
        ELSE 6
    END;

-- Дополнительная статистика: общее количество
SELECT 
    'TOTAL' as status,
    COUNT(*) as count
FROM 
    notifications
WHERE 
    type = 'email'
    AND created_at >= EXTRACT(EPOCH FROM DATE_TRUNC('day', CURRENT_DATE))::bigint
    AND created_at < EXTRACT(EPOCH FROM DATE_TRUNC('day', CURRENT_DATE + INTERVAL '1 day'))::bigint;
