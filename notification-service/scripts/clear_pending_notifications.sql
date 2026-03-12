-- Скрипт для очистки ожидающих уведомлений
-- Использование: psql -U postgres -d notification_db -f clear_pending_notifications.sql
-- Или через Docker: docker exec -i gateway-postgres-1 psql -U postgres -d notification_db -f /path/to/script.sql

-- Показать статистику перед удалением
SELECT 
    status, 
    COUNT(*) as count,
    MIN(created_at) as oldest,
    MAX(created_at) as newest
FROM notifications 
GROUP BY status
ORDER BY count DESC;

-- Удалить все pending и failed уведомления
-- (failed тоже удаляем, так как это неактуальные письма)
DELETE FROM notifications 
WHERE status IN ('pending', 'failed');

-- Показать результат
SELECT 
    status, 
    COUNT(*) as count
FROM notifications 
GROUP BY status
ORDER BY count DESC;

-- Очистить завершённые батчи
DELETE FROM notification_batches
WHERE status IN ('completed', 'failed');

SELECT 'Очистка завершена!' as result;
