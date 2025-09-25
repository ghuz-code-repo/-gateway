# Расширенное удаление пользователя - Документация

## Обзор
Функция `DeleteUser` была расширена для полного удаления всех связанных с пользователем данных, документов и файлов.

## Что удаляется при удалении пользователя

### 1. Записи в базе данных
- **Пользователь** - основная запись пользователя из коллекции `users`
- **Роли сервисов** - все назначения ролей пользователя в коллекции `user_service_roles`
- **Токены сброса пароля** - все активные токены из коллекции `password_reset_tokens`
- **Заблокированные токены** - все токены из коллекции `blacklisted_tokens`

### 2. Связанные записи
- **Логи импорта** - все записи в `import_logs` где пользователь был администратором
- **Дополнительные роли сервисов** - дублирующие записи (на случай ошибок)
- **Логи активности** - записи из коллекции `activity_logs` (если существует)
- **Пользовательские сессии** - записи из коллекции `user_sessions` (если существует)
- **Обновление ссылок** - обновляет поле `assigned_by` в ролях, где удаляемый пользователь был назначающим

### 3. Файлы и директории
- **Аватар пользователя** - `./data/{userID}/avatar.jpg`
- **Оригинальные аватары** - `./data/{userID}/original.{ext}` (поддерживает .jpg, .jpeg, .png, .gif, .webp)
- **Вложения документов** - все файлы из поля `Documents[].Attachments[].FilePath`
- **Устаревшие документы** - файлы из поля `LegacyDocs[].FilePath`
- **Пользовательская директория** - `./data/{userID}/` (удаляется если пустая)

## Функции

### `DeleteUser(id primitive.ObjectID) error`
Основная функция удаления пользователя с расширенной очисткой.

**Параметры:**
- `id` - ObjectID пользователя для удаления

**Возвращает:**
- `error` - ошибка если удаление не удалось

**Процесс:**
1. Получение данных пользователя
2. Удаление ролей сервисов
3. Удаление токенов сброса пароля
4. Удаление заблокированных токенов
5. Удаление связанных записей
6. Удаление файлов пользователя
7. Удаление записи пользователя
8. Отправка уведомления на email

### `deleteUserRelatedRecords(userID primitive.ObjectID, username string) error`
Удаляет все связанные записи из других коллекций.

**Удаляемые коллекции:**
- `import_logs` - по `admin_username`
- `user_service_roles` - по `user_id` (дубли)
- `activity_logs` - по `user_id`
- `user_sessions` - по `user_id`

**Обновляемые записи:**
- `user_service_roles.assigned_by` → `primitive.NilObjectID`

### `deleteUserFiles(user *User) error`
Удаляет все файлы и папки пользователя.

**Удаляемые файлы:**
- Аватары: `./data/{userID}/avatar.jpg`
- Оригинальные аватары: `./data/{userID}/original.{ext}`
- Вложения документов: из `user.Documents[].Attachments[].FilePath`
- Устаревшие документы: из `user.LegacyDocs[].FilePath`

## Логирование

Все операции логируются с подробной информацией:
- Количество удаленных записей по каждому типу
- Пути удаленных файлов
- Предупреждения о неудачных операциях
- Итоговая сводка об удалении

**Пример логов:**
```
Starting deletion of user john.doe (ID: 507f1f77bcf86cd799439011) and all related data
Deleted 3 password reset tokens for user john.doe
Deleted 1 blacklisted tokens for user john.doe
Deleted 5 import logs for user john.doe
Deleted avatar file: ./data/507f1f77bcf86cd799439011/avatar.jpg
Deleted original avatar file: ./data/507f1f77bcf86cd799439011/original.jpg
Deleted document attachment: ./data/507f1f77bcf86cd799439011/documents/contract.pdf
File cleanup completed for user john.doe: 3 files deleted
Related records cleanup completed for user john.doe: 8 records deleted
User john.doe (ID: 507f1f77bcf86cd799439011) successfully deleted with all related data
```

## Безопасность

- **Проверка существования** - функция проверяет существование пользователя перед удалением
- **Graceful errors** - ошибки удаления файлов не прерывают процесс удаления пользователя
- **Atomic operations** - использует контекст с таймаутом для операций БД
- **Email уведомления** - отправляется асинхронно после успешного удаления

## Использование

### Через API (существующий эндпоинт)
```http
POST /users/:id/delete
```

### Через Excel импорт
Установить значение "true" в колонке "Удалить" для пользователя в Excel файле.

### Программно
```go
err := models.DeleteUser(userID)
if err != nil {
    log.Printf("Failed to delete user: %v", err)
}
```

## Мониторинг

Для мониторинга успешности удаления проверяйте логи на:
- Сообщения "successfully deleted with all related data"
- Количество удаленных файлов и записей
- Предупреждения о неудачных операциях

## Восстановление

⚠️ **ВАЖНО**: После удаления пользователя восстановление невозможно. Все данные, файлы и записи удаляются безвозвратно.

Убедитесь, что у вас есть резервные копии важных данных перед удалением пользователей.