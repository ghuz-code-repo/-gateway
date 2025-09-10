// Восстановление связи между пользователем и существующим файлом аватарки
use authdb;

// Проверяем, есть ли файл для пользователя с ID 688216ad279b8a22aabeb269
var userId = ObjectId("688216ad279b8a22aabeb269");
var avatarPath = "/data/avatars/avatar_688216ad279b8a22aabeb269_1757343313.jpg";

// Обновляем путь к аватарке
db.users.updateOne(
    { _id: userId },
    { 
        $set: { 
            avatar_path: avatarPath,
            updated_at: new Date()
        } 
    }
);

print("Восстановлена связь с аватаркой для пользователя");

// Проверяем результат
db.users.findOne({ _id: userId }, { avatar_path: 1, username: 1, email: 1 });
