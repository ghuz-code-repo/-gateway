// Скрипт для миграции путей аватаров в MongoDB
// Запускать из папки !gateway

const { MongoClient } = require('mongodb');

async function migrateAvatarPaths() {
    const client = new MongoClient('mongodb://localhost:27017');
    
    try {
        await client.connect();
        console.log('Подключен к MongoDB');
        
        const db = client.db('auth_service');
        const collection = db.collection('users');
        
        // Найти всех пользователей с аватарами
        const users = await collection.find({
            avatar_path: { $regex: /^\/data\/.*\/avatar\.jpg$/ }
        }).toArray();
        
        console.log(`Найдено ${users.length} пользователей с аватарами для миграции`);
        
        for (const user of users) {
            const oldPath = user.avatar_path;
            // Извлечь userID из старого пути /data/userID/avatar.jpg
            const userIdMatch = oldPath.match(/\/data\/([^\/]+)\/avatar\.jpg/);
            
            if (userIdMatch) {
                const userId = userIdMatch[1];
                const newPath = `/avatar/${userId}`;
                
                // Обновить путь в базе данных
                await collection.updateOne(
                    { _id: user._id },
                    { $set: { avatar_path: newPath } }
                );
                
                console.log(`Обновлен пользователь ${user._id}: ${oldPath} -> ${newPath}`);
            }
        }
        
        console.log('Миграция завершена');
        
    } catch (error) {
        console.error('Ошибка миграции:', error);
    } finally {
        await client.close();
    }
}

migrateAvatarPaths();