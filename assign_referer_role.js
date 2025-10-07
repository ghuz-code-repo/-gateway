// Назначение роли реферера пользователю с ролью 'user'
print('🚀 Назначение роли реферера пользователям');

// Подключаемся к правильной базе данных
db = db.getSiblingDB('gateway_auth');

// Имя роли
const REFERER_ROLE_NAME = 'referal-referer';

// Проверяем, существует ли роль
const refererRole = db.roles.findOne({ name: REFERER_ROLE_NAME });

if (!refererRole) {
    print('❌ Роль ' + REFERER_ROLE_NAME + ' не найдена!');
    print('💡 Сначала выполните скрипт create_referer_role.js');
    quit();
}

print('✅ Роль найдена: ' + refererRole.displayName);
print('   Разрешений: ' + refererRole.permissions.length);

// Находим всех пользователей, которым нужна эта роль
// Обычно это пользователи с globalRoles: ['user'] или без специальных ролей

print('\n🔍 Поиск пользователей...');

// Вариант 1: Найти пользователей с глобальной ролью 'user'
const usersWithUserRole = db.users.find({
    globalRoles: { $in: ['user'] }
}).toArray();

print('   Найдено пользователей с ролью "user": ' + usersWithUserRole.length);

// Вариант 2: Найти пользователей БЕЗ сервисных ролей для referal
const usersWithoutReferalRoles = db.users.find({
    $or: [
        { 'serviceRoles.referal': { $exists: false } },
        { 'serviceRoles.referal': { $size: 0 } },
        { 'serviceRoles.referal': [] }
    ]
}).toArray();

print('   Найдено пользователей без реферальных ролей: ' + usersWithoutReferalRoles.length);

// Объединяем списки (уникальные пользователи)
const allUserIds = new Set();
usersWithUserRole.forEach(u => allUserIds.add(u._id.toString()));
usersWithoutReferalRoles.forEach(u => allUserIds.add(u._id.toString()));

print('\n📊 Всего уникальных пользователей для обновления: ' + allUserIds.size);

if (allUserIds.size === 0) {
    print('⚠️  Пользователи не найдены. Возможно, все уже имеют роли.');
    print('\n💡 Для ручного назначения роли выполните:');
    print('   db.users.updateOne(');
    print('     { username: "имя_пользователя" },');
    print('     { $addToSet: { "serviceRoles.referal": "referal-referer" } }');
    print('   );');
    quit();
}

// Спрашиваем подтверждение (в интерактивном режиме)
print('\n⚠️  Будет обновлено пользователей: ' + allUserIds.size);
print('   Будет назначена роль: ' + REFERER_ROLE_NAME);

// Назначаем роль
print('\n🔄 Начинаем обновление...');

let updated = 0;
let errors = 0;

for (const userId of allUserIds) {
    try {
        const result = db.users.updateOne(
            { _id: ObjectId(userId) },
            { 
                $addToSet: { 
                    'serviceRoles.referal': REFERER_ROLE_NAME 
                },
                $set: {
                    updatedAt: new Date()
                }
            }
        );
        
        if (result.modifiedCount > 0) {
            const user = db.users.findOne({ _id: ObjectId(userId) });
            print('✅ Обновлен: ' + user.username);
            updated++;
        }
    } catch (error) {
        print('❌ Ошибка при обновлении пользователя ' + userId + ': ' + error.message);
        errors++;
    }
}

print('\n📊 Результаты:');
print('   Успешно обновлено: ' + updated);
print('   Ошибок: ' + errors);

// Проверяем результат
print('\n🔍 Проверка назначенных ролей:');
const usersWithRefererRole = db.users.find({
    'serviceRoles.referal': REFERER_ROLE_NAME
}).toArray();

print('   Всего пользователей с ролью реферера: ' + usersWithRefererRole.length);

if (usersWithRefererRole.length > 0) {
    print('\n   Примеры:');
    usersWithRefererRole.slice(0, 5).forEach(user => {
        print('   - ' + user.username + ' (' + user.email + ')');
    });
}

print('\n✅ Готово!');
