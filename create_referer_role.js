// Создание роли для обычных пользователей (рефереров)
print('🚀 Создание роли для обычных пользователей (рефереров)');

// Подключаемся к правильной базе данных
db = db.getSiblingDB('gateway_auth');

// Роль для обычного пользователя (referrer/referer)
const REFERER_ROLE = {
    name: 'referal-referer',
    displayName: 'Реферер',
    description: 'Обычный пользователь - может создавать и просматривать свои рефералы',
    serviceRoles: ['referer'],
    permissions: [
        'referal.profile.view',           // Просмотр своего профиля
        'referal.referrals.list',         // Просмотр списка своих рефералов
        'referal.referrals.view',         // Просмотр деталей своих рефералов
        'referal.referrals.create',       // Создание новых рефералов
        'referal.status.pending.view',    // Просмотр своих рефералов в статусе "Новый"
        'referal.status.analytics_review.view',  // Просмотр своих рефералов на проверке
        'referal.status.callcenter_review.view', // Просмотр своих рефералов в колл-центре
        'referal.status.director_review.view',   // Просмотр своих рефералов у директора
        'referal.status.accepted.view',   // Просмотр принятых рефералов
        'referal.status.paid.view',       // Просмотр оплаченных рефералов
        'referal.status.rejected.view'    // Просмотр отклоненных рефералов
    ]
};

print('\n📋 Создание роли реферера...');

try {
    const result = db.roles.updateOne(
        { name: REFERER_ROLE.name },
        { 
            $set: {
                displayName: REFERER_ROLE.displayName,
                description: REFERER_ROLE.description,
                serviceRoles: REFERER_ROLE.serviceRoles,
                permissions: REFERER_ROLE.permissions,
                updatedAt: new Date(),
                active: true
            },
            $setOnInsert: {
                createdAt: new Date()
            }
        },
        { upsert: true }
    );
    
    if (result.upsertedCount > 0) {
        print('🆕 Создана роль: ' + REFERER_ROLE.displayName + ' (' + REFERER_ROLE.permissions.length + ' разрешений)');
    } else {
        print('✅ Обновлена роль: ' + REFERER_ROLE.displayName + ' (' + REFERER_ROLE.permissions.length + ' разрешений)');
    }
} catch (error) {
    print('❌ Ошибка при создании роли: ' + error.message);
}

// Проверяем созданную роль
print('\n🔍 Проверка созданной роли:');
const refererRole = db.roles.findOne({ name: REFERER_ROLE.name });

if (refererRole) {
    print('✓ ' + refererRole.displayName);
    print('  Описание: ' + refererRole.description);
    print('  Сервисные роли: ' + refererRole.serviceRoles.join(', '));
    print('  Разрешений: ' + refererRole.permissions.length);
    print('  Разрешения:');
    refererRole.permissions.forEach(perm => {
        print('    - ' + perm);
    });
} else {
    print('❌ Роль не найдена!');
}

print('\n💡 Для назначения роли пользователю выполните:');
print('   db.users.updateOne(');
print('     { username: "имя_пользователя" },');
print('     { $addToSet: { serviceRoles: { $each: ["referal-referer"] } } }');
print('   );');

print('\n✅ Готово!');
