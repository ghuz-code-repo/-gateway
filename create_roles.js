// Создание детализированных ролей для статусов рефералов
print('🚀 Создание детализированных ролей для статусов рефералов');

// Подключаемся к правильной базе данных
db = db.getSiblingDB('gateway_auth');

// Детализированные роли с новыми разрешениями
const DETAILED_ROLES = [
    {
        name: 'referal-analytics-detailed',
        displayName: 'Аналитик (детализированный)',
        description: 'Может работать с новыми заявками и переводить их на проверку',
        serviceRoles: ['analytics'],
        permissions: [
            'referal.admin.panel',
            'referal.profile.view',
            'referal.status.pending.view',
            'referal.status.pending.move_from',
            'referal.status.analytics_review.view',
            'referal.status.analytics_review.edit',
            'referal.status.analytics_review.move_from',
            'referal.status.callcenter_review.move_to',
            'referal.status.director_review.move_to'
        ]
    },
    {
        name: 'referal-callcenter-detailed',
        displayName: 'Колл-центр (детализированный)',
        description: 'Может работать с заявками на проверке в колл-центре',
        serviceRoles: ['call-center'],
        permissions: [
            'referal.admin.panel',
            'referal.profile.view',
            'referal.status.callcenter_review.view',
            'referal.status.callcenter_review.edit',
            'referal.status.callcenter_review.move_from',
            'referal.status.director_review.move_to',
            'referal.status.rejected.move_to'
        ]
    },
    {
        name: 'referal-director-detailed',
        displayName: 'Коммерческий директор (детализированный)',
        description: 'Может принимать решения по заявкам и переводить к оплате',
        serviceRoles: ['manager'],
        permissions: [
            'referal.admin.panel',
            'referal.admin.reports',
            'referal.profile.view',
            'referal.status.director_review.view',
            'referal.status.director_review.edit',
            'referal.status.director_review.move_from',
            'referal.status.accepted.move_to',
            'referal.status.rejected.move_to'
        ]
    },
    {
        name: 'referal-viewer-detailed',
        displayName: 'Наблюдатель (детализированный)',
        description: 'Может только просматривать заявки во всех статусах',
        serviceRoles: ['analytics'],
        permissions: [
            'referal.admin.panel',
            'referal.profile.view',
            'referal.admin.reports',
            'referal.status.pending.view',
            'referal.status.analytics_review.view',
            'referal.status.callcenter_review.view',
            'referal.status.director_review.view',
            'referal.status.accepted.view',
            'referal.status.paid.view',
            'referal.status.rejected.view'
        ]
    },
    {
        name: 'referal-status-admin-detailed',
        displayName: 'Администратор статусов (детализированный)',
        description: 'Полный доступ ко всем статусам и операциям',
        serviceRoles: ['admin'],
        permissions: [
            'referal.admin.panel',
            'referal.admin.change_status',
            'referal.admin.reports',
            'referal.admin.export',
            'referal.profile.view',
            'referal.payments.view',
            'referal.status.pending.view',
            'referal.status.pending.edit',
            'referal.status.pending.move_to',
            'referal.status.pending.move_from',
            'referal.status.analytics_review.view',
            'referal.status.analytics_review.edit',
            'referal.status.analytics_review.move_to',
            'referal.status.analytics_review.move_from',
            'referal.status.callcenter_review.view',
            'referal.status.callcenter_review.edit',
            'referal.status.callcenter_review.move_to',
            'referal.status.callcenter_review.move_from',
            'referal.status.director_review.view',
            'referal.status.director_review.edit',
            'referal.status.director_review.move_to',
            'referal.status.director_review.move_from',
            'referal.status.accepted.view',
            'referal.status.accepted.edit',
            'referal.status.accepted.move_to',
            'referal.status.accepted.move_from',
            'referal.status.paid.view',
            'referal.status.paid.edit',
            'referal.status.paid.move_to',
            'referal.status.paid.move_from',
            'referal.status.rejected.view',
            'referal.status.rejected.edit',
            'referal.status.rejected.move_to',
            'referal.status.rejected.move_from'
        ]
    }
];

print('\n📋 Создание детализированных ролей...');

// Создаем роли
let created = 0;
let updated = 0;

for (const roleData of DETAILED_ROLES) {
    try {
        const result = db.roles.updateOne(
            { name: roleData.name },
            { 
                $set: {
                    displayName: roleData.displayName,
                    description: roleData.description,
                    serviceRoles: roleData.serviceRoles,
                    permissions: roleData.permissions,
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
            print('🆕 Создана роль: ' + roleData.displayName + ' (' + roleData.permissions.length + ' разрешений)');
            created++;
        } else {
            print('✅ Обновлена роль: ' + roleData.displayName + ' (' + roleData.permissions.length + ' разрешений)');
            updated++;
        }
    } catch (error) {
        print('❌ Ошибка при создании роли ' + roleData.name + ': ' + error.message);
    }
}

print('\n📊 Статистика:');
print('   Создано новых ролей: ' + created);
print('   Обновлено существующих: ' + updated);
print('   Всего ролей: ' + (created + updated));

// Проверяем созданные роли
print('\n🔍 Проверка созданных ролей:');
const detailedRoles = db.roles.find({ 
    name: { $in: DETAILED_ROLES.map(r => r.name) } 
}).toArray();

for (const role of detailedRoles) {
    print('✓ ' + role.displayName + ' - ' + role.permissions.length + ' разрешений');
}

print('\n💡 Примеры назначения ролей пользователям:');
print('   Аналитик: referal-analytics-detailed');
print('   Колл-центр: referal-callcenter-detailed');
print('   Директор: referal-director-detailed');
print('   Наблюдатель: referal-viewer-detailed');
print('   Администратор: referal-status-admin-detailed');

print('\n🔍 Для отладки разрешений перейдите по адресу:');
print('   http://localhost/referal/admin/debug/permissions-ui');

print('\n✅ Готово!');