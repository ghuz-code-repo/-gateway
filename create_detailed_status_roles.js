#!/usr/bin/env node

/**
 * Создание детализированных ролей для системы статусов рефералов
 * Этот скрипт создает роли с гранулярными разрешениями для управления статусами
 */

const { MongoClient } = require('mongodb');

// Подключение к MongoDB
const MONGODB_URI = 'mongodb://localhost:27017';
const DATABASE_NAME = 'gateway_auth';

// Детализированные роли с новыми разрешениями
const DETAILED_ROLES = [
    {
        name: 'referal-analytics-detailed',
        displayName: 'Аналитик (детализированный)',
        description: 'Может работать с новыми заявками и переводить их на проверку',
        serviceRoles: ['analytics'],
        permissions: [
            // Базовые разрешения
            'referal.admin.panel',
            'referal.profile.view',
            
            // Разрешения на статусы для аналитиков
            'referal.status.pending.view',                    // Просмотр ожидающих
            'referal.status.pending.move_from',               // Перевод из ожидающих
            'referal.status.analytics_review.view',          // Просмотр на аналитике
            'referal.status.analytics_review.edit',          // Редактирование на аналитике
            'referal.status.analytics_review.move_from',     // Перевод из аналитики
            'referal.status.callcenter_review.move_to',      // Перевод в колл-центр
            'referal.status.director_review.move_to'         // Перевод к директору
        ]
    },
    
    {
        name: 'referal-callcenter-detailed',
        displayName: 'Колл-центр (детализированный)',
        description: 'Может работать с заявками на проверке в колл-центре',
        serviceRoles: ['call-center'],
        permissions: [
            // Базовые разрешения
            'referal.admin.panel',
            'referal.profile.view',
            
            // Разрешения на статусы для колл-центра
            'referal.status.callcenter_review.view',         // Просмотр в колл-центре
            'referal.status.callcenter_review.edit',         // Редактирование в колл-центре
            'referal.status.callcenter_review.move_from',    // Перевод из колл-центра
            'referal.status.director_review.move_to',        // Перевод к директору
            'referal.status.rejected.move_to'                // Отклонение
        ]
    },
    
    {
        name: 'referal-director-detailed',
        displayName: 'Коммерческий директор (детализированный)',
        description: 'Может принимать решения по заявкам и переводить к оплате',
        serviceRoles: ['manager'],
        permissions: [
            // Базовые разрешения
            'referal.admin.panel',
            'referal.admin.reports',
            'referal.profile.view',
            
            // Разрешения на статусы для директора
            'referal.status.director_review.view',           // Просмотр у директора
            'referal.status.director_review.edit',           // Редактирование у директора
            'referal.status.director_review.move_from',      // Перевод от директора
            'referal.status.accepted.move_to',               // Акцепт к оплате
            'referal.status.rejected.move_to'                // Отклонение
        ]
    },
    
    {
        name: 'referal-payment-manager-detailed',
        displayName: 'Менеджер по платежам (детализированный)',
        description: 'Может работать с принятыми к оплате заявками',
        serviceRoles: ['manager'],
        permissions: [
            // Базовые разрешения
            'referal.admin.panel',
            'referal.admin.reports',
            'referal.profile.view',
            'referal.payments.view',
            
            // Разрешения на статусы для менеджера платежей
            'referal.status.accepted.view',                  // Просмотр принятых
            'referal.status.accepted.edit',                  // Редактирование принятых
            'referal.status.accepted.move_from',             // Перевод из принятых
            'referal.status.paid.move_to',                   // Перевод в оплачено
            'referal.status.paid.view'                       // Просмотр оплаченных
        ]
    },
    
    {
        name: 'referal-viewer-detailed',
        displayName: 'Наблюдатель (детализированный)',
        description: 'Может только просматривать заявки во всех статусах',
        serviceRoles: ['analytics'],
        permissions: [
            // Базовые разрешения
            'referal.admin.panel',
            'referal.profile.view',
            'referal.admin.reports',
            
            // Только просмотр всех статусов
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
            // Все базовые разрешения
            'referal.admin.panel',
            'referal.admin.change_status',
            'referal.admin.reports',
            'referal.admin.export',
            'referal.profile.view',
            'referal.payments.view',
            
            // Все разрешения на статусы
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

async function createDetailedRoles() {
    const client = new MongoClient(MONGODB_URI);
    
    try {
        await client.connect();
        console.log('🔗 Подключен к MongoDB');
        
        const db = client.db(DATABASE_NAME);
        const rolesCollection = db.collection('roles');
        
        console.log('\n📋 Создание детализированных ролей для статусов...');
        
        for (const roleData of DETAILED_ROLES) {
            try {
                // Проверяем, существует ли роль
                const existingRole = await rolesCollection.findOne({ name: roleData.name });
                
                if (existingRole) {
                    // Обновляем существующую роль
                    await rolesCollection.updateOne(
                        { name: roleData.name },
                        { 
                            $set: {
                                displayName: roleData.displayName,
                                description: roleData.description,
                                serviceRoles: roleData.serviceRoles,
                                permissions: roleData.permissions,
                                updatedAt: new Date()
                            }
                        }
                    );
                    console.log(`✅ Обновлена роль: ${roleData.displayName} (${roleData.permissions.length} разрешений)`);
                } else {
                    // Создаем новую роль
                    const newRole = {
                        name: roleData.name,
                        displayName: roleData.displayName,
                        description: roleData.description,
                        serviceRoles: roleData.serviceRoles,
                        permissions: roleData.permissions,
                        createdAt: new Date(),
                        updatedAt: new Date(),
                        active: true
                    };
                    
                    await rolesCollection.insertOne(newRole);
                    console.log(`🆕 Создана роль: ${roleData.displayName} (${roleData.permissions.length} разрешений)`);
                }
                
                // Выводим детали разрешений
                console.log(`   📝 Разрешения: ${roleData.permissions.slice(0, 3).join(', ')}${roleData.permissions.length > 3 ? ` и еще ${roleData.permissions.length - 3}...` : ''}`);
                
            } catch (error) {
                console.error(`❌ Ошибка при создании роли ${roleData.name}:`, error.message);
            }
        }
        
        console.log('\n📊 Статистика созданных ролей:');
        const totalRoles = await rolesCollection.countDocuments({ 
            name: { $in: DETAILED_ROLES.map(r => r.name) } 
        });
        console.log(`   Всего детализированных ролей: ${totalRoles}`);
        
        // Выводим примеры использования
        console.log('\n💡 Примеры назначения ролей пользователям:');
        console.log('   Аналитик: referal-analytics-detailed');
        console.log('   Колл-центр: referal-callcenter-detailed');
        console.log('   Директор: referal-director-detailed');
        console.log('   Менеджер платежей: referal-payment-manager-detailed');
        console.log('   Наблюдатель: referal-viewer-detailed');
        console.log('   Администратор: referal-status-admin-detailed');
        
        console.log('\n🔍 Для отладки разрешений перейдите по адресу:');
        console.log('   http://localhost/referal/admin/debug/permissions-ui');
        
    } catch (error) {
        console.error('❌ Ошибка:', error);
    } finally {
        await client.close();
        console.log('\n✅ Соединение с базой данных закрыто');
    }
}

// Дополнительная функция для показа статистики разрешений
async function showPermissionStatistics() {
    const client = new MongoClient(MONGODB_URI);
    
    try {
        await client.connect();
        const db = client.db(DATABASE_NAME);
        const rolesCollection = db.collection('roles');
        
        console.log('\n📈 Статистика разрешений по ролям:');
        
        for (const roleData of DETAILED_ROLES) {
            const role = await rolesCollection.findOne({ name: roleData.name });
            if (role) {
                console.log(`\n🎭 ${role.displayName}:`);
                console.log(`   Всего разрешений: ${role.permissions.length}`);
                
                const statusPermissions = role.permissions.filter(p => p.includes('status'));
                const adminPermissions = role.permissions.filter(p => p.includes('admin'));
                const profilePermissions = role.permissions.filter(p => p.includes('profile'));
                
                console.log(`   Разрешения статусов: ${statusPermissions.length}`);
                console.log(`   Админ разрешения: ${adminPermissions.length}`);
                console.log(`   Профиль разрешения: ${profilePermissions.length}`);
            }
        }
        
    } catch (error) {
        console.error('❌ Ошибка при получении статистики:', error);
    } finally {
        await client.close();
    }
}

// Запуск скрипта
async function main() {
    console.log('🚀 Создание детализированной системы разрешений для статусов рефералов');
    console.log('=' * 80);
    
    await createDetailedRoles();
    await showPermissionStatistics();
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = {
    createDetailedRoles,
    showPermissionStatistics,
    DETAILED_ROLES
};