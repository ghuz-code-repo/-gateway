// ========================================
// СКРИПТ ВОССТАНОВЛЕНИЯ РОЛЕЙ CLIENT-SERVICE
// ========================================
// 
// Этот скрипт восстанавливает роли для client-service на основе MIGRATION_REPORT.md
// 
// ЗАПУСК НА СЕРВЕРЕ:
// cat restore_client_service_roles.js | docker exec -i gateway-mongo-1 mongosh authdb
//
// ========================================

print("\n" + "=".repeat(70));
print("🔧 ВОССТАНОВЛЕНИЕ РОЛЕЙ CLIENT-SERVICE");
print("=".repeat(70) + "\n");

// Получаем все разрешения для client-service
const service = db.services.findOne({ key: "client-service" });

if (!service) {
    print("❌ ОШИБКА: Сервис client-service не найден!");
    print("Необходимо сначала создать сервис в auth-service");
    quit(1);
}

print("✅ Сервис найден: " + service.name);
print("📋 Доступные разрешения: " + service.available_permissions.length);

// Определяем РЕАЛЬНЫЕ роли, которые были на сервере
const rolesToCreate = [
    {
        name: "admin",
        description: "Администратор",
        permissions: [
            "client-service.applications.view",
            "client-service.applications.create",
            "client-service.applications.edit",
            "client-service.applications.delete",
            "client-service.applications.assign",
            "client-service.applications.status.change",
            "client-service.applications.export",
            "client-service.responsible.view",
            "client-service.responsible.create",
            "client-service.responsible.edit",
            "client-service.responsible.delete",
            "client-service.admin.panel",
            "client-service.admin.users",
            "client-service.admin.settings",
            "client-service.admin.logs"
        ]
    },
    {
        name: "call-center",
        description: "Сотрудник Call-центра",
        permissions: [
            "client-service.applications.view",
            "client-service.applications.create",
            "client-service.applications.edit",
            "client-service.applications.status.change"
        ]
    },
    {
        name: "manager_dcs",
        description: "Менеджер ДКС",
        permissions: [
            "client-service.applications.view",
            "client-service.applications.create",
            "client-service.applications.edit",
            "client-service.applications.assign",
            "client-service.applications.status.change",
            "client-service.applications.export",
            "client-service.responsible.view",
            "client-service.responsible.create",
            "client-service.responsible.edit"
        ]
    },
    {
        name: "temporary",
        description: "Временный доступ",
        permissions: [
            "client-service.applications.view"
        ]
    }
];

print("\n" + "=".repeat(70));
print("📝 СОЗДАНИЕ/ОБНОВЛЕНИЕ РОЛЕЙ");
print("=".repeat(70) + "\n");

let created = 0;
let updated = 0;
let errors = 0;

rolesToCreate.forEach(roleData => {
    try {
        const existingRole = db.roles.findOne({
            service_key: "client-service",
            name: roleData.name
        });

        if (existingRole) {
            // Обновляем существующую роль
            const result = db.roles.updateOne(
                { _id: existingRole._id },
                {
                    $set: {
                        description: roleData.description,
                        permissions: roleData.permissions,
                        updated_at: new Date()
                    }
                }
            );
            
            if (result.modifiedCount > 0) {
                print(`✅ Обновлена роль: client-service:${roleData.name} (${roleData.permissions.length} разрешений)`);
                updated++;
            } else {
                print(`ℹ️  Роль не изменена: client-service:${roleData.name}`);
            }
        } else {
            // Создаем новую роль
            const result = db.roles.insertOne({
                service_key: "client-service",
                name: roleData.name,
                description: roleData.description,
                permissions: roleData.permissions,
                created_at: new Date(),
                updated_at: new Date()
            });
            
            if (result.acknowledged) {
                print(`✨ Создана роль: client-service:${roleData.name} (${roleData.permissions.length} разрешений)`);
                created++;
            } else {
                print(`❌ Ошибка создания роли: client-service:${roleData.name}`);
                errors++;
            }
        }
    } catch (e) {
        print(`❌ ОШИБКА при обработке роли ${roleData.name}: ${e.message}`);
        errors++;
    }
});

print("\n" + "=".repeat(70));
print("📊 ИТОГОВАЯ СТАТИСТИКА");
print("=".repeat(70) + "\n");

print(`✨ Создано новых ролей: ${created}`);
print(`✅ Обновлено существующих ролей: ${updated}`);
print(`❌ Ошибок: ${errors}`);

// Проверяем итоговое состояние
const finalRoles = db.roles.find({ service_key: "client-service" }).toArray();
print(`\n📋 Всего ролей для client-service: ${finalRoles.length}`);

print("\n" + "=".repeat(70));
print("🎯 СПИСОК РОЛЕЙ ПОСЛЕ ВОССТАНОВЛЕНИЯ");
print("=".repeat(70) + "\n");

finalRoles.forEach(role => {
    print(`  • ${role.name} - ${role.description} (${role.permissions.length} разрешений)`);
});

print("\n" + "=".repeat(70));
print("✅ ВОССТАНОВЛЕНИЕ ЗАВЕРШЕНО");
print("=".repeat(70) + "\n");

print("🚀 Следующие шаги:");
print("   1. Проверьте роли в админ-панели auth-service");
print("   2. Убедитесь что пользователи имеют правильные роли");
print("   3. Проверьте доступ пользователей в client-service");
print("");
