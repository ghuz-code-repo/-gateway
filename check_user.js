// Поиск пользователя prodgaraj и проверка его ролей
print('🔍 Поиск пользователя prodgaraj');

const databases = ['gateway', 'gateway_auth', 'authdb', 'auth_service'];
let userFound = false;
let userId = null;

for (const dbName of databases) {
    print(`\n📂 Проверка базы: ${dbName}`);
    db = db.getSiblingDB(dbName);
    
    // Проверяем коллекцию users
    if (db.getCollectionNames().includes('users')) {
        const user = db.users.findOne({ 
            $or: [
                { username: 'prodgaraj' },
                { login: 'prodgaraj' },
                { email: { $regex: 'prodgaraj', $options: 'i' } }
            ]
        });
        
        if (user) {
            print('✅ Пользователь найден!');
            print('   ID: ' + user._id);
            print('   Username: ' + (user.username || user.login || 'N/A'));
            print('   Email: ' + (user.email || 'N/A'));
            if (user.roles) print('   Roles: ' + JSON.stringify(user.roles));
            if (user.globalRoles) print('   Global Roles: ' + JSON.stringify(user.globalRoles));
            userFound = true;
            userId = user._id;
            
            // Проверяем user_service_roles если есть
            if (db.getCollectionNames().includes('user_service_roles')) {
                print('\n🔑 Сервисные роли:');
                const serviceRoles = db.user_service_roles.find({ userId: userId }).toArray();
                if (serviceRoles.length > 0) {
                    serviceRoles.forEach(sr => {
                        print(`   Сервис: ${sr.serviceKey}`);
                        print(`   Роли: ${JSON.stringify(sr.roleNames)}`);
                    });
                } else {
                    print('   ⚠️  Сервисные роли не назначены');
                }
            }
        }
    }
}

if (!userFound) {
    print('\n❌ Пользователь prodgaraj не найден ни в одной базе!');
    print('\n💡 Возможные причины:');
    print('   1. Пользователь использует внешнюю аутентификацию');
    print('   2. Пользователь хранится в другой системе (LDAP, OAuth)');
    print('   3. Пользователь создается динамически при входе');
    print('\n🔍 Проверьте логи auth-service для деталей');
}

print('\n✅ Готово!');
