// ============================================================================
// Migration Script: Assign 'user' role to all users without a referal role
// ============================================================================
// Purpose: Ensures every user in the system has at least the 'user' role
//          in the referal service (user_service_roles collection).
//          This is required after removing the hardcoded fallback in
//          verifyHandler that auto-granted referal access to all users.
//
// Usage (inside mongo container):
//   mongosh authdb /scripts/migrate_referal_user_roles.js
//
// Or from docker compose (from !gateway/ directory):
//   docker compose exec mongo mongosh authdb /docker-entrypoint-initdb.d/migrate_referal_user_roles.js
//
// Or with authentication:
//   docker compose exec mongo mongosh -u mongoadmin -p <ROOT_PASSWORD> --authenticationDatabase admin authdb /scripts/migrate_referal_user_roles.js
//
// Safe to run multiple times — skips users who already have an active referal role.
// ============================================================================

print("=== Migration: Assign 'user' role to users without referal role ===");
print("Started at: " + new Date().toISOString());

// Get all user IDs in the system
const allUserIds = db.users.distinct("_id");
print("Total users in system: " + allUserIds.length);

// Get user IDs that already have ANY active referal role
const usersWithReferalRole = db.user_service_roles.distinct("user_id", {
    service_key: "referal",
    is_active: true
});
print("Users already with active referal role: " + usersWithReferalRole.length);

// Filter to only users missing a referal role
const usersToMigrate = allUserIds.filter(
    uid => !usersWithReferalRole.some(rid => rid.equals(uid))
);
print("Users to migrate: " + usersToMigrate.length);

if (usersToMigrate.length === 0) {
    print("Nothing to migrate — all users already have a referal role.");
    print("=== Migration complete ===");
    quit(0);
}

// Find admin user to use as assigned_by (fallback to first user if no admin)
const adminUser = db.users.findOne({ username: "admin" });
const assignedBy = adminUser ? adminUser._id : usersToMigrate[0];
print("assigned_by: " + assignedBy + (adminUser ? " (admin)" : " (fallback)"));

// Build documents to insert
const now = new Date();
const docs = usersToMigrate.map(uid => ({
    role_name: "user",
    service_key: "referal",
    user_id: uid,
    assigned_at: now,
    assigned_by: assignedBy,
    is_active: true
}));

// Insert in bulk
const result = db.user_service_roles.insertMany(docs);
print("Inserted: " + result.insertedIds.length + " records");

// Print migrated users for audit trail
print("");
print("--- Migrated users ---");
usersToMigrate.forEach(uid => {
    const u = db.users.findOne({ _id: uid }, { username: 1, firstName: 1, lastName: 1 });
    if (u) {
        print("  " + u.username + " | " + (u.firstName || "") + " " + (u.lastName || ""));
    }
});

// Final verification
print("");
const afterTotal = db.user_service_roles.countDocuments({
    service_key: "referal",
    is_active: true
});
const remaining = db.users.distinct("_id").filter(
    uid => !db.user_service_roles.distinct("user_id", {
        service_key: "referal",
        is_active: true
    }).some(rid => rid.equals(uid))
);

print("Total active referal roles after migration: " + afterTotal);
print("Users still without referal role: " + remaining.length);

if (remaining.length > 0) {
    print("WARNING: Some users were not migrated!");
    remaining.forEach(uid => {
        const u = db.users.findOne({ _id: uid }, { username: 1 });
        if (u) print("  MISSING: " + u.username);
    });
} else {
    print("SUCCESS: All users now have a referal role.");
}

print("");
print("Finished at: " + new Date().toISOString());
print("=== Migration complete ===");
