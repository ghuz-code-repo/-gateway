db = db.getSiblingDB("authdb");

// Step 0: Backup
print("=== BACKUP ===");
var allDocs = db.user_service_roles.find().toArray();
print("Total records: " + allDocs.length);

var backupName = "user_service_roles_backup_cleanup";
if (allDocs.length > 0) {
  db.getCollection(backupName).drop();
  db.getCollection(backupName).insertMany(allDocs);
  print("Backup created: " + backupName + " (" + allDocs.length + " records)");
}

// Step 1: Remove empty records
print("\n=== STEP 1: Remove empty records ===");
var emptyFilter = {$or: [
  {service_key: "", role_name: ""},
  {service_key: {$exists: false}},
  {role_name: {$exists: false}}
]};
var empties = db.user_service_roles.find(emptyFilter).toArray();
print("Empty records found: " + empties.length);
empties.forEach(function(d) { print("  user=" + d.user_id + " svc=" + d.service_key + " role=" + d.role_name); });
if (empties.length > 0) {
  var r = db.user_service_roles.deleteMany(emptyFilter);
  print("Deleted: " + r.deletedCount);
}

// Step 2: Fix "client" to "client-service"
print("\n=== STEP 2: Fix client to client-service ===");
var clientDocs = db.user_service_roles.find({service_key: "client"}).toArray();
print("Records with service_key=client: " + clientDocs.length);
if (clientDocs.length > 0) {
  var r2 = db.user_service_roles.updateMany({service_key: "client"}, {$set: {service_key: "client-service"}});
  print("Updated: " + r2.modifiedCount);
}

// Step 3: Remove orphaned roles
print("\n=== STEP 3: Remove orphaned role assignments ===");
var validRoles = {};
db.service_roles.find().forEach(function(sr) {
  var svc = sr.service_key || sr.service || "";
  var name = sr.name || "";
  if (svc && name) validRoles[svc + ":" + name] = true;
});
print("Valid roles in service_roles: " + Object.keys(validRoles).length);

var orphanIds = [];
db.user_service_roles.find({service_key: {$ne: ""}, role_name: {$ne: ""}}).forEach(function(d) {
  var key = d.service_key + ":" + d.role_name;
  if (!validRoles[key]) {
    print("  ORPHAN: user=" + d.user_id + " " + key);
    orphanIds.push(d._id);
  }
});
print("Orphaned assignments: " + orphanIds.length);
if (orphanIds.length > 0) {
  var r3 = db.user_service_roles.deleteMany({_id: {$in: orphanIds}});
  print("Deleted: " + r3.deletedCount);
}

print("\n=== CLEANUP COMPLETE ===");
print("Remaining records: " + db.user_service_roles.countDocuments());
