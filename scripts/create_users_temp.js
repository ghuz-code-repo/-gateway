// Temporary script to create MongoDB auth users
// Run via: docker exec gateway-mongo-1 mongosh --quiet /tmp/create_users.js

// 1. Create root admin in admin DB
db = db.getSiblingDB("admin");
try {
  db.createUser({
    user: "mongoadmin",
    pwd: "Ur1Ci0T2D4bOoLbWH36ZwGzRWPaZV1",
    roles: [{ role: "root", db: "admin" }]
  });
  print("Created root user: mongoadmin");
} catch (e) {
  if (e.codeName === "DuplicateKey" || e.code === 51003) {
    print("Root user mongoadmin already exists - OK");
  } else {
    throw e;
  }
}

// 2. Create app user in authdb
db = db.getSiblingDB("authdb");
try {
  db.createUser({
    user: "authservice",
    pwd: "xwIUkbZfspjbUtxZBel4t96A00Kaex",
    roles: [{ role: "readWrite", db: "authdb" }]
  });
  print("Created app user: authservice");
} catch (e) {
  if (e.codeName === "DuplicateKey" || e.code === 51003) {
    print("App user authservice already exists - OK");
  } else {
    throw e;
  }
}

print("DONE: All MongoDB users created.");
