// Check user avatar path
db = db.getSiblingDB('authdb');
const user = db.users.findOne({username: 'prodgaraj'}, {avatar_path: 1, username: 1});
print('User avatar path:', JSON.stringify(user, null, 2));