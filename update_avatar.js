db = db.getSiblingDB('authdb');
db.users.updateOne(
  {email: 'admin@example.com'}, 
  {$set: {avatar_path: '/data/avatars/avatar_688216ad279b8a22aabeb269_1757343313.jpg'}}
);
print('Avatar path updated successfully');
