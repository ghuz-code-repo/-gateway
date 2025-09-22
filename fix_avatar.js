// Fix avatar path for user
db = db.getSiblingDB('authdb');
db.users.updateOne(
    {username: 'prodgaraj'}, 
    {$set: {avatar_path: '/avatar/68cd3dc2bea57056df2d77de'}}
);
print('Avatar path updated successfully');