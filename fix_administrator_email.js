db.users.updateOne(
  {username: 'administrator'},
  {$set: {email: 'admin@goldenhouse.com'}}
)
print("Updated administrator email")
db.users.findOne({username: 'administrator'}, {username: 1, email: 1})
