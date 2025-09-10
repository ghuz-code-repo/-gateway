use analytics;
db.users.findOne({}, {avatar_path: 1, username: 1});
