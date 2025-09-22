// Миграция путей аватаров
db.users.updateMany(
  {avatar_path: {$regex: "^/data/.*avatar.jpg$"}},
  [
    {
      $set: {
        avatar_path: {
          $concat: [
            "/avatar/",
            {
              $arrayElemAt: [
                {$split: ["$avatar_path", "/"]},
                2
              ]
            }
          ]
        }
      }
    }
  ]
);

// Проверяем результат
db.users.find({avatar_path: {$regex: "^/avatar/"}}, {_id: 1, name: 1, avatar_path: 1}).pretty();