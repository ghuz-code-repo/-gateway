package migrations

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Old Role struct (before migration)
type OldRole struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Name        string             `bson:"name"`
	Description string             `bson:"description"`
	Permissions []string           `bson:"permissions"`
}

// New Role struct (after migration)
type NewRole struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	ServiceKey  string             `bson:"service"`
	Name        string             `bson:"name"`
	Description string             `bson:"description"`
	Permissions []string           `bson:"permissions"`
}

// Service struct
type Service struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Key         string             `bson:"key"`
	Name        string             `bson:"name"`
	Description string             `bson:"description"`
	Permissions []string           `bson:"permissions"`
	CreatedAt   time.Time          `bson:"created_at"`
}
