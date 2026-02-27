package models

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Permission represents a service permission in the system
type Permission struct {
	ID          primitive.ObjectID `bson:"_id" json:"id"`
	Service     string             `bson:"service" json:"service"`
	DisplayName string             `bson:"display_name" json:"display_name"` // Отображаемое имя сервиса
	Icon        string             `bson:"icon" json:"icon"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	DeletedAt   *time.Time         `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"` // Soft delete timestamp
}

// CreatePermission creates a new service permission
func CreatePermission(service string, displayName string) error {
	collection := permsCol
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use service name as display name if none provided
	if displayName == "" {
		displayName = service
	}

	// Check if permission already exists
	var existingPermission Permission
	err := collection.FindOne(ctx, bson.M{"service": service}).Decode(&existingPermission)
	if err == nil {
		// Permission already exists
		return fmt.Errorf("permission already exists for service: %s", service)
	}

	// Create new permission
	permission := Permission{
		ID:          primitive.NewObjectID(),
		Service:     service,
		DisplayName: displayName,
		Icon:        "link", // Default icon
		CreatedAt:   time.Now(),
	}

	_, err = collection.InsertOne(ctx, permission)
	if err != nil {
		return fmt.Errorf("failed to create permission: %v", err)
	}

	return nil
}

// GetPermissionByID returns a permission by its ID
func GetPermissionByID(id primitive.ObjectID) (*Permission, error) {
	collection := permsCol
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var permission Permission
	err := collection.FindOne(ctx, bson.M{"_id": id}).Decode(&permission)
	if err != nil {
		return nil, fmt.Errorf("permission not found: %v", err)
	}

	return &permission, nil
}

// GetPermissionByService returns a permission by its service name
func GetPermissionByService(service string) (*Permission, error) {
	collection := permsCol
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var permission Permission
	err := collection.FindOne(ctx, bson.M{"service": service}).Decode(&permission)
	if err != nil {
		return nil, fmt.Errorf("permission not found: %v", err)
	}

	return &permission, nil
}

// UpdatePermissionDisplayName updates the display name of a permission
func UpdatePermissionDisplayName(id primitive.ObjectID, displayName string) error {
	collection := permsCol
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := collection.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"display_name": displayName}},
	)
	if err != nil {
		return fmt.Errorf("failed to update permission display name: %v", err)
	}

	return nil
}

// GetAllPermissions returns all permissions in the system
func GetAllPermissions() ([]Permission, error) {
	collection := permsCol
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("error finding permissions: %v", err)
	}
	defer cursor.Close(ctx)

	var permissions []Permission
	if err = cursor.All(ctx, &permissions); err != nil {
		return nil, fmt.Errorf("error decoding permissions: %v", err)
	}

	return permissions, nil
}

// DeletePermission deletes a permission by ID
func DeletePermission(id primitive.ObjectID) error {
	collection := permsCol
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete permission: %v", err)
	}

	return nil
}

// contains checks if a slice contains a string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}
