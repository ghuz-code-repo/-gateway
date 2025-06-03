package models

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Role represents a user role with permissions
type Role struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name        string             `bson:"name" json:"name"`
	Description string             `bson:"description" json:"description"`
	Permissions []string           `bson:"permissions" json:"permissions"`
}

// CreateRole creates a new role
func CreateRole(name, description string, permissions []string) (*Role, error) {
	ctx := context.Background()

	role := &Role{
		Name:        name,
		Description: description,
		Permissions: permissions,
	}

	result, err := rolesCol.InsertOne(ctx, role)
	if err != nil {
		return nil, err
	}

	role.ID = result.InsertedID.(primitive.ObjectID)
	return role, nil
}

// GetAllRoles returns all roles
func GetAllRoles() ([]Role, error) {
	ctx := context.Background()

	cursor, err := rolesCol.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []Role
	if err = cursor.All(ctx, &roles); err != nil {
		return nil, err
	}

	return roles, nil
}

// GetRoleByID retrieves a role by ID
func GetRoleByID(id primitive.ObjectID) (*Role, error) {
	ctx := context.Background()

	var role Role
	err := rolesCol.FindOne(ctx, bson.M{"_id": id}).Decode(&role)
	if err != nil {
		return nil, err
	}

	return &role, nil
}

// UpdateRole updates an existing role
func UpdateRole(id primitive.ObjectID, name, description string, permissions []string) error {
	ctx := context.Background()

	_, err := rolesCol.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{
			"$set": bson.M{
				"name":        name,
				"description": description,
				"permissions": permissions,
			},
		},
	)

	return err
}

// DeleteRole removes a role
func DeleteRole(id primitive.ObjectID) error {
	ctx := context.Background()

	_, err := rolesCol.DeleteOne(ctx, bson.M{"_id": id})
	return err
}

// GetRolesWithPermission returns all roles that use a specific permission
func GetRolesWithPermission(permission string) ([]Role, error) {
	ctx := context.Background()

	cursor, err := rolesCol.Find(ctx, bson.M{"permissions": permission})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []Role
	if err = cursor.All(ctx, &roles); err != nil {
		return nil, err
	}

	return roles, nil
}
