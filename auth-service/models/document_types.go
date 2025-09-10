package models

import (
	"context"
	"sort"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// GetDocumentTypeByID retrieves a document type by its ID
func GetDocumentTypeByID(id string) (*DocumentType, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var docType DocumentType
	err := documentTypesCol.FindOne(ctx, bson.M{"_id": id}).Decode(&docType)
	if err != nil {
		return nil, err
	}

	return &docType, nil
}

// GetAllDocumentTypes retrieves all active document types
func GetAllDocumentTypes() ([]DocumentType, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := documentTypesCol.Find(ctx, bson.M{"is_active": true})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var documentTypes []DocumentType
	err = cursor.All(ctx, &documentTypes)
	if err != nil {
		return nil, err
	}

	// Sort by order field
	sort.Slice(documentTypes, func(i, j int) bool {
		return documentTypes[i].Order < documentTypes[j].Order
	})

	return documentTypes, nil
}

// AddUserDocumentNew adds a new document to a user using the new document system
func AddUserDocumentNew(userID primitive.ObjectID, userDoc UserDocument) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	userDoc.ID = primitive.NewObjectID()
	userDoc.CreatedAt = time.Now()
	userDoc.UpdatedAt = time.Now()

	update := bson.M{
		"$push": bson.M{
			"documents": userDoc,
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	_, err := usersCol.UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}

// UpdateUserDocumentNew updates an existing user document using the new document system
func UpdateUserDocumentNew(userID, docID primitive.ObjectID, fields map[string]interface{}, title string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{
		"$set": bson.M{
			"documents.$.title":      title,
			"documents.$.fields":     fields,
			"documents.$.updated_at": time.Now(),
			"updated_at":             time.Now(),
		},
	}

	_, err := usersCol.UpdateOne(
		ctx,
		bson.M{
			"_id":          userID,
			"documents.id": docID,
		},
		update,
	)
	return err
}

// RemoveUserDocumentNew removes a user document using the new document system
func RemoveUserDocumentNew(userID, docID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{
		"$pull": bson.M{
			"documents": bson.M{"id": docID},
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	_, err := usersCol.UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}
