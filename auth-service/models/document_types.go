package models

import (
	"context"
	"fmt"
	"log"
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

	// First, let's see all documents without filter
	allCursor, err := documentTypesCol.Find(ctx, bson.M{})
	if err == nil {
		var allDocs []DocumentType
		allCursor.All(ctx, &allDocs)
		log.Printf("All documents in collection: %d", len(allDocs))
		for _, doc := range allDocs {
			log.Printf("Document: %s, active: %v", doc.Name, doc.IsActive)
		}
		allCursor.Close(ctx)
	}

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

	log.Printf("Found %d active document types", len(documentTypes))

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

// UpdateUserDocumentByIndex updates a user document by its index in the documents array
func UpdateUserDocumentByIndex(userID primitive.ObjectID, docIndex int, fields map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create update fields dynamically
	updateFields := bson.M{
		"updated_at": time.Now(),
	}
	
	// Update each field in the document
	for key, value := range fields {
		updateFields[fmt.Sprintf("documents.%d.fields.%s", docIndex, key)] = value
	}
	
	// Also update the document's updated_at field
	updateFields[fmt.Sprintf("documents.%d.updated_at", docIndex)] = time.Now()

	update := bson.M{
		"$set": updateFields,
	}

	_, err := usersCol.UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}
