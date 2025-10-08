package migrations

import (
	"auth-service/models"
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// MigrateDocumentsToServicesField migrates existing documents to include allowed_services field
func MigrateDocumentsToServicesField(db *mongo.Database) error {
	log.Println("Starting migration: adding allowed_services field to existing documents...")
	
	collection := db.Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get all services
	servicesCollection := db.Collection("services")
	cursor, err := servicesCollection.Find(ctx, bson.M{})
	if err != nil {
		return fmt.Errorf("failed to get services: %v", err)
	}
	defer cursor.Close(ctx)

	var services []models.Service
	if err = cursor.All(ctx, &services); err != nil {
		return fmt.Errorf("failed to decode services: %v", err)
	}

	// Get all service keys
	var allServiceKeys []string
	for _, service := range services {
		allServiceKeys = append(allServiceKeys, service.Key)
	}

	log.Printf("Found %d services: %v", len(allServiceKeys), allServiceKeys)

	// Find all users with documents
	userCursor, err := collection.Find(ctx, bson.M{"documents": bson.M{"$exists": true, "$ne": nil}})
	if err != nil {
		return fmt.Errorf("failed to find users with documents: %v", err)
	}
	defer userCursor.Close(ctx)

	updateCount := 0
	userCount := 0

	for userCursor.Next(ctx) {
		var user models.User
		if err := userCursor.Decode(&user); err != nil {
			log.Printf("Failed to decode user: %v", err)
			continue
		}

		userCount++
		userNeedsUpdate := false

		// Group documents by type to determine first documents
		documentTypeMap := make(map[string]int) // type -> index of first document
		
		for i, doc := range user.Documents {
			// Check if document needs migration
			if doc.AllowedServices == nil || len(doc.AllowedServices) == 0 {
				// Determine if this is the first document of this type
				_, exists := documentTypeMap[doc.DocumentType]
				if !exists {
					// This is the first document of this type
					documentTypeMap[doc.DocumentType] = i
					// Assign all services to first document
					user.Documents[i].AllowedServices = allServiceKeys
					log.Printf("Assigning all services to first %s document for user %s", doc.DocumentType, user.Username)
				} else {
					// This is not the first document of this type
					// Leave empty for user to configure manually
					user.Documents[i].AllowedServices = []string{}
					log.Printf("Leaving %s document at index %d for user %s without services (user will configure manually)", doc.DocumentType, i, user.Username)
				}
				userNeedsUpdate = true
			}
		}

		// Update user if any documents were modified
		if userNeedsUpdate {
			filter := bson.M{"_id": user.ID}
			update := bson.M{
				"$set": bson.M{
					"documents":  user.Documents,
					"updated_at": time.Now(),
				},
			}

			result, err := collection.UpdateOne(ctx, filter, update)
			if err != nil {
				log.Printf("Failed to update user %s: %v", user.Username, err)
				continue
			}

			if result.ModifiedCount > 0 {
				updateCount++
				log.Printf("Updated documents for user %s", user.Username)
			}
		}
	}

	log.Printf("Migration completed: %d out of %d users updated", updateCount, userCount)
	return nil
}