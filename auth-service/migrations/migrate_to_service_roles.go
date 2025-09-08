package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

func main() {
	// MongoDB connection string - update as needed
	mongoURI := "mongodb://localhost:27017"
	dbName := "authdb"

	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	defer client.Disconnect(ctx)

	// Ping to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		log.Fatal("Failed to ping MongoDB:", err)
	}

	log.Println("Connected to MongoDB successfully")

	db := client.Database(dbName)
	rolesCol := db.Collection("roles")
	servicesCol := db.Collection("services")

	// Step 1: Create services collection with default services
	log.Println("Step 1: Creating services...")
	if err := createDefaultServices(servicesCol); err != nil {
		log.Printf("Warning: Failed to create services: %v", err)
	}

	// Step 2: Create system service for admin and other system-wide roles
	log.Println("Step 2: Creating system service...")
	systemService := Service{
		Key:         "system",
		Name:        "System",
		Description: "System-wide service for administrative roles",
		Permissions: []string{"admin", "manage_all"},
		CreatedAt:   time.Now(),
	}
	_, err = servicesCol.UpdateOne(
		ctx,
		bson.M{"key": "system"},
		bson.M{"$setOnInsert": systemService},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		log.Printf("Warning: Failed to create system service: %v", err)
	}

	// Step 3: Migrate existing roles
	log.Println("Step 3: Migrating existing roles...")
	cursor, err := rolesCol.Find(ctx, bson.M{})
	if err != nil {
		log.Fatal("Failed to fetch existing roles:", err)
	}
	defer cursor.Close(ctx)

	var rolesToMigrate []OldRole
	if err := cursor.All(ctx, &rolesToMigrate); err != nil {
		log.Fatal("Failed to decode roles:", err)
	}

	log.Printf("Found %d roles to migrate", len(rolesToMigrate))

	for _, oldRole := range rolesToMigrate {
		// Check if role already has service field
		var checkRole bson.M
		err := rolesCol.FindOne(ctx, bson.M{"_id": oldRole.ID}).Decode(&checkRole)
		if err != nil {
			continue
		}

		if _, hasService := checkRole["service"]; hasService {
			log.Printf("Role '%s' already has service field, skipping", oldRole.Name)
			continue
		}

		// Determine service key based on role name and permissions
		serviceKey := determineServiceKey(oldRole.Name, oldRole.Permissions)
		
		// Map permissions to new structure
		newPermissions := mapPermissions(serviceKey, oldRole.Permissions)

		// Update role with new structure
		update := bson.M{
			"$set": bson.M{
				"service":     serviceKey,
				"permissions": newPermissions,
			},
		}

		result, err := rolesCol.UpdateOne(ctx, bson.M{"_id": oldRole.ID}, update)
		if err != nil {
			log.Printf("Failed to migrate role '%s': %v", oldRole.Name, err)
			continue
		}

		if result.ModifiedCount > 0 {
			log.Printf("Successfully migrated role '%s' to service '%s'", oldRole.Name, serviceKey)
		}
	}

	// Step 4: Create compound index for roles
	log.Println("Step 4: Creating compound index for roles...")
	indexModel := mongo.IndexModel{
		Keys: bson.D{
			{"service", 1},
			{"name", 1},
		},
		Options: options.Index().SetUnique(true),
	}
	_, err = rolesCol.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		log.Printf("Warning: Failed to create compound index: %v", err)
	}

	// Step 5: Create unique index for services
	log.Println("Step 5: Creating unique index for services...")
	serviceIndexModel := mongo.IndexModel{
		Keys:    bson.D{{"key", 1}},
		Options: options.Index().SetUnique(true),
	}
	_, err = servicesCol.Indexes().CreateOne(ctx, serviceIndexModel)
	if err != nil {
		log.Printf("Warning: Failed to create service index: %v", err)
	}

	log.Println("Migration completed successfully!")
}

func createDefaultServices(servicesCol *mongo.Collection) error {
	ctx := context.Background()

	defaultServices := []Service{
		{
			Key:         "referal",
			Name:        "Referral Program",
			Description: "Referral program management service",
			Permissions: []string{"view", "create", "edit", "delete", "export", "manage_users"},
			CreatedAt:   time.Now(),
		},
		{
			Key:         "calculators",
			Name:        "Calculators",
			Description: "Calculator tools service",
			Permissions: []string{"view", "use", "create", "edit", "delete", "share"},
			CreatedAt:   time.Now(),
		},
	}

	for _, service := range defaultServices {
		_, err := servicesCol.UpdateOne(
			ctx,
			bson.M{"key": service.Key},
			bson.M{"$setOnInsert": service},
			options.Update().SetUpsert(true),
		)
		if err != nil {
			return err
		}
		log.Printf("Created/verified service: %s", service.Key)
	}

	return nil
}

func determineServiceKey(roleName string, permissions []string) string {
	// Admin roles go to system service
	if roleName == "admin" || roleName == "administrator" {
		return "system"
	}

	// Check if permissions indicate a specific service
	for _, perm := range permissions {
		if perm == "referal" || perm == "referral" {
			return "referal"
		}
		if perm == "calculators" || perm == "calculator" {
			return "calculators"
		}
	}

	// Default to system service for unidentified roles
	return "system"
}

func mapPermissions(serviceKey string, oldPermissions []string) []string {
	// If it's a system role with service-level permissions,
	// we keep them as is (they represent access to services)
	if serviceKey == "system" {
		return oldPermissions
	}

	// For service-specific roles, map to appropriate permissions
	switch serviceKey {
	case "referal":
		// Convert service names to actual permissions
		newPerms := []string{}
		for _, perm := range oldPermissions {
			if perm == "referal" || perm == "referral" {
				// Give full permissions for backward compatibility
				newPerms = append(newPerms, "view", "create", "edit", "delete")
			}
		}
		if len(newPerms) == 0 {
			// Default permissions
			newPerms = []string{"view"}
		}
		return newPerms

	case "calculators":
		newPerms := []string{}
		for _, perm := range oldPermissions {
			if perm == "calculators" || perm == "calculator" {
				// Give full permissions for backward compatibility
				newPerms = append(newPerms, "view", "use", "create", "edit")
			}
		}
		if len(newPerms) == 0 {
			// Default permissions
			newPerms = []string{"view", "use"}
		}
		return newPerms

	default:
		// Keep original permissions for system roles
		return oldPermissions
	}
}
