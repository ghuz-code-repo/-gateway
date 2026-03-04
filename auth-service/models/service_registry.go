package models

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

// ServiceInstance represents a running instance of a service
type ServiceInstance struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ServiceKey      string             `bson:"service_key" json:"service_key" validate:"required"`   // Links to Service.Key
	ContainerName   string             `bson:"container_name" json:"container_name"`                 // Docker container name
	InternalURL     string             `bson:"internal_url" json:"internal_url" validate:"required"` // e.g., "http://referal:80"
	ExternalPrefix  string             `bson:"external_prefix" json:"external_prefix"`               // e.g., "/referal" (from Service.Key)
	HealthCheckPath string             `bson:"health_check_path" json:"health_check_path"`           // e.g., "/health"
	Status          string             `bson:"status" json:"status"`                                 // "active", "unhealthy", "stopped"
	RegisteredAt    time.Time          `bson:"registered_at" json:"registered_at"`
	LastHeartbeat   time.Time          `bson:"last_heartbeat" json:"last_heartbeat"`
	Metadata        map[string]string  `bson:"metadata,omitempty" json:"metadata,omitempty"` // Additional service info
}

// RegisterServiceInstance registers a new service instance in the registry
func RegisterServiceInstance(serviceKey, containerName, internalURL, healthCheckPath string, metadata map[string]string) (*ServiceInstance, error) {
	// Verify that the service exists in the services collection
	service, err := GetServiceByKey(serviceKey)
	if err != nil {
		return nil, fmt.Errorf("service %s not found in services collection: %v", serviceKey, err)
	}

	collection := db.Collection("service_instances")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	now := time.Now()
	instance := &ServiceInstance{
		ServiceKey:      serviceKey,
		ContainerName:   containerName,
		InternalURL:     internalURL,
		ExternalPrefix:  "/" + service.Key, // Use service key as prefix
		HealthCheckPath: healthCheckPath,
		Status:          "active",
		RegisteredAt:    now,
		LastHeartbeat:   now,
		Metadata:        metadata,
	}

	// Check if instance already registered (by container name or internal URL)
	filter := bson.M{
		"$or": []bson.M{
			{"container_name": containerName},
			{"internal_url": internalURL},
		},
	}

	var existing ServiceInstance
	err = collection.FindOne(ctx, filter).Decode(&existing)
	if err == nil {
		// Instance already exists, update it
		update := bson.M{
			"$set": bson.M{
				"service_key":       serviceKey,
				"health_check_path": healthCheckPath,
				"status":            "active",
				"last_heartbeat":    now,
				"metadata":          metadata,
			},
		}
		_, err = collection.UpdateOne(ctx, filter, update)
		if err != nil {
			return nil, fmt.Errorf("failed to update existing instance: %v", err)
		}
		existing.ServiceKey = serviceKey
		existing.HealthCheckPath = healthCheckPath
		existing.Status = "active"
		existing.LastHeartbeat = now
		existing.Metadata = metadata
		log.Printf("Updated existing service instance: %s (%s)", serviceKey, containerName)
		return &existing, nil
	} else if err != mongo.ErrNoDocuments {
		return nil, fmt.Errorf("error checking for existing instance: %v", err)
	}

	// Insert new instance
	result, err := collection.InsertOne(ctx, instance)
	if err != nil {
		return nil, fmt.Errorf("failed to register service instance: %v", err)
	}

	instance.ID = result.InsertedID.(primitive.ObjectID)
	log.Printf("Registered new service instance: %s (%s) at %s", serviceKey, containerName, internalURL)
	return instance, nil
}

// UnregisterServiceInstance removes a service instance from the registry
func UnregisterServiceInstance(serviceKey, containerName string) error {
	collection := db.Collection("service_instances")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{
		"service_key":    serviceKey,
		"container_name": containerName,
	}

	result, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to unregister service instance: %v", err)
	}

	if result.DeletedCount == 0 {
		log.Printf("Warning: No instance found to unregister: %s (%s)", serviceKey, containerName)
	} else {
		log.Printf("Unregistered service instance: %s (%s)", serviceKey, containerName)
	}

	return nil
}

// UpdateHeartbeat updates the last heartbeat time for a service instance
func UpdateHeartbeat(serviceKey, containerName string) error {
	collection := db.Collection("service_instances")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"service_key":    serviceKey,
		"container_name": containerName,
	}

	update := bson.M{
		"$set": bson.M{
			"last_heartbeat": time.Now(),
			"status":         "active",
		},
	}

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update heartbeat: %v", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("no instance found to update: %s (%s)", serviceKey, containerName)
	}

	return nil
}

// GetActiveServiceInstances returns all active service instances
func GetActiveServiceInstances() ([]ServiceInstance, error) {
	collection := db.Collection("service_instances")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{"status": "active"}
	opts := options.Find().SetSort(bson.D{{Key: "service_key", Value: 1}})

	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch active instances: %v", err)
	}
	defer cursor.Close(ctx)

	var instances []ServiceInstance
	if err = cursor.All(ctx, &instances); err != nil {
		return nil, fmt.Errorf("failed to decode instances: %v", err)
	}

	return instances, nil
}

// GetAllServiceInstances returns ALL service instances regardless of status.
// Used by nginx config generation to keep routes alive even for unhealthy services.
func GetAllServiceInstances() ([]ServiceInstance, error) {
	collection := db.Collection("service_instances")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.D{{Key: "service_key", Value: 1}})

	cursor, err := collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch all instances: %v", err)
	}
	defer cursor.Close(ctx)

	var instances []ServiceInstance
	if err = cursor.All(ctx, &instances); err != nil {
		return nil, fmt.Errorf("failed to decode instances: %v", err)
	}

	return instances, nil
}

// GetServiceInstancesByKey returns all instances for a specific service
func GetServiceInstancesByKey(serviceKey string) ([]ServiceInstance, error) {
	collection := db.Collection("service_instances")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{"service_key": serviceKey}
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch instances for service %s: %v", serviceKey, err)
	}
	defer cursor.Close(ctx)

	var instances []ServiceInstance
	if err = cursor.All(ctx, &instances); err != nil {
		return nil, fmt.Errorf("failed to decode instances: %v", err)
	}

	return instances, nil
}

// MarkUnhealthyInstances marks instances as unhealthy if they haven't sent heartbeat
func MarkUnhealthyInstances(timeout time.Duration) error {
	collection := db.Collection("service_instances")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	threshold := time.Now().Add(-timeout)
	filter := bson.M{
		"last_heartbeat": bson.M{"$lt": threshold},
		"status":         "active",
	}

	update := bson.M{
		"$set": bson.M{
			"status": "unhealthy",
		},
	}

	result, err := collection.UpdateMany(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to mark unhealthy instances: %v", err)
	}

	if result.ModifiedCount > 0 {
		log.Printf("Marked %d instances as unhealthy (no heartbeat for %v)", result.ModifiedCount, timeout)
	}

	return nil
}

// CleanupOldInstances removes instances that have been unhealthy for too long
func CleanupOldInstances(unhealthyFor time.Duration) error {
	collection := db.Collection("service_instances")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	threshold := time.Now().Add(-unhealthyFor)
	filter := bson.M{
		"last_heartbeat": bson.M{"$lt": threshold},
		"status":         "unhealthy",
	}

	result, err := collection.DeleteMany(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to cleanup old instances: %v", err)
	}

	if result.DeletedCount > 0 {
		log.Printf("Cleaned up %d old unhealthy instances", result.DeletedCount)
	}

	return nil
}
