package routes

import (
	"log"
	"net/http"
	"time"

	"auth-service/models"

	"github.com/gin-gonic/gin"
)

// RegisterServiceInstanceRequest represents the request to register a service
type RegisterServiceInstanceRequest struct {
	ServiceKey      string            `json:"service_key" binding:"required"`
	ContainerName   string            `json:"container_name"`
	InternalURL     string            `json:"internal_url" binding:"required"`
	HealthCheckPath string            `json:"health_check_path"`
	Metadata        map[string]string `json:"metadata"`
}

// registerServiceInstanceHandler handles POST /api/registry/register
func registerServiceInstanceHandler(c *gin.Context) {
	var req RegisterServiceInstanceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Default health check path
	if req.HealthCheckPath == "" {
		req.HealthCheckPath = "/health"
	}

	instance, err := models.RegisterServiceInstance(
		req.ServiceKey,
		req.ContainerName,
		req.InternalURL,
		req.HealthCheckPath,
		req.Metadata,
	)
	if err != nil {
		log.Printf("Failed to register service instance: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Trigger nginx config regeneration
	if err := regenerateNginxConfig(); err != nil {
		log.Printf("Warning: Failed to regenerate nginx config: %v", err)
		// Don't fail the request, just log the warning
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Service instance registered successfully",
		"instance": instance,
	})
}

// unregisterServiceInstanceHandler handles DELETE /api/registry/unregister/:serviceKey
func unregisterServiceInstanceHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")
	containerName := c.Query("container_name")

	if serviceKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "service_key is required"})
		return
	}

	err := models.UnregisterServiceInstance(serviceKey, containerName)
	if err != nil {
		log.Printf("Failed to unregister service instance: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Trigger nginx config regeneration
	if err := regenerateNginxConfig(); err != nil {
		log.Printf("Warning: Failed to regenerate nginx config: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Service instance unregistered successfully"})
}

// heartbeatHandler handles POST /api/registry/heartbeat
func heartbeatHandler(c *gin.Context) {
	var req struct {
		ServiceKey    string `json:"service_key" binding:"required"`
		ContainerName string `json:"container_name"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := models.UpdateHeartbeat(req.ServiceKey, req.ContainerName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Heartbeat updated"})
}

// listServiceInstancesHandler handles GET /api/registry/services
func listServiceInstancesHandler(c *gin.Context) {
	instances, err := models.GetActiveServiceInstances()
	if err != nil {
		log.Printf("Failed to fetch service instances: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"services": instances,
		"count":    len(instances),
	})
}

// getServiceInstancesHandler handles GET /api/registry/services/:serviceKey
func getServiceInstancesHandler(c *gin.Context) {
	serviceKey := c.Param("serviceKey")

	instances, err := models.GetServiceInstancesByKey(serviceKey)
	if err != nil {
		log.Printf("Failed to fetch instances for service %s: %v", serviceKey, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"service_key": serviceKey,
		"instances":   instances,
		"count":       len(instances),
	})
}

// startHealthCheckMonitor starts a background goroutine to monitor service health
func startHealthCheckMonitor() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			// Mark instances as unhealthy if no heartbeat for 2 minutes
			if err := models.MarkUnhealthyInstances(2 * time.Minute); err != nil {
				log.Printf("Error marking unhealthy instances: %v", err)
			}

			// Cleanup instances that have been unhealthy for 10 minutes
			if err := models.CleanupOldInstances(10 * time.Minute); err != nil {
				log.Printf("Error cleaning up old instances: %v", err)
			}
		}
	}()

	log.Println("Started service health check monitor")
}

// ServiceHealthStatus represents the health status of a service
type ServiceHealthStatus struct {
	ServiceKey      string    `json:"service_key"`
	ServiceName     string    `json:"service_name"`
	ExternalPrefix  string    `json:"external_prefix"`
	Status          string    `json:"status"`           // "healthy", "unhealthy", "offline"
	LastHeartbeat   time.Time `json:"last_heartbeat"`
	HasActiveInstance bool    `json:"has_active_instance"`
	HealthCheckURL  string    `json:"health_check_url,omitempty"`
}

// getServicesHealthHandler handles GET /api/services/health
// Returns health status for all services (for admin panel cards)
func getServicesHealthHandler(c *gin.Context) {
	// Get all services from database (not deleted)
	services, err := models.GetAllServices()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch services"})
		return
	}

	// Get active instances
	instances, err := models.GetActiveServiceInstances()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch instances"})
		return
	}

	// Build instance map
	instanceMap := make(map[string]*models.ServiceInstance)
	for i := range instances {
		instanceMap[instances[i].ServiceKey] = &instances[i]
	}

	// Build health status for each service
	var healthStatuses []ServiceHealthStatus
	for _, service := range services {
		if service.Status == "deleted" {
			continue
		}

		// Build external prefix from service key
		externalPrefix := "/" + service.Key
		
		status := ServiceHealthStatus{
			ServiceKey:        service.Key,
			ServiceName:       service.Name,
			ExternalPrefix:    externalPrefix,
			HasActiveInstance: false,
			Status:            "offline", // default
		}

		// Check if service has active instance
		if instance, exists := instanceMap[service.Key]; exists {
			status.HasActiveInstance = true
			status.LastHeartbeat = instance.LastHeartbeat
			status.HealthCheckURL = instance.HealthCheckPath
			status.ExternalPrefix = instance.ExternalPrefix // Use from instance if available

			// Determine status based on instance status and last heartbeat
			timeSinceHeartbeat := time.Since(instance.LastHeartbeat)
			
			if instance.Status == "active" && timeSinceHeartbeat < 1*time.Minute {
				status.Status = "healthy" // Green
			} else if instance.Status == "active" && timeSinceHeartbeat < 2*time.Minute {
				status.Status = "unhealthy" // Yellow - registered but heartbeat is stale
			} else {
				status.Status = "offline" // Red - no recent heartbeat or inactive
			}
		}

		healthStatuses = append(healthStatuses, status)
	}

	c.JSON(http.StatusOK, gin.H{
		"services": healthStatuses,
		"count":    len(healthStatuses),
	})
}
