package models

import (
	"context"
	"time"
)

// Helper functions for cache and database operations

// GetCacheStats returns current cache statistics
func GetCacheStats() map[string]interface{} {
	if policyCache == nil {
		return map[string]interface{}{
			"cache_enabled": false,
			"message": "Cache not initialized",
		}
	}
	
	stats := policyCache.GetStats()
	stats["cache_enabled"] = true
	return stats
}

// InvalidateServiceCache invalidates cache for a specific service
func InvalidateServiceCache(service string) {
	if policyCache != nil {
		policyCache.InvalidateService(service)
	}
}

// ClearAllCache clears all cache entries
func ClearAllCache() {
	if policyCache != nil {
		policyCache.mutex.Lock()
		defer policyCache.mutex.Unlock()
		
		policyCache.cache = make(map[string]*CacheEntry)
		policyCache.hitCount = 0
		policyCache.missCount = 0
	}
}

// IsDBConnected checks if database connection is active
func IsDBConnected() bool {
	if db == nil {
		return false
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := db.Client().Ping(ctx, nil)
	return err == nil
}

// GetCurrentTimestamp returns current Unix timestamp
func GetCurrentTimestamp() int64 {
	return time.Now().Unix()
}

// InitializePolicySystem initializes the complete policy system
func InitializePolicySystem() error {
	// Initialize cache with default settings
	// TTL: 300 seconds (5 minutes), Max size: 1000 entries
	InitializePolicyCache(300, 1000)
	
	// Initialize default policies for services
	err := InitializeDefaultServicePolicies()
	if err != nil {
		return err
	}
	
	return nil
}
