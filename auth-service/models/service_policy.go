package models

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ServiceRole represents a role specific to a service with permissions
type ServiceRole struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Service     string             `bson:"service" json:"service"`
	Name        string             `bson:"name" json:"name"`
	DisplayName string             `bson:"display_name" json:"display_name"`
	Permissions []string           `bson:"permissions" json:"permissions"`
	CreatedBy   string             `bson:"created_by" json:"created_by"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
	IsActive    bool               `bson:"is_active" json:"is_active"`
}

// ServicePermission represents a specific permission for a service
type ServicePermission struct {
	ID          string    `bson:"_id" json:"id"`
	Service     string    `bson:"service" json:"service"`
	Resource    string    `bson:"resource" json:"resource"`
	Action      string    `bson:"action" json:"action"`
	Scope       string    `bson:"scope" json:"scope"`
	Description string    `bson:"description" json:"description"`
	UIElement   string    `bson:"ui_element,omitempty" json:"ui_element,omitempty"`
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`
	IsActive    bool      `bson:"is_active" json:"is_active"`
}

// PolicyEvaluationRequest represents a request to evaluate access policy
type PolicyEvaluationRequest struct {
	Service   string                 `json:"service"`
	UserRoles []string               `json:"user_roles"`
	Resource  string                 `json:"resource"`
	Action    string                 `json:"action"`
	Scope     string                 `json:"scope,omitempty"`
	Context   map[string]interface{} `json:"context,omitempty"`
}

// PolicyEvaluationResponse represents the response of policy evaluation
type PolicyEvaluationResponse struct {
	Allowed     bool                   `json:"allowed"`
	Reason      string                 `json:"reason"`
	Permissions []string               `json:"permissions,omitempty"`
	UIElements  map[string]bool        `json:"ui_elements,omitempty"`
	CacheKey    string                 `json:"cache_key,omitempty"`
}

// PolicyCache represents an in-memory cache for policy decisions
type PolicyCache struct {
	cache    map[string]*CacheEntry
	mutex    sync.RWMutex
	ttl      time.Duration
	maxSize  int
	hitCount int64
	missCount int64
}

// CacheEntry represents a cached policy decision
type CacheEntry struct {
	Response  *PolicyEvaluationResponse
	ExpiresAt time.Time
	AccessCount int64
}

// Global policy cache instance
var policyCache *PolicyCache

// InitializePolicyCache initializes the global policy cache
func InitializePolicyCache(ttlSeconds int, maxSize int) {
	policyCache = &PolicyCache{
		cache:   make(map[string]*CacheEntry),
		ttl:     time.Duration(ttlSeconds) * time.Second,
		maxSize: maxSize,
	}
	
	// Start cleanup routine
	go policyCache.cleanupRoutine()
}

// cleanupRoutine periodically cleans up expired cache entries
func (pc *PolicyCache) cleanupRoutine() {
	ticker := time.NewTicker(time.Minute * 5) // Clean every 5 minutes
	defer ticker.Stop()
	
	for range ticker.C {
		pc.cleanup()
	}
}

// cleanup removes expired entries and enforces size limits
func (pc *PolicyCache) cleanup() {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()
	
	now := time.Now()
	
	// Remove expired entries
	for key, entry := range pc.cache {
		if now.After(entry.ExpiresAt) {
			delete(pc.cache, key)
		}
	}
	
	// Enforce size limit by removing least accessed entries
	if len(pc.cache) > pc.maxSize {
		// Convert to slice for sorting
		type cacheItem struct {
			key   string
			entry *CacheEntry
		}
		
		items := make([]cacheItem, 0, len(pc.cache))
		for k, v := range pc.cache {
			items = append(items, cacheItem{key: k, entry: v})
		}
		
		// Remove entries with lowest access count
		itemsToRemove := len(pc.cache) - pc.maxSize
		for i := 0; i < itemsToRemove; i++ {
			minIdx := 0
			minCount := items[0].entry.AccessCount
			
			for j, item := range items {
				if item.entry.AccessCount < minCount {
					minIdx = j
					minCount = item.entry.AccessCount
				}
			}
			
			delete(pc.cache, items[minIdx].key)
			items = append(items[:minIdx], items[minIdx+1:]...)
		}
	}
}

// Get retrieves a cached policy decision
func (pc *PolicyCache) Get(key string) (*PolicyEvaluationResponse, bool) {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()
	
	entry, exists := pc.cache[key]
	if !exists {
		pc.missCount++
		return nil, false
	}
	
	if time.Now().After(entry.ExpiresAt) {
		pc.missCount++
		return nil, false
	}
	
	entry.AccessCount++
	pc.hitCount++
	return entry.Response, true
}

// Set stores a policy decision in cache
func (pc *PolicyCache) Set(key string, response *PolicyEvaluationResponse) {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()
	
	pc.cache[key] = &CacheEntry{
		Response:    response,
		ExpiresAt:   time.Now().Add(pc.ttl),
		AccessCount: 1,
	}
}

// InvalidateService removes all cache entries for a specific service
func (pc *PolicyCache) InvalidateService(service string) {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()
	
	for key := range pc.cache {
		if pc.keyMatchesService(key, service) {
			delete(pc.cache, key)
		}
	}
}

// keyMatchesService checks if a cache key belongs to a specific service
func (pc *PolicyCache) keyMatchesService(key, service string) bool {
	// Cache keys format: "service:user_roles:resource:action:scope"
	return len(key) > len(service) && key[:len(service)] == service && key[len(service)] == ':'
}

// GetStats returns cache statistics
func (pc *PolicyCache) GetStats() map[string]interface{} {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()
	
	totalRequests := pc.hitCount + pc.missCount
	hitRate := float64(0)
	if totalRequests > 0 {
		hitRate = float64(pc.hitCount) / float64(totalRequests) * 100
	}
	
	return map[string]interface{}{
		"cache_size":      len(pc.cache),
		"max_size":        pc.maxSize,
		"hit_count":       pc.hitCount,
		"miss_count":      pc.missCount,
		"hit_rate":        hitRate,
		"ttl_seconds":     int(pc.ttl.Seconds()),
	}
}

// CreateServiceRole creates a new service role
func CreateServiceRole(role *ServiceRole) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	role.ID = primitive.NewObjectID()
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()
	role.IsActive = true

	collection := db.Collection("service_roles")
	_, err := collection.InsertOne(ctx, role)
	
	if err == nil {
		// Invalidate cache for this service
		if policyCache != nil {
			policyCache.InvalidateService(role.Service)
		}
	}
	
	return err
}

// GetServiceRoles retrieves all roles for a specific service
func GetServiceRoles(service string) ([]ServiceRole, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := db.Collection("service_roles")
	filter := bson.M{"service": service, "is_active": true}

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []ServiceRole
	err = cursor.All(ctx, &roles)
	return roles, err
}

// UpdateServiceRole updates an existing service role
func UpdateServiceRole(roleID string, role *ServiceRole) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return err
	}

	role.UpdatedAt = time.Now()
	filter := bson.M{"_id": objID}
	update := bson.M{"$set": role}

	collection := db.Collection("service_roles")
	_, err = collection.UpdateOne(ctx, filter, update)
	
	if err == nil {
		// Invalidate cache for this service
		if policyCache != nil {
			policyCache.InvalidateService(role.Service)
		}
	}
	
	return err
}

// DeleteServiceRole soft deletes a service role
func DeleteServiceRole(roleID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": objID}
	update := bson.M{"$set": bson.M{"is_active": false, "updated_at": time.Now()}}

	collection := db.Collection("service_roles")
	result, err := collection.UpdateOne(ctx, filter, update)
	
	if err == nil && result.ModifiedCount > 0 {
		// Get the role to invalidate cache for the correct service
		var role ServiceRole
		collection.FindOne(ctx, filter).Decode(&role)
		if policyCache != nil {
			policyCache.InvalidateService(role.Service)
		}
	}
	
	return err
}

// CreateServicePermission creates a new service permission
func CreateServicePermission(permission *ServicePermission) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Generate ID from service.resource.action.scope
	permission.ID = fmt.Sprintf("%s.%s.%s", permission.Service, permission.Resource, permission.Action)
	if permission.Scope != "" && permission.Scope != "all" {
		permission.ID += "." + permission.Scope
	}
	
	permission.CreatedAt = time.Now()
	permission.IsActive = true

	collection := db.Collection("service_permissions")
	_, err := collection.InsertOne(ctx, permission)
	
	if err == nil {
		// Invalidate cache for this service
		if policyCache != nil {
			policyCache.InvalidateService(permission.Service)
		}
	}
	
	return err
}

// GetServicePermissions retrieves all permissions for a specific service
func GetServicePermissions(service string) ([]ServicePermission, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := db.Collection("service_permissions")
	filter := bson.M{"service": service, "is_active": true}

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var permissions []ServicePermission
	err = cursor.All(ctx, &permissions)
	return permissions, err
}

// EvaluatePolicy evaluates access policy for a user request
func EvaluatePolicy(req *PolicyEvaluationRequest) (*PolicyEvaluationResponse, error) {
	// Generate cache key
	cacheKey := generateCacheKey(req)
	
	// Check cache first
	if policyCache != nil {
		if cached, hit := policyCache.Get(cacheKey); hit {
			cached.CacheKey = cacheKey
			return cached, nil
		}
	}
	
	// Perform actual policy evaluation
	response, err := evaluatePolicyFromDB(req)
	if err != nil {
		return nil, err
	}
	
	response.CacheKey = cacheKey
	
	// Cache the result
	if policyCache != nil {
		policyCache.Set(cacheKey, response)
	}
	
	return response, nil
}

// generateCacheKey creates a cache key from the evaluation request
func generateCacheKey(req *PolicyEvaluationRequest) string {
	// Format: "service:roles:resource:action:scope"
	rolesJSON, _ := json.Marshal(req.UserRoles)
	return fmt.Sprintf("%s:%s:%s:%s:%s", 
		req.Service, 
		string(rolesJSON), 
		req.Resource, 
		req.Action, 
		req.Scope)
}

// evaluatePolicyFromDB performs the actual policy evaluation against the database
func evaluatePolicyFromDB(req *PolicyEvaluationRequest) (*PolicyEvaluationResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get all service roles for user roles
	collection := db.Collection("service_roles")
	filter := bson.M{
		"service":   req.Service,
		"name":      bson.M{"$in": req.UserRoles},
		"is_active": true,
	}

	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return &PolicyEvaluationResponse{
			Allowed: false,
			Reason:  "Database error: " + err.Error(),
		}, nil
	}
	defer cursor.Close(ctx)

	var roles []ServiceRole
	err = cursor.All(ctx, &roles)
	if err != nil {
		return &PolicyEvaluationResponse{
			Allowed: false,
			Reason:  "Failed to decode roles",
		}, nil
	}

	if len(roles) == 0 {
		return &PolicyEvaluationResponse{
			Allowed: false,
			Reason:  "No matching roles found for user",
		}, nil
	}

	// Collect all permissions from user roles
	allPermissions := make(map[string]bool)
	for _, role := range roles {
		for _, perm := range role.Permissions {
			allPermissions[perm] = true
		}
	}

	// Build required permission ID
	requiredPermission := fmt.Sprintf("%s.%s.%s", req.Service, req.Resource, req.Action)
	if req.Scope != "" && req.Scope != "all" {
		requiredPermission += "." + req.Scope
	}

	// Check if user has the required permission
	if allPermissions[requiredPermission] {
		return &PolicyEvaluationResponse{
			Allowed:     true,
			Reason:      fmt.Sprintf("User has permission: %s", requiredPermission),
			Permissions: getPermissionsList(allPermissions),
		}, nil
	}

	// Check for wildcard permissions
	wildcardPermission := fmt.Sprintf("%s.%s.*", req.Service, req.Resource)
	if allPermissions[wildcardPermission] {
		return &PolicyEvaluationResponse{
			Allowed:     true,
			Reason:      fmt.Sprintf("User has wildcard permission: %s", wildcardPermission),
			Permissions: getPermissionsList(allPermissions),
		}, nil
	}

	// Check for admin wildcard
	adminPermission := fmt.Sprintf("%s.*", req.Service)
	if allPermissions[adminPermission] {
		return &PolicyEvaluationResponse{
			Allowed:     true,
			Reason:      fmt.Sprintf("User has admin permission: %s", adminPermission),
			Permissions: getPermissionsList(allPermissions),
		}, nil
	}

	return &PolicyEvaluationResponse{
		Allowed:     false,
		Reason:      fmt.Sprintf("Missing required permission: %s", requiredPermission),
		Permissions: getPermissionsList(allPermissions),
	}, nil
}

// getPermissionsList converts permission map to slice
func getPermissionsList(permissions map[string]bool) []string {
	var perms []string
	for perm := range permissions {
		perms = append(perms, perm)
	}
	return perms
}

// InitializeDefaultServicePolicies creates default roles and permissions for services
func InitializeDefaultServicePolicies() error {
	// Initialize default permissions for referal service
	referalPermissions := []ServicePermission{
		{
			Service:     "referal",
			Resource:    "dashboard",
			Action:      "view",
			Scope:       "all",
			Description: "Просмотр главной страницы",
		},
		{
			Service:     "referal",
			Resource:    "referals",
			Action:      "view",
			Scope:       "own",
			Description: "Просмотр собственных рефералов",
		},
		{
			Service:     "referal",
			Resource:    "referals",
			Action:      "create",
			Scope:       "own",
			Description: "Создание рефералов",
		},
		{
			Service:     "referal",
			Resource:    "referals",
			Action:      "manage",
			Scope:       "all",
			Description: "Управление всеми рефералами",
		},
		{
			Service:     "referal",
			Resource:    "users",
			Action:      "manage",
			Scope:       "all",
			Description: "Управление пользователями",
		},
		{
			Service:     "referal",
			Resource:    "reports",
			Action:      "view",
			Scope:       "all",
			Description: "Просмотр отчетов",
		},
		{
			Service:     "referal",
			Resource:    "admin",
			Action:      "access",
			Scope:       "all",
			Description: "Доступ к админ панели",
		},
	}

	// Create permissions
	for _, perm := range referalPermissions {
		CreateServicePermission(&perm)
	}

	// Initialize default roles for referal service
	referalRoles := []ServiceRole{
		{
			Service:     "referal",
			Name:        "user",
			DisplayName: "Пользователь",
			Permissions: []string{
				"referal.dashboard.view",
				"referal.referals.view.own",
				"referal.referals.create.own",
			},
			CreatedBy: "system",
		},
		{
			Service:     "referal",
			Name:        "admin",
			DisplayName: "Администратор",
			Permissions: []string{
				"referal.*",
			},
			CreatedBy: "system",
		},
		{
			Service:     "referal",
			Name:        "manager",
			DisplayName: "Менеджер",
			Permissions: []string{
				"referal.dashboard.view",
				"referal.referals.view.all",
				"referal.referals.manage.all",
				"referal.reports.view.all",
			},
			CreatedBy: "system",
		},
	}

	// Create roles
	for _, role := range referalRoles {
		CreateServiceRole(&role)
	}

	return nil
}
