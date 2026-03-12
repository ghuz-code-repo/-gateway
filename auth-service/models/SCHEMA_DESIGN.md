# MongoDB Schema Design - Services and Roles

## Overview
This document describes the updated MongoDB schema design for the authentication service, implementing a hierarchical permission system with Services and Roles.

## Collections

### 1. Services Collection
The `services` collection stores the master definition of services and their available permissions.

```go
type Service struct {
    ID          primitive.ObjectID `bson:"_id,omitempty"`
    Key         string             `bson:"key" validate:"required"`     // Unique service identifier (e.g., "referal")
    Name        string             `bson:"name"`                        // Display name
    Description string             `bson:"description"`                 // Service description
    Permissions []string           `bson:"permissions"`                 // Master list of available permissions
    CreatedAt   time.Time          `bson:"created_at"`                  // Creation timestamp
}
```

**Indexes:**
- Unique index on `key` field for fast lookups and ensuring uniqueness

**Example Document:**
```json
{
    "_id": ObjectId("..."),
    "key": "referal",
    "name": "Referral Program",
    "description": "Referral program management service",
    "permissions": ["view", "create", "edit", "delete", "export", "manage_users"],
    "created_at": ISODate("2024-01-01T00:00:00Z")
}
```

### 2. Roles Collection
The `roles` collection defines roles within services, with permissions that are subsets of the service's master permission list.

```go
type Role struct {
    ID          primitive.ObjectID `bson:"_id,omitempty"`
    ServiceKey  string             `bson:"service" validate:"required"` // Reference to service key
    Name        string             `bson:"name" validate:"required"`    // Role name
    Description string             `bson:"description"`                 // Role description
    Permissions []string           `bson:"permissions"`                 // Subset of Service.Permissions
}
```

**Indexes:**
- Compound unique index on `(service, name)` for fast lookups and ensuring uniqueness within a service

**Example Document:**
```json
{
    "_id": ObjectId("..."),
    "service": "referal",
    "name": "manager",
    "description": "Referral program manager",
    "permissions": ["view", "create", "edit", "export"]
}
```

### 3. Users Collection (Existing)
Users reference roles by name, maintaining the existing structure.

```go
type User struct {
    ID       primitive.ObjectID `bson:"_id,omitempty"`
    Username string             `bson:"username"`
    Email    string             `bson:"email"`
    Password string             `bson:"password"`
    Roles    []string           `bson:"roles"`       // Role names
    FullName string             `bson:"full_name"`
}
```

## Default Services

The system creates two default services:

1. **Referral Service (`referal`)**
   - Permissions: `view`, `create`, `edit`, `delete`, `export`, `manage_users`

2. **Calculators Service (`calculators`)**
   - Permissions: `view`, `use`, `create`, `edit`, `delete`, `share`

3. **System Service (`system`)**
   - Special service for system-wide roles like admin
   - Permissions: `admin`, `manage_all`

## Key Features

### 1. Permission Validation
When creating or updating a role, the system validates that all assigned permissions exist in the parent service's permission list.

### 2. Service Isolation
Roles are scoped to services, allowing the same role name (e.g., "viewer") to exist across different services with different permission sets.

### 3. Fast Lookups
The compound index `(service, name)` on the roles collection enables:
- Fast role lookups by service and name
- Uniqueness constraint within a service scope

### 4. Extensibility
New services can be added dynamically with their own permission sets without affecting existing services or roles.

## Migration

A migration script is provided at `migrations/migrate_to_service_roles.go` to help transition from the old schema to the new structure:

1. Creates the services collection with default services
2. Adds the `service` field to existing roles
3. Maps old permissions to the new structure
4. Creates necessary indexes

Run the migration:
```bash
cd auth-service/migrations
go run migrate_to_service_roles.go
```

## API Usage Examples

### Creating a Service
```go
service, err := CreateService(
    "analytics",
    "Analytics Service",
    "Data analytics and reporting",
    []string{"view", "export", "create_report", "schedule"},
)
```

### Creating a Role
```go
role, err := CreateRole(
    "analytics",           // service key
    "analyst",            // role name
    "Data Analyst",       // description
    []string{"view", "export", "create_report"}, // permissions (subset of service permissions)
)
```

### Validating Role Permissions
```go
valid, invalidPerms := ValidateRolePermissions(
    "analytics",
    []string{"view", "export", "invalid_perm"},
)
// valid: false
// invalidPerms: ["invalid_perm"]
```

### Getting Roles for a Service
```go
roles, err := GetRolesByService("referal")
```

### Getting a Role by Service and Name
```go
role, err := GetRoleByServiceAndName("referal", "manager")
```

## Benefits

1. **Clear Hierarchy**: Services define the permission universe, roles select from it
2. **Type Safety**: Validation ensures roles can only have valid permissions
3. **Scalability**: Easy to add new services without affecting existing ones
4. **Performance**: Compound indexes provide fast lookups
5. **Flexibility**: Same role names can exist across different services with different meanings
