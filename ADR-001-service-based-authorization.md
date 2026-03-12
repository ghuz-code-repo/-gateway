# Architecture Decision Record: Service-Based Authorization System

**ADR Number:** ADR-001  
**Date:** 2024  
**Status:** Accepted  
**Deciders:** [Stakeholders to be listed]  
**Technical Story:** Redesign authorization system to support service-scoped roles and permissions

## Context and Problem Statement

The current authorization system lacks proper service isolation and has ambiguous permission management. We need a clearer model where:
- Roles are explicitly tied to services
- Permissions are defined and managed at the service level
- The gateway can efficiently determine user permissions for a specific service

## Decision Drivers

- **Service Isolation:** Need clear boundaries between different services' permissions
- **Simplified Management:** Reduce complexity in permission assignment and management
- **Performance:** Efficient permission resolution at request time
- **Maintainability:** Clear ownership and lifecycle management of permissions

## Decided Solution

### Core Data Model Changes

#### 1. Role Collection Schema
```json
{
  "_id": "ObjectId",
  "name": "string",
  "service": "string",  // NEW: Foreign key to services.key
  "permissions": ["string"],  // Array of permission names (free-form)
  "description": "string",
  "createdAt": "timestamp",
  "updatedAt": "timestamp"
}
```

**Key Changes:**
- Role now owns a `service` field (required, string)
- `service` field contains the unique key of a Service
- `permissions` array remains but references permission names defined in the Service

#### 2. Services Collection Schema (NEW)
```json
{
  "_id": "ObjectId",
  "key": "string",  // Unique identifier (e.g., "user-management", "billing")
  "name": "string",  // Display name
  "description": "string",
  "availablePermissions": [  // Canonical list of permissions for this service
    {
      "name": "string",  // Permission identifier (e.g., "users.read")
      "displayName": "string",  // Human-readable name
      "description": "string"   // Description of what this permission allows
    }
  ],
  "status": "string",  // active, deprecated, disabled
  "createdAt": "timestamp",
  "updatedAt": "timestamp"
}
```

**Purpose:**
- Central registry of all services in the system
- Defines the canonical list of permissions available for each service
- Provides metadata for UI/documentation

#### 3. Permissions Collection (REMOVED)
The separate `permissions` collection will be removed. All permission definitions now live within their respective service documents.

### Gateway Request Headers

At request time, the API Gateway will inject the following headers based on the authenticated user and the target service:

#### Headers Specification
1. **`X-User-Service-Roles`**
   - Contains comma-separated list of role names the user has for the current service
   - Example: `admin,viewer,data-analyst`
   - Empty string if user has no roles for the service

2. **`X-User-Service-Permissions`**
   - Contains comma-separated list of all permissions (union) from the user's roles for the current service
   - Example: `users.read,users.write,users.delete,reports.view`
   - Empty string if user has no permissions for the service
   - Duplicates are removed (set operation)

### CRUD Operations and UI Requirements

The following CRUD operations and UI components must be implemented:

#### 1. Service Management
- **Create Service:** Define new service with its available permissions
- **Read Service:** View service details and permission catalog
- **Update Service:** Modify service metadata and permission list
- **Delete Service:** Soft delete with impact analysis
- **UI:** Service registry dashboard, permission designer

#### 2. Role Management
- **Create Role:** Create role for a specific service with selected permissions
- **Read Role:** View role details and assigned permissions
- **Update Role:** Modify role permissions and metadata
- **Delete Role:** Remove role with user impact notification
- **UI:** Role management interface with service filtering

#### 3. Permission Management (within Service)
- **Add Permission:** Add new permission to service's available permissions
- **Update Permission:** Modify permission metadata (name changes require migration)
- **Remove Permission:** Soft delete with impact analysis on existing roles
- **UI:** Permission editor within service management interface

## Edge Cases and Error Handling

### 1. Deleted Service
**Scenario:** A service is deleted but roles still reference it.

**Handling:**
- Implement soft delete for services (status: "deleted")
- Existing roles remain but are marked as "orphaned"
- Gateway returns empty permissions for deleted services
- UI shows warning for roles with deleted services
- Provide migration tool to reassign or clean up orphaned roles

### 2. Duplicate Permission Names
**Scenario:** Multiple permissions with the same name within a service.

**Handling:**
- Enforce unique constraint on permission names within a service's `availablePermissions`
- Allow same permission name across different services (namespaced by service)
- Validation at service update time to prevent duplicates

### 3. Permission Removed from Service
**Scenario:** A permission is removed from a service but roles still reference it.

**Handling:**
- Soft delete permissions (add `deletedAt` field)
- Roles keep the permission reference but it's marked as "deprecated"
- Gateway ignores deprecated permissions (not included in headers)
- UI shows warning for roles with deprecated permissions
- Provide cleanup tool to remove deprecated permissions from roles

### 4. Role References Non-existent Permission
**Scenario:** Role has a permission that doesn't exist in the service's available permissions.

**Handling:**
- Validation at role creation/update time
- Gateway ignores unknown permissions (defensive programming)
- Audit log for permission mismatches
- UI shows validation errors

### 5. Service Key Changes
**Scenario:** A service's unique key needs to be changed.

**Handling:**
- Service keys are immutable once created
- If change is absolutely necessary, implement migration process:
  1. Create new service with new key
  2. Migrate all roles to new service
  3. Update gateway configuration
  4. Deprecate old service

### 6. Circular or Conflicting Permissions
**Scenario:** Permissions that logically conflict with each other.

**Handling:**
- No system-level enforcement (business logic responsibility)
- Documentation of permission best practices
- Optional permission validation rules at service level

### 7. Performance at Scale
**Scenario:** User has many roles with many permissions.

**Handling:**
- Cache permission resolution at gateway level
- Implement permission aggregation service
- Set reasonable limits on:
  - Permissions per role: 100
  - Roles per user per service: 10
  - Header size limits (8KB typical)

### 8. Missing Service for New Role
**Scenario:** Attempting to create a role without specifying a service.

**Handling:**
- Service field is required and validated
- API returns 400 Bad Request with clear error message
- UI enforces service selection before role creation

## Migration Strategy

### Phase 1: Preparation
1. Create `services` collection with all existing services
2. Populate `availablePermissions` from existing permissions
3. Add `service` field to existing roles (nullable initially)

### Phase 2: Migration
1. Map existing roles to appropriate services
2. Validate all role permissions against service permissions
3. Generate migration report for conflicts

### Phase 3: Cutover
1. Make `service` field required on roles
2. Update gateway to use new header format
3. Remove old `permissions` collection
4. Deploy new UI components

### Phase 4: Cleanup
1. Remove deprecated fields
2. Archive migration data
3. Update documentation

## Consequences

### Positive
- Clear service boundaries for authorization
- Simplified permission management per service
- Better auditability and traceability
- Improved performance through service-scoped queries
- Cleaner API for downstream services

### Negative
- Migration complexity for existing systems
- Additional complexity in role creation (must select service)
- Potential for orphaned roles if services are deleted
- Header size increase (two headers instead of one)

### Neutral
- Learning curve for administrators
- Need for comprehensive documentation
- Regular maintenance of service/permission registry

## Compliance and Security Considerations

1. **Audit Logging:** All changes to services, roles, and permissions must be logged
2. **Data Retention:** Soft deletes maintain audit trail
3. **Access Control:** Service management requires elevated privileges
4. **Validation:** Strict validation of permissions at multiple layers
5. **Backward Compatibility:** Maintain old headers during migration period

## Implementation Checklist

- [ ] Database schema updates
- [ ] Service registry implementation
- [ ] Role service field implementation
- [ ] Permission management within services
- [ ] Gateway header injection logic
- [ ] CRUD APIs for all entities
- [ ] UI components for all management interfaces
- [ ] Migration scripts and tools
- [ ] Performance testing
- [ ] Security review
- [ ] Documentation update
- [ ] Training materials

## References

- Previous authorization system documentation
- Service mesh authorization patterns
- RBAC best practices
- API Gateway documentation

## Decision

We will proceed with this service-based authorization model as described, with implementation beginning immediately after stakeholder approval.

## Sign-off

**Stakeholders:**
- [ ] Engineering Lead: ___________________ Date: ___________
- [ ] Product Manager: ___________________ Date: ___________
- [ ] Security Team: ____________________ Date: ___________
- [ ] DevOps Lead: _____________________ Date: ___________
- [ ] Frontend Lead: ____________________ Date: ___________

---

**Next Steps:**
1. Review and approve this ADR
2. Create detailed technical specifications
3. Set up project tracking and milestones
4. Begin Phase 1 implementation
