# Service-Specific Excel Import/Export Implementation

## Overview
Implemented service-specific import/export functionality for service administrators with restricted permissions.

## New Features

### 1. Service-Specific Excel Export
- **Route**: `GET /service/{serviceKey}/export`
- **Permission**: Service administrators only
- **Functionality**: Exports users belonging to a specific service
- **File Format**: Excel (.xlsx) with service-specific columns

### 2. Service-Specific Excel Import
- **Route**: `POST /service/{serviceKey}/import` 
- **Permission**: Service administrators only
- **Functionality**: Imports users with service-scoped restrictions
- **Business Rules**:
  - Service admins can only create new users or manage users within their service
  - Cannot modify users from other services
  - Can set roles only within their service scope

### 3. Service Import Page
- **Route**: `GET /service/{serviceKey}/import`
- **Template**: `service_import.html`
- **Features**:
  - Service-specific import instructions
  - File upload interface
  - Import history display
  - Service information panel

### 4. Service Import Logs
- **Route**: `GET /service/{serviceKey}/import/logs`
- **Returns**: JSON with recent import operations for the service
- **Features**: Tracks success/failure, user counts, error details

## Implementation Details

### Files Created/Modified:
1. **New**: `handlers/service_excel_import_export.go` - Core import/export logic
2. **New**: `templates/service_import.html` - Service import UI
3. **Modified**: `routes/routes.go` - New route definitions
4. **Modified**: `routes/user_management.go` - Route handlers
5. **Modified**: `models/import_export.go` - Service import models

### Key Models:
- `ServiceImportResult` - Results structure for service imports
- `ServiceImportLogEntry` - Logging structure for service operations

### Access Control:
- Uses existing role system (`admin` role required)
- Service-scoped permissions (admins can only manage their service)
- Proper authentication and authorization checks

## Usage Instructions

### For Service Administrators:

1. **Export Users**:
   - Navigate to `/service/{your-service-key}/export`
   - Downloads Excel file with current service users

2. **Import Users**:
   - Go to `/service/{your-service-key}/import`
   - Download template using "Скачать шаблон" button
   - Fill in user data (new users need username, email, password)
   - Upload completed file
   - Review import results

3. **View Import History**:
   - Import logs are displayed on the import page
   - Shows success/failure status and user counts

## Technical Notes

### Limitations (Current Implementation):
- Service-specific role management is simplified
- User role updates for existing users are skipped
- Basic email validation only
- No complex service role hierarchy

### Future Enhancements:
- Implement full service-specific role management
- Add user role update capabilities
- Enhanced validation and error handling
- Bulk operations for existing users
- More granular permission controls

## Security Features

1. **Authentication**: Required for all operations
2. **Authorization**: Service admin role verification
3. **Service Scoping**: Admins restricted to their service only
4. **Input Validation**: File type and content validation
5. **Audit Logging**: All operations logged with details

## Error Handling

- Comprehensive error messages for users
- Detailed logging for administrators
- Graceful handling of file format issues
- Service access validation
- Import operation result tracking

This implementation provides a solid foundation for service-scoped user management while maintaining security and proper access controls.