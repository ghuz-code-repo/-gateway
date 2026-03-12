package models

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// UserImportExport represents a user record for import/export operations
type UserImportExport struct {
	ID              string            `xlsx:"ID" json:"id,omitempty"`
	Username        string            `xlsx:"Username" json:"username" validate:"required"`
	Email           string            `xlsx:"Email" json:"email" validate:"required,email"`
	FirstName       string            `xlsx:"Имя" json:"first_name"`
	LastName        string            `xlsx:"Фамилия" json:"last_name"`
	MiddleName      string            `xlsx:"Отчество" json:"middle_name"`
	Suffix          string            `xlsx:"Частица" json:"suffix"`
	Department      string            `xlsx:"Отдел" json:"department"`
	Position        string            `xlsx:"Должность" json:"position"`
	Phone           string            `xlsx:"Телефон" json:"phone"`
	Password        string            `xlsx:"Пароль" json:"password,omitempty"`
	Banned          string            `xlsx:"Забанен" json:"banned"`      // "true" or "false"
	DeleteUser      string            `xlsx:"Удалить" json:"delete_user"` // "true" to delete user
	ServiceRoles    map[string]string `json:"service_roles"`
	PasswordChanged bool              `json:"password_changed,omitempty"` // Indicates if password was changed during import
}

// ServiceInfo represents service information for export
type ServiceInfo struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Roles       []string `json:"roles"`
}

// ImportResult represents the result of an import operation
type ImportResult struct {
	ProcessedRows      int                 `json:"processed_rows"`
	CreatedUsers       []UserImportExport  `json:"created_users"`
	UpdatedUsers       []UserImportExport  `json:"updated_users"`
	DeletedUsers       []UserImportExport  `json:"deleted_users"`
	BannedUsers        []UserImportExport  `json:"banned_users"`
	UnbannedUsers      []UserImportExport  `json:"unbanned_users"`
	Errors             []ImportError       `json:"errors"`
	EmailNotifications []EmailNotification `json:"email_notifications"`
}

// ImportError represents an error during import
type ImportError struct {
	Row     int    `json:"row"`
	Field   string `json:"field"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

// ImportLogEntry represents a log entry for import operations
type ImportLogEntry struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Timestamp     time.Time          `bson:"timestamp" json:"timestamp"`
	AdminUsername string             `bson:"admin_username" json:"admin_username"`
	FileName      string             `bson:"file_name" json:"file_name"`
	Success       bool               `bson:"success" json:"success"`
	ErrorMessage  string             `bson:"error_message,omitempty" json:"error_message,omitempty"`
	Result        ImportResult       `bson:"result" json:"result"`
}

// EmailNotification represents an email notification sent during import
type EmailNotification struct {
	RecipientEmail string    `json:"recipient_email"`
	Type           string    `json:"type"`
	Success        bool      `json:"success"`
	ErrorMessage   string    `json:"error_message,omitempty"`
	SentAt         time.Time `json:"sent_at"`
}

// ServiceImportResult represents the result of a service-specific import operation
type ServiceImportResult struct {
	ProcessedRows  int                `json:"processed_rows"`
	CreatedUsers   []UserImportExport `json:"created_users"`
	AddedToService []UserImportExport `json:"added_to_service"`
	UpdatedRoles   []UserImportExport `json:"updated_roles"`
	Errors         []ImportError      `json:"errors"`
}

// ServiceImportLogEntry represents a log entry for service-specific import operations
type ServiceImportLogEntry struct {
	ID            primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	Timestamp     time.Time           `bson:"timestamp" json:"timestamp"`
	AdminUsername string              `bson:"admin_username" json:"admin_username"`
	ServiceKey    string              `bson:"service_key" json:"service_key"`
	ServiceName   string              `bson:"service_name" json:"service_name"`
	FileName      string              `bson:"file_name" json:"file_name"`
	Success       bool                `bson:"success" json:"success"`
	ErrorMessage  string              `bson:"error_message,omitempty" json:"error_message,omitempty"`
	Result        ServiceImportResult `bson:"result" json:"result"`
}

// GetUsersForExport retrieves all users with their roles for export
func GetUsersForExport() ([]UserImportExport, error) {
	users, err := GetAllUsers()
	if err != nil {
		return nil, err
	}

	// Get all services to create service name mapping
	services, err := GetAllServices()
	if err != nil {
		return nil, err
	}

	// Create service key to name mapping
	serviceKeyToName := make(map[string]string)
	for _, service := range services {
		serviceKeyToName[service.Key] = service.Name
	}

	// Batch-load all user service roles in one query (avoids N+1)
	allRolesGrouped, err := GetAllUserServiceRolesGrouped()
	if err != nil {
		log.Printf("Warning: Failed to batch-load service roles for export: %v", err)
		allRolesGrouped = make(map[primitive.ObjectID][]UserServiceRole)
	}

	var exportUsers []UserImportExport
	for _, user := range users {
		bannedStatus := "false"
		if user.IsBanned {
			bannedStatus = "true"
		}

		exportUser := UserImportExport{
			ID:           user.ID.Hex(),
			Username:     user.Username,
			Email:        user.Email,
			FirstName:    user.FirstName,
			LastName:     user.LastName,
			MiddleName:   user.MiddleName,
			Suffix:       user.Suffix,
			Department:   user.Department,
			Position:     user.Position,
			Phone:        user.Phone,
			Banned:       bannedStatus,
			DeleteUser:   "false", // Default value, user sets to "true" to delete
			ServiceRoles: make(map[string]string),
		}

		// Debug logging for empty fields
		if exportUser.Banned == "" || exportUser.DeleteUser == "" {
			log.Printf("DEBUG: User %s export data - Banned: '%s', DeleteUser: '%s', IsBanned: %t",
				user.Username, exportUser.Banned, exportUser.DeleteUser, user.IsBanned)
		}

		// Get user service roles from batch-loaded data
		userRoles := allRolesGrouped[user.ID]
		if len(userRoles) > 0 {
			// Group roles by service key (not name) for consistency with forms
			serviceRolesMap := make(map[string][]string)
			for _, userRole := range userRoles {
				serviceKey := userRole.ServiceKey
				serviceRolesMap[serviceKey] = append(serviceRolesMap[serviceKey], userRole.RoleName)
			}

			// Convert to comma-separated strings
			for serviceKey, roles := range serviceRolesMap {
				exportUser.ServiceRoles[serviceKey] = strings.Join(roles, ",")
			}
		}

		exportUsers = append(exportUsers, exportUser)
		log.Printf("User %s has %d service roles", user.Username, len(exportUser.ServiceRoles))
	}

	return exportUsers, nil
}

// GetServicesForExport retrieves all services with their roles for export reference
func GetServicesForExport() ([]ServiceInfo, error) {
	services, err := GetAllServices()
	if err != nil {
		log.Printf("ERROR: GetAllServices failed: %v", err)
		return nil, err
	}

	log.Printf("DEBUG SERVICES EXPORT: GetAllServices returned %d services", len(services))

	var serviceInfos []ServiceInfo
	for _, service := range services {
		// Get roles for this service
		roles, err := GetRolesByService(service.Key)
		if err != nil {
			log.Printf("Warning: Could not get roles for service %s: %v", service.Key, err)
			roles = []Role{} // Continue with empty roles rather than failing
		}

		roleNames := make([]string, len(roles))
		for i, role := range roles {
			roleNames[i] = role.Name
		}

		serviceInfo := ServiceInfo{
			Key:         service.Key,
			Name:        service.Name,
			Description: service.Description,
			Roles:       roleNames,
		}
		serviceInfos = append(serviceInfos, serviceInfo)
	}

	return serviceInfos, nil
}

// SaveImportLog saves an import operation log to the database
func SaveImportLog(logEntry *ImportLogEntry) error {
	collection := db.Collection("import_logs")
	_, err := collection.InsertOne(context.Background(), logEntry)
	if err != nil {
		log.Printf("Error saving import log: %v", err)
		return err
	}
	return nil
}

// GetImportLogs retrieves import logs with pagination
func GetImportLogs(limit, skip int) ([]ImportLogEntry, error) {
	collection := db.Collection("import_logs")

	// Create find options with sorting (newest first) and pagination
	opts := options.Find()
	opts.SetSort(bson.D{{Key: "timestamp", Value: -1}}) // Sort by timestamp descending (newest first)
	opts.SetLimit(int64(limit))
	opts.SetSkip(int64(skip))

	cursor, err := collection.Find(context.Background(), bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())

	var logs []ImportLogEntry
	for cursor.Next(context.Background()) {
		var log ImportLogEntry
		if err := cursor.Decode(&log); err != nil {
			continue
		}
		logs = append(logs, log)
	}

	return logs, nil
}

// GetImportLogByID retrieves a specific import log by ID
func GetImportLogByID(id string) (*ImportLogEntry, error) {
	collection := db.Collection("import_logs")

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	var log ImportLogEntry
	err = collection.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&log)
	if err != nil {
		return nil, err
	}

	return &log, nil
}

// ValidateUserImportData validates user data for import
func ValidateUserImportData(user *UserImportExport, row int) []ImportError {
	var errors []ImportError

	// Validate required fields
	if strings.TrimSpace(user.Username) == "" {
		errors = append(errors, ImportError{
			Row:     row,
			Field:   "Username",
			Value:   user.Username,
			Message: "Username is required",
		})
	}

	if strings.TrimSpace(user.Email) == "" {
		errors = append(errors, ImportError{
			Row:     row,
			Field:   "Email",
			Value:   user.Email,
			Message: "Email is required",
		})
	}

	// Validate email format (basic check)
	if user.Email != "" && !strings.Contains(user.Email, "@") {
		errors = append(errors, ImportError{
			Row:     row,
			Field:   "Email",
			Value:   user.Email,
			Message: "Invalid email format",
		})
	}

	return errors
}

// LogImportOperation logs the details of an import operation
func LogImportOperation(adminUsername, fileName string, result ImportResult, success bool, errorMessage string) error {
	logEntry := &ImportLogEntry{
		Timestamp:     time.Now(),
		AdminUsername: adminUsername,
		FileName:      fileName,
		Success:       success,
		ErrorMessage:  errorMessage,
		Result:        result,
	}

	return SaveImportLog(logEntry)
}

// NotifyAdminOfImportFailure sends notification to admin about import failure
func NotifyAdminOfImportFailure(adminEmail, fileName, errorMessage string) error {
	// TODO: Implement admin notification logic
	log.Printf("ADMIN NOTIFICATION: Import failed for file %s by %s. Error: %s", fileName, adminEmail, errorMessage)
	return nil
}

// GetUserByUsernameOrEmail finds a user by username or email for import processing
func GetUserByUsernameOrEmail(username, email string) (*User, error) {
	// Try to find by username first
	if user, err := GetUserByUsername(username); err == nil {
		return user, nil
	}

	// Then try by email
	if user, err := GetUserByEmail(email); err == nil {
		return user, nil
	}

	return nil, fmt.Errorf("user not found")
}

// LogServiceImportOperation logs the details of a service-specific import operation
func LogServiceImportOperation(adminUsername, serviceKey, serviceName, fileName string, result ServiceImportResult, success bool, errorMessage string) error {
	logEntry := &ServiceImportLogEntry{
		Timestamp:     time.Now(),
		AdminUsername: adminUsername,
		ServiceKey:    serviceKey,
		ServiceName:   serviceName,
		FileName:      fileName,
		Success:       success,
		ErrorMessage:  errorMessage,
		Result:        result,
	}

	return SaveServiceImportLog(logEntry)
}

// SaveServiceImportLog saves a service import log entry to the database
func SaveServiceImportLog(logEntry *ServiceImportLogEntry) error {
	ctx := context.Background()

	_, err := db.Collection("service_import_logs").InsertOne(ctx, logEntry)
	if err != nil {
		log.Printf("Failed to save service import log: %v", err)
		return err
	}

	log.Printf("Service import log saved successfully for service %s", logEntry.ServiceKey)
	return nil
}

// GetServiceImportLogs retrieves import logs for a specific service
func GetServiceImportLogs(serviceKey string, limit int) ([]ServiceImportLogEntry, error) {
	ctx := context.Background()

	filter := bson.M{}
	if serviceKey != "" {
		filter["service_key"] = serviceKey
	}

	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: -1}})
	if limit > 0 {
		opts.SetLimit(int64(limit))
	}

	cursor, err := db.Collection("service_import_logs").Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []ServiceImportLogEntry
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}

	return logs, nil
}
