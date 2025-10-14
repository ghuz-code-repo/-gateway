package models

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/xuri/excelize/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var (
	client              *mongo.Client
	db                  *mongo.Database
	usersCol            *mongo.Collection
	rolesCol            *mongo.Collection
	serviceRolesCol     *mongo.Collection
	permsCol            *mongo.Collection
	servicesCol         *mongo.Collection
	userServiceRolesCol *mongo.Collection
	documentTypesCol    *mongo.Collection
)

// DocumentType represents a document type configuration
type DocumentType struct {
	ID            string            `bson:"_id" json:"id"`
	Name          string            `bson:"name" json:"name"`
	Description   string            `bson:"description" json:"description"`
	DocumentGroup string            `bson:"document_group" json:"document_group"`
	Fields        []DocumentField   `bson:"fields" json:"fields"`
	IsActive      bool              `bson:"is_active" json:"is_active"`
	Order         int               `bson:"order" json:"order"`
	CreatedAt     time.Time         `bson:"created_at" json:"created_at"`
	UpdatedAt     time.Time         `bson:"updated_at" json:"updated_at"`
}

// DocumentField represents a field in a document type
type DocumentField struct {
	ID           string                 `bson:"id" json:"id"`
	Name         string                 `bson:"name,omitempty" json:"name,omitempty"`
	Label        string                 `bson:"label" json:"label"`
	Type         string                 `bson:"type" json:"type"` // text, number, date, select, textarea
	Required     bool                   `bson:"required" json:"required"`
	Options      []string               `bson:"options,omitempty" json:"options,omitempty"` // for select fields
	Validation   map[string]interface{} `bson:"validation,omitempty" json:"validation,omitempty"`
	Placeholder  string                 `bson:"placeholder,omitempty" json:"placeholder,omitempty"`
	MaxLength    int                    `bson:"maxlength,omitempty" json:"maxlength,omitempty"`
	Format       *FieldFormat           `bson:"format,omitempty" json:"format,omitempty"` // formatting configuration
}

// FieldFormat represents formatting configuration for a field
type FieldFormat struct {
	Mask         string `bson:"mask,omitempty" json:"mask,omitempty"`                   // input mask like "9999 999999"
	Pattern      string `bson:"pattern,omitempty" json:"pattern,omitempty"`             // regex pattern for validation
	Transform    string `bson:"transform,omitempty" json:"transform,omitempty"`         // uppercase, lowercase, capitalize
	Separator    string `bson:"separator,omitempty" json:"separator,omitempty"`         // separator character for grouping
	GroupSize    int    `bson:"group_size,omitempty" json:"group_size,omitempty"`       // size of each group
	Prefix       string `bson:"prefix,omitempty" json:"prefix,omitempty"`               // prefix text
	Suffix       string `bson:"suffix,omitempty" json:"suffix,omitempty"`               // suffix text
	DecimalPlaces int   `bson:"decimal_places,omitempty" json:"decimal_places,omitempty"` // for number fields
}

// DocumentAttachment represents an attached file to a document
type DocumentAttachment struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	FileName     string             `bson:"file_name" json:"file_name"`
	OriginalName string             `bson:"original_name" json:"original_name"`
	FilePath     string             `bson:"file_path" json:"file_path"`
	ContentType  string             `bson:"content_type" json:"content_type"`
	Size         int64              `bson:"size" json:"size"`
	UploadedAt   time.Time          `bson:"uploaded_at" json:"uploaded_at"`
}

// UserDocument represents a user document with dynamic fields
type UserDocument struct {
	ID             primitive.ObjectID           `bson:"_id,omitempty" json:"id"`
	DocumentType   string                      `bson:"document_type" json:"document_type"`
	Title          string                       `bson:"title" json:"title"`
	Fields         map[string]interface{}       `bson:"fields" json:"fields"`
	Attachments    []DocumentAttachment         `bson:"attachments" json:"attachments"`
	AllowedServices []string                    `bson:"allowed_services" json:"allowed_services"` // Services where this document can be used
	Status         string                       `bson:"status" json:"status"` // draft, completed, archived
	CreatedAt      time.Time                    `bson:"created_at" json:"created_at"`
	UpdatedAt      time.Time                    `bson:"updated_at" json:"updated_at"`
}

// Document represents a user document (legacy - will be replaced by UserDocument)
type Document struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	FileName    string             `bson:"file_name" json:"file_name"`
	OriginalName string            `bson:"original_name" json:"original_name"`
	FilePath    string             `bson:"file_path" json:"file_path"`
	ContentType string             `bson:"content_type" json:"content_type"`
	Size        int64              `bson:"size" json:"size"`
	UploadedAt  time.Time          `bson:"uploaded_at" json:"uploaded_at"`
}

// CropCoords represents the crop coordinates for avatar
type CropCoords struct {
	X      float64 `bson:"x" json:"x"`           // X position relative to original image (0-1)
	Y      float64 `bson:"y" json:"y"`           // Y position relative to original image (0-1)  
	Width  float64 `bson:"width" json:"width"`   // Width relative to original image (0-1)
	Height float64 `bson:"height" json:"height"` // Height relative to original image (0-1)
}

// User struct represents a user in the system
type User struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username   string             `bson:"username" json:"username"`
	Email      string             `bson:"email" json:"email"`
	Password   string             `bson:"password" json:"-"`          // Never return password in JSON
	Roles      []string           `bson:"roles" json:"roles"`         // Store role names
	
	// Separated name fields
	LastName   string             `bson:"last_name,omitempty" json:"last_name,omitempty"`     // Фамилия
	FirstName  string             `bson:"first_name,omitempty" json:"first_name,omitempty"`   // Имя
	MiddleName string             `bson:"middle_name,omitempty" json:"middle_name,omitempty"` // Отчество
	Suffix     string             `bson:"suffix,omitempty" json:"suffix,omitempty"`           // Суффикс (Jr., Sr., III и т.д.)
	
	// Legacy field for backward compatibility
	FullName   string             `bson:"full_name,omitempty" json:"full_name,omitempty"`
	
	Phone      string             `bson:"phone,omitempty" json:"phone,omitempty"`
	Position   string             `bson:"position,omitempty" json:"position,omitempty"`
	Department string             `bson:"department,omitempty" json:"department,omitempty"`
	AvatarPath string             `bson:"avatar_path,omitempty" json:"avatar_path,omitempty"`
	OriginalAvatarPath string     `bson:"original_avatar_path,omitempty" json:"original_avatar_path,omitempty"`
	CropCoordinates    *CropCoords `bson:"crop_coordinates,omitempty" json:"crop_coordinates,omitempty"`
	
	// Passport and personal data
	PassportNumber      string     `bson:"passport_number,omitempty" json:"passport_number,omitempty"`
	PassportIssuedBy    string     `bson:"passport_issued_by,omitempty" json:"passport_issued_by,omitempty"`
	PassportIssuedDate  *time.Time `bson:"passport_issued_date,omitempty" json:"passport_issued_date,omitempty"`
	Address             string     `bson:"address,omitempty" json:"address,omitempty"`
	BirthDate           *time.Time `bson:"birth_date,omitempty" json:"birth_date,omitempty"`
	
	Documents  []UserDocument     `bson:"documents,omitempty" json:"documents,omitempty"`      // New document system
	LegacyDocs []Document         `bson:"legacy_docs,omitempty" json:"legacy_docs,omitempty"` // Legacy documents
	IsBanned   bool               `bson:"is_banned,omitempty" json:"is_banned,omitempty"`     // User ban status
	BannedAt   *time.Time         `bson:"banned_at,omitempty" json:"banned_at,omitempty"`     // When user was banned
	BanReason  string             `bson:"ban_reason,omitempty" json:"ban_reason,omitempty"`   // Reason for ban
	CreatedAt  time.Time          `bson:"created_at,omitempty" json:"created_at,omitempty"`
	UpdatedAt  time.Time          `bson:"updated_at,omitempty" json:"updated_at,omitempty"`
}

// GetFullName returns the complete full name with suffix
func (u *User) GetFullName() string {
	var parts []string
	
	if u.LastName != "" {
		parts = append(parts, u.LastName)
	}
	if u.FirstName != "" {
		parts = append(parts, u.FirstName)
	}
	if u.MiddleName != "" {
		parts = append(parts, u.MiddleName)
	}
	if u.Suffix != "" {
		parts = append(parts, u.Suffix)
	}
	
	if len(parts) > 0 {
		return strings.Join(parts, " ")
	}
	
	// Fallback to legacy field if new fields are empty
	return u.FullName
}

// GetShortName returns "Фамилия И. О." format
func (u *User) GetShortName() string {
	if u.LastName == "" {
		// Fallback to legacy field or username
		if u.FullName != "" {
			return u.FullName
		}
		return u.Username
	}
	
	var parts []string
	parts = append(parts, u.LastName)
	
	if u.FirstName != "" {
		parts = append(parts, string([]rune(u.FirstName)[0])+".")
	}
	
	if u.MiddleName != "" {
		parts = append(parts, string([]rune(u.MiddleName)[0])+".")
	}
	
	return strings.Join(parts, " ")
}

// GetDisplayName returns full name for cards, short name for lists
func (u *User) GetDisplayName(isCard bool) string {
	if isCard {
		return u.GetFullName()
	}
	return u.GetShortName()
}

// UserServiceRole represents a user's role assignment in a specific service
type UserServiceRole struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id" validate:"required"`
	ServiceKey string            `bson:"service_key" json:"service_key" validate:"required"`
	RoleName   string            `bson:"role_name" json:"role_name" validate:"required"`
	AssignedAt time.Time         `bson:"assigned_at" json:"assigned_at"`
	AssignedBy primitive.ObjectID `bson:"assigned_by,omitempty" json:"assigned_by,omitempty"`
	IsActive   bool              `bson:"is_active" json:"is_active"`
}

// UserWithServiceRoles represents a user with their roles in a specific service
type UserWithServiceRoles struct {
	User
	ServiceRoles []string `json:"service_roles"`
}

// Claims struct for JWT
type Claims struct {
	Username string `json:"username"`
	UserID   string `json:"user_id"`
	jwt.StandardClaims
}

// GenerateSecurePassword generates a secure password with specified requirements
// Length 10-16 characters, including uppercase, lowercase, digits and special characters
func GenerateSecurePassword() string {
	const (
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		special   = "!@#$%^&*()_+-=[]{}|;:,.<>?"
		allChars  = lowercase + uppercase + digits + special
	)

	// Generate random length between 10-16
	length, _ := rand.Int(rand.Reader, big.NewInt(7)) // 0-6
	passwordLength := int(length.Int64()) + 10        // 10-16

	password := make([]byte, passwordLength)

	// Ensure at least one character from each category
	categories := []string{lowercase, uppercase, digits, special}
	for i, category := range categories {
		charIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(category))))
		password[i] = category[charIndex.Int64()]
	}

	// Fill the rest with random characters
	for i := 4; i < passwordLength; i++ {
		charIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(allChars))))
		password[i] = allChars[charIndex.Int64()]
	}

	// Shuffle the password
	for i := len(password) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		password[i], password[j.Int64()] = password[j.Int64()], password[i]
	}

	return string(password)
}

// InitDB initializes MongoDB connection and collections
func InitDB(uri, dbName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var err error
	client, err = mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return err
	}

	// Ping to verify connection
	err = client.Ping(ctx, nil)
	if err != nil {
		return err
	}

	// Initialize the database
	db = client.Database(dbName)

	// Initialize collections AFTER db is set
	usersCol = db.Collection("users")
	rolesCol = db.Collection("roles")
	serviceRolesCol = db.Collection("service_roles")
	permsCol = db.Collection("permissions")
	servicesCol = db.Collection("services")
	userServiceRolesCol = db.Collection("user_service_roles")
	documentTypesCol = db.Collection("document_types")

	// Create indexes for unique fields
	_, err = usersCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"username", 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("Warning: Failed to create username index: %v", err)
	}
	// Create compound index for roles (service, name) for uniqueness and fast lookup
	// First, try to drop old name index if it exists
	rolesCol.Indexes().DropOne(ctx, "name_1")
	
	_, err = rolesCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{"service", 1},
			{"name", 1},
		},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("Warning: Failed to create role compound index (service, name): %v", err)
	}
	_, err = permsCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"service", 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("Warning: Failed to create permission service index: %v", err)
	}
	
	// Create unique index for services collection on key field
	_, err = servicesCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"key", 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("Warning: Failed to create service key index: %v", err)
	}

	// Create compound unique index for user_service_roles (user_id, service_key, role_name)
	_, err = userServiceRolesCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{"user_id", 1},
			{"service_key", 1},
			{"role_name", 1},
		},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("Warning: Failed to create user_service_roles compound index: %v", err)
	}

	// Create index on user_id for fast lookups
	_, err = userServiceRolesCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{"user_id", 1}},
	})
	if err != nil {
		log.Printf("Warning: Failed to create user_service_roles user_id index: %v", err)
	}

	// Create unique index for document_types collection
	_, err = documentTypesCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"id", 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("Warning: Failed to create document_types id index: %v", err)
	}

	// Create default services
	if err := CreateDefaultServices(); err != nil {
		log.Printf("Warning: Failed to create default services: %v", err)
	}

	// Create default permissions
	CreateDefaultPermissions()

	// Create default document types
	if err := CreateDefaultDocumentTypes(); err != nil {
		log.Printf("Warning: Failed to create default document types: %v", err)
	}

	return nil
}

// GetDatabase returns the database instance for use in migrations
func GetDatabase() *mongo.Database {
	return db
}

// CreateDefaultPermissions creates default permissions for services
func CreateDefaultPermissions() {
	ctx := context.Background()
	services := []string{"calculators", "referal"} // Add "referal" to the default services

	log.Println("Creating default permissions for services:", services)

	for _, service := range services {
		result, err := permsCol.UpdateOne(
			ctx,
			bson.M{"service": service},
			bson.M{"$setOnInsert": bson.M{"service": service}},
			options.Update().SetUpsert(true),
		)
		if err != nil {
			log.Printf("Warning: Failed to insert permission for service %s: %v", service, err)
		} else if result.UpsertedCount > 0 {
			log.Printf("Created permission for service: %s", service)
		}
	}

	// Ensure admin role has access to all services
	updateAdminPermissions(services)
}

// updateAdminPermissions ensures the admin role has access to all services
func updateAdminPermissions(services []string) {
	ctx := context.Background()

	// Find admin role
	var adminRole Role
	err := rolesCol.FindOne(ctx, bson.M{"name": "admin"}).Decode(&adminRole)
	if err != nil {
		log.Printf("Warning: Failed to find admin role: %v", err)
		return
	}

	// Update admin role permissions to include all services
	_, err = rolesCol.UpdateOne(
		ctx,
		bson.M{"name": "admin"},
		bson.M{"$set": bson.M{"permissions": services}},
	)
	if err != nil {
		log.Printf("Warning: Failed to update admin role permissions: %v", err)
	} else {
		log.Printf("Updated admin role with all service permissions")
	}
}

// EnsureAdminExists creates an admin user and role if no system administrators exist
func EnsureAdminExists() {
	ctx := context.Background()

	// Create default permissions if needed
	CreateDefaultPermissions()

	// Ensure admin role (system-wide role) exists
	var adminRole Role
	err := rolesCol.FindOne(ctx, bson.M{"service": "system", "name": "admin"}).Decode(&adminRole)
	if err == mongo.ErrNoDocuments {
		// Create admin role
		adminRole = Role{
			ServiceKey:  "system",
			Name:        "admin",
			Description: "System Administrator",
			Permissions: []string{},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		// Get all permissions
		cursor, err := permsCol.Find(ctx, bson.M{})
		if err != nil {
			log.Printf("Warning: Failed to fetch permissions: %v", err)
		} else {
			var perms []Permission
			if err = cursor.All(ctx, &perms); err == nil {
				for _, p := range perms {
					adminRole.Permissions = append(adminRole.Permissions, p.Service)
				}
			}
			cursor.Close(ctx)
		}

		result, err := rolesCol.InsertOne(ctx, adminRole)
		if err != nil {
			log.Printf("Warning: Failed to create admin role: %v", err)
		} else {
			log.Println("Created system admin role with all permissions")
			adminRole.ID = result.InsertedID.(primitive.ObjectID)
		}
	}

	// Always ensure admin role has all current permissions
	if err == nil {
		// Update admin role with all permissions
		cursor, err := permsCol.Find(ctx, bson.M{})
		if err == nil {
			var perms []Permission
			if err = cursor.All(ctx, &perms); err == nil {
				permServices := []string{}
				for _, p := range perms {
					permServices = append(permServices, p.Service)
				}

				if len(permServices) > 0 {
					_, err = rolesCol.UpdateOne(
						ctx,
						bson.M{"service": "system", "name": "admin"},
						bson.M{"$set": bson.M{
							"permissions": permServices,
							"updatedAt":   time.Now(),
						}},
					)
					if err != nil {
						log.Printf("Warning: Failed to update admin role permissions: %v", err)
					}
				}
			}
			cursor.Close(ctx)
		}
	}

	// Check if any system administrators exist
	var systemAdminsCount int64
	systemAdminsCount, err = usersCol.CountDocuments(ctx, bson.M{"roles": "admin"})
	if err != nil {
		log.Printf("Warning: Failed to count system administrators: %v", err)
		systemAdminsCount = 0
	}

	// Only create default admin user if no system administrators exist
	if systemAdminsCount == 0 {
		log.Println("No system administrators found, creating default admin user")
		
		// Create default admin user with password "admin"
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Warning: Failed to hash password: %v", err)
			return
		}

		adminUser := User{
			Username:  "admin",
			Email:     "d.tolkunov@gh.uz",
			Password:  string(hashedPassword),
			Roles:     []string{"admin"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		_, err = usersCol.InsertOne(ctx, adminUser)
		if err != nil {
			log.Printf("Warning: Failed to create default admin user: %v", err)
			return
		}

		log.Println("Created default admin user with username: admin, password: admin")
	} else {
		log.Printf("Found %d system administrator(s), no need to create default admin", systemAdminsCount)
	}
}

// CreateDefaultDocumentTypes creates default document types
func CreateDefaultDocumentTypes() error {
	ctx := context.Background()
	
	documentTypes := []DocumentType{
		{
			ID:          "passport",
			Name:        "Паспорт",
			Description: "Паспорт гражданина РФ",
			IsActive:    true,
			Order:       1,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Fields: []DocumentField{
				{
					Name:        "series",
					Label:       "Серия",
					Type:        "text",
					Required:    true,
					Placeholder: "1234",
					Validation: map[string]interface{}{
						"maxLength": 4,
						"pattern":   "^[0-9]{4}$",
					},
				},
				{
					Name:        "number",
					Label:       "Номер",
					Type:        "text",
					Required:    true,
					Placeholder: "123456",
					Validation: map[string]interface{}{
						"maxLength": 6,
						"pattern":   "^[0-9]{6}$",
					},
				},
				{
					Name:        "issued_by",
					Label:       "Кем выдан",
					Type:        "textarea",
					Required:    true,
					Placeholder: "УМВД России по городу Москве",
				},
				{
					Name:        "issue_date",
					Label:       "Дата выдачи",
					Type:        "date",
					Required:    true,
				},
				{
					Name:        "birth_place",
					Label:       "Место рождения",
					Type:        "text",
					Required:    false,
					Placeholder: "г. Москва",
				},
			},
		},
		{
			ID:          "contract",
			Name:        "Трудовой договор",
			Description: "Трудовой договор сотрудника",
			IsActive:    true,
			Order:       2,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Fields: []DocumentField{
				{
					Name:        "contract_number",
					Label:       "Номер договора",
					Type:        "text",
					Required:    true,
					Placeholder: "ТД-001/2024",
				},
				{
					Name:        "start_date",
					Label:       "Дата начала работы",
					Type:        "date",
					Required:    true,
				},
				{
					Name:        "position",
					Label:       "Должность",
					Type:        "text",
					Required:    true,
					Placeholder: "Менеджер по продажам",
				},
				{
					Name:        "department",
					Label:       "Отдел",
					Type:        "text",
					Required:    false,
					Placeholder: "Отдел продаж",
				},
				{
					Name:        "salary",
					Label:       "Оклад (руб.)",
					Type:        "number",
					Required:    false,
					Placeholder: "50000",
				},
			},
		},
		{
			ID:          "education",
			Name:        "Документ об образовании",
			Description: "Диплом, аттестат или иной документ об образовании",
			IsActive:    true,
			Order:       3,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Fields: []DocumentField{
				{
					Name:     "document_type",
					Label:    "Тип документа",
					Type:     "select",
					Required: true,
					Options:  []string{"Диплом ВУЗ", "Диплом колледж", "Аттестат", "Сертификат", "Удостоверение"},
				},
				{
					Name:        "institution",
					Label:       "Учебное заведение",
					Type:        "text",
					Required:    true,
					Placeholder: "Московский государственный университет",
				},
				{
					Name:        "specialization",
					Label:       "Специальность/направление",
					Type:        "text",
					Required:    false,
					Placeholder: "Экономика и управление",
				},
				{
					Name:        "graduation_year",
					Label:       "Год окончания",
					Type:        "number",
					Required:    true,
					Placeholder: "2020",
					Validation: map[string]interface{}{
						"min": 1950,
						"max": time.Now().Year() + 10,
					},
				},
			},
		},
		{
			ID:          "medical",
			Name:        "Медицинская справка",
			Description: "Медицинские документы и справки",
			IsActive:    true,
			Order:       4,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Fields: []DocumentField{
				{
					Name:     "medical_type",
					Label:    "Тип медицинского документа",
					Type:     "select",
					Required: true,
					Options:  []string{"Справка 086/у", "Медицинская книжка", "Справка о прививках", "Справка о состоянии здоровья", "Другое"},
				},
				{
					Name:        "clinic_name",
					Label:       "Медицинское учреждение",
					Type:        "text",
					Required:    true,
					Placeholder: "Городская поликлиника №1",
				},
				{
					Name:        "issue_date",
					Label:       "Дата выдачи",
					Type:        "date",
					Required:    true,
				},
				{
					Name:        "valid_until",
					Label:       "Действительна до",
					Type:        "date",
					Required:    false,
				},
				{
					Name:        "doctor_name",
					Label:       "ФИО врача",
					Type:        "text",
					Required:    false,
					Placeholder: "Иванов И.И.",
				},
			},
		},
	}

	for _, docType := range documentTypes {
		var existingType DocumentType
		err := documentTypesCol.FindOne(ctx, bson.M{"_id": docType.ID}).Decode(&existingType)
		if err == mongo.ErrNoDocuments {
			_, err = documentTypesCol.InsertOne(ctx, docType)
			if err != nil {
				log.Printf("Failed to insert document type %s: %v", docType.ID, err)
				return err
			}
			log.Printf("Created document type: %s", docType.Name)
		}
	}

	return nil
}

// ValidateUser checks if user credentials are valid
func ValidateUser(username, password string) (*User, bool) {
	ctx := context.Background()
	var user User
	
	// Input validation and sanitization
	username = SanitizeString(username)
	if username == "" {
		log.Printf("Empty username after sanitization")
		return nil, false
	}
	
	// Basic validation to prevent injection attacks
	if len(username) > 254 { // Max reasonable length for username or email
		log.Printf("Username too long")
		return nil, false
	}
	
	// Try to find user by username or email
	filter := bson.M{
		"$or": []bson.M{
			{"username": username},
			{"email": username}, // Allow login with email
		},
	}
	
	err := usersCol.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		log.Printf("User not found: %v", err)
		return nil, false
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		log.Printf("Password doesn't match: %v", err)
		return nil, false
	}

	return &user, true
}

// GenerateToken creates a new JWT token for a user
func GenerateToken(user *User) (string, error) {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "default_jwt_secret_change_in_production"
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	issuedAt := time.Now()
	claims := &Claims{
		Username: user.Username,
		UserID:   user.ID.Hex(),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  issuedAt.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

// CheckPermission verifies if a user has permission to access a service
// func CheckPermission(userID, service string) bool {
// 	ctx := context.Background()
// 	uid, err := primitive.ObjectIDFromHex(userID)
// 	if err != nil {
// 		log.Printf("Invalid user ID format: %v", err)
// 		return false
// 	}

// 	// Get user and roles
// 	var user User
// 	err = usersCol.FindOne(ctx, bson.M{"_id": uid}).Decode(&user)
// 	if err != nil {
// 		log.Printf("User not found: %v", err)
// 		return false
// 	}

// 	log.Printf("Checking permission for user %s and service %s", user.Username, service)
// 	log.Printf("User has roles: %v", user.Roles)

// 	// Check each role the user has for the service permission
// 	for _, roleName := range user.Roles {
// 		var role Role
// 		err = rolesCol.FindOne(ctx, bson.M{"name": roleName}).Decode(&role)
// 		if err != nil {
// 			log.Printf("Role %s not found: %v", roleName, err)
// 			continue
// 		}

// 		log.Printf("Role %s has permissions: %v", roleName, role.Permissions)

// 		for _, permService := range role.Permissions {
// 			if permService == service {
// 				log.Printf("Permission granted for service %s", service)
// 				return true
// 			}
// 		}
// 	}

// 	log.Printf("Permission denied for service %s", service)
// 	return false
// }

// GetUserByID retrieves a user by their ID
func GetUserByID(userID string) (*User, error) {
	ctx := context.Background()
	uid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, err
	}

	var user User
	err = usersCol.FindOne(ctx, bson.M{"_id": uid}).Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserByObjectID retrieves a user by MongoDB ObjectID
func GetUserByObjectID(id primitive.ObjectID) (*User, error) {
	ctx := context.Background()
	var user User

	err := usersCol.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email address
func GetUserByEmail(email string) (*User, error) {
	ctx := context.Background()
	var user User

	err := usersCol.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // User not found
		}
		return nil, err
	}

	return &user, nil
}

// UpdateUser updates an existing user in the database
func UpdateUser(id primitive.ObjectID, username, email, password, fullName string, roles []string) error {
	// Get a handle to the users collection
	collection := client.Database("authdb").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First check if user exists
	existingUser, err := GetUserByObjectID(id)
	if err != nil {
		return fmt.Errorf("user not found: %v", err)
	}

	// Check if another user already has this username (only if username is changing)
	if username != existingUser.Username {
		userWithSameName, _ := GetUserByUsername(username)
		if userWithSameName != nil && userWithSameName.ID != id {
			return fmt.Errorf("username already exists")
		}
	}

	// Define update document
	update := bson.M{
		"$set": bson.M{
			"username":  username,
			"email":     email,
			"roles":     roles,
			"full_name": fullName, // Update full name
		},
	}

	// Only update password if provided (non-empty)
	if password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("error hashing password: %v", err)
		}
		update["$set"].(bson.M)["password"] = string(hashedPassword)
	}

	// Update the user
	_, err = collection.UpdateOne(
		ctx,
		bson.M{"_id": id},
		update,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %v", err)
	}

	if email != "" {
		// Get Russian email template
		subject, body := GetAccountUpdatedEmail(fullName, username, email, password, roles)

		go SendEmailNotificationNew(email, subject, body)
	}

	return nil
}

// DeleteUser deletes a user from the database and all related data/files
func DeleteUser(id primitive.ObjectID) error {
	// Get the user first so we have their email and file information
	user, err := GetUserByObjectID(id)
	if err != nil {
		return fmt.Errorf("user not found: %v", err)
	}

	// Store user data before deletion for email and cleanup
	email := user.Email
	username := user.Username
	fullName := user.FullName
	userIDHex := id.Hex()

	// Get a handle to the users collection
	collection := client.Database("authdb").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Printf("Starting deletion of user %s (ID: %s) and all related data", username, userIDHex)

	// Delete all related data first
	// 1. Remove all user service roles
	err = RemoveAllUserServiceRoles(id)
	if err != nil {
		log.Printf("Warning: Failed to remove user service roles during deletion: %v", err)
	}

	// 2. Delete all password reset tokens
	tokensCol := getPasswordResetTokensCollection()
	tokenDeleteResult, err := tokensCol.DeleteMany(ctx, bson.M{"user_id": id})
	if err != nil {
		log.Printf("Warning: Failed to delete password reset tokens during user deletion: %v", err)
	} else if tokenDeleteResult.DeletedCount > 0 {
		log.Printf("Deleted %d password reset tokens for user %s", tokenDeleteResult.DeletedCount, username)
	}

	// 3. Delete all blacklisted tokens
	blacklistCol := getBlacklistedTokensCollection()
	blacklistDeleteResult, err := blacklistCol.DeleteMany(ctx, bson.M{"user_id": id})
	if err != nil {
		log.Printf("Warning: Failed to delete blacklisted tokens during user deletion: %v", err)
	} else if blacklistDeleteResult.DeletedCount > 0 {
		log.Printf("Deleted %d blacklisted tokens for user %s", blacklistDeleteResult.DeletedCount, username)
	}

	// 4. Delete all related records from other collections
	err = deleteUserRelatedRecords(id, username)
	if err != nil {
		log.Printf("Warning: Failed to delete user related records: %v", err)
	}

	// 5. Delete all user files and folders
	err = deleteUserFiles(user)
	if err != nil {
		log.Printf("Warning: Failed to delete user files during deletion: %v", err)
	}

	// Delete the user from database
	result, err := collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}
	
	if result.DeletedCount == 0 {
		return fmt.Errorf("user not found or already deleted")
	}

	// Send email notification if email is available
	if email != "" {
		// Get Russian email template
		subject, body := GetAccountDeletedEmail(fullName, username)

		go SendEmailNotificationNew(email, subject, body)
	}
	
	log.Printf("User %s (ID: %s) successfully deleted with all related data", username, userIDHex)

	return nil
}

// deleteUserFiles removes all files and directories associated with a user
func deleteUserFiles(user *User) error {
	userIDHex := user.ID.Hex()
	deletedFilesCount := 0
	
	// 1. Delete avatar files
	userDir := fmt.Sprintf("./data/%s", userIDHex)
	
	// Delete avatar file
	avatarPath := filepath.Join(userDir, "avatar.jpg")
	if err := os.Remove(avatarPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Failed to delete avatar file %s: %v", avatarPath, err)
	} else if err == nil {
		deletedFilesCount++
		log.Printf("Deleted avatar file: %s", avatarPath)
	}
	
	// Delete original avatar files (multiple formats possible)
	originalExts := []string{".jpg", ".jpeg", ".png", ".gif", ".webp"}
	for _, ext := range originalExts {
		originalPath := filepath.Join(userDir, "original"+ext)
		if err := os.Remove(originalPath); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: Failed to delete original avatar file %s: %v", originalPath, err)
		} else if err == nil {
			deletedFilesCount++
			log.Printf("Deleted original avatar file: %s", originalPath)
		}
	}

	// 2. Delete document attachment files
	for _, document := range user.Documents {
		for _, attachment := range document.Attachments {
			if attachment.FilePath != "" {
				// Handle both relative and absolute paths
				filePath := attachment.FilePath
				if !filepath.IsAbs(filePath) && !strings.HasPrefix(filePath, "./") {
					filePath = "./" + filePath
				}
				
				if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
					log.Printf("Warning: Failed to delete document attachment %s: %v", filePath, err)
				} else if err == nil {
					deletedFilesCount++
					log.Printf("Deleted document attachment: %s", filePath)
				}
			}
		}
	}

	// 3. Delete legacy document files
	for _, legacyDoc := range user.LegacyDocs {
		if legacyDoc.FilePath != "" {
			filePath := legacyDoc.FilePath
			if !filepath.IsAbs(filePath) && !strings.HasPrefix(filePath, "./") {
				filePath = "./" + filePath
			}
			
			if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
				log.Printf("Warning: Failed to delete legacy document %s: %v", filePath, err)
			} else if err == nil {
				deletedFilesCount++
				log.Printf("Deleted legacy document: %s", filePath)
			}
		}
	}

	// 4. Try to remove the user directory if it's empty
	if err := os.Remove(userDir); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Info: User directory %s not empty or could not be removed: %v", userDir, err)
		}
	} else {
		log.Printf("Removed empty user directory: %s", userDir)
	}

	log.Printf("File cleanup completed for user %s: %d files deleted", user.Username, deletedFilesCount)
	return nil
}

// deleteUserRelatedRecords removes all related records from other collections
func deleteUserRelatedRecords(userID primitive.ObjectID, username string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	deletedRecordsCount := 0

	// 1. Delete all import logs where this user was the admin
	importLogsCol := client.Database("authdb").Collection("import_logs")
	importLogResult, err := importLogsCol.DeleteMany(ctx, bson.M{"admin_username": username})
	if err != nil {
		log.Printf("Warning: Failed to delete import logs for user %s: %v", username, err)
	} else if importLogResult.DeletedCount > 0 {
		deletedRecordsCount += int(importLogResult.DeletedCount)
		log.Printf("Deleted %d import logs for user %s", importLogResult.DeletedCount, username)
	}

	// 2. Delete all user service roles (this should already be done by RemoveAllUserServiceRoles, but double-check)
	userServiceRolesCol := client.Database("authdb").Collection("user_service_roles")
	serviceRolesResult, err := userServiceRolesCol.DeleteMany(ctx, bson.M{"user_id": userID})
	if err != nil {
		log.Printf("Warning: Failed to delete service roles for user %s: %v", username, err)
	} else if serviceRolesResult.DeletedCount > 0 {
		deletedRecordsCount += int(serviceRolesResult.DeletedCount)
		log.Printf("Deleted %d additional service roles for user %s", serviceRolesResult.DeletedCount, username)
	}

	// 3. Delete any user-related activity logs (if such collection exists)
	activityLogsCol := client.Database("authdb").Collection("activity_logs")
	activityResult, err := activityLogsCol.DeleteMany(ctx, bson.M{"user_id": userID})
	if err != nil {
		log.Printf("Info: No activity logs collection or failed to delete for user %s: %v", username, err)
	} else if activityResult.DeletedCount > 0 {
		deletedRecordsCount += int(activityResult.DeletedCount)
		log.Printf("Deleted %d activity logs for user %s", activityResult.DeletedCount, username)
	}

	// 4. Delete any user sessions (if such collection exists)
	userSessionsCol := client.Database("authdb").Collection("user_sessions")
	sessionsResult, err := userSessionsCol.DeleteMany(ctx, bson.M{"user_id": userID})
	if err != nil {
		log.Printf("Info: No user sessions collection or failed to delete for user %s: %v", username, err)
	} else if sessionsResult.DeletedCount > 0 {
		deletedRecordsCount += int(sessionsResult.DeletedCount)
		log.Printf("Deleted %d user sessions for user %s", sessionsResult.DeletedCount, username)
	}

	// 5. Remove user references from assignments where this user assigned roles to others
	assignmentResult, err := userServiceRolesCol.UpdateMany(
		ctx,
		bson.M{"assigned_by": userID},
		bson.M{"$set": bson.M{"assigned_by": primitive.NilObjectID}},
	)
	if err != nil {
		log.Printf("Warning: Failed to update assignment references for user %s: %v", username, err)
	} else if assignmentResult.ModifiedCount > 0 {
		log.Printf("Updated %d role assignments where user %s was the assigner", assignmentResult.ModifiedCount, username)
	}

	log.Printf("Related records cleanup completed for user %s: %d records deleted", username, deletedRecordsCount)
	return nil
}

// GetUsersWithRole returns all users who have the specified role
func GetUsersWithRole(roleName string) ([]*User, error) {
	ctx := context.Background()
	cursor, err := usersCol.Find(ctx, bson.M{"roles": roleName})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []*User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, err
	}

	return users, nil
}

// GetAllUsers retrieves all users
func GetAllUsers() ([]User, error) {
	ctx := context.Background()
	cursor, err := usersCol.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []User
	if err = cursor.All(ctx, &users); err != nil {
		return nil, err
	}

	return users, nil
}

// GetUsersWithServiceRoles retrieves users who have roles in a specific service
func GetUsersWithServiceRoles(serviceKey string) ([]User, error) {
	ctx := context.Background()
	
	// Find roles for this service
	serviceRoles, err := GetRolesByService(serviceKey)
	if err != nil {
		return nil, err
	}
	
	// Extract role names
	roleNames := make([]string, 0, len(serviceRoles))
	for _, role := range serviceRoles {
		roleNames = append(roleNames, role.Name)
	}
	
	if len(roleNames) == 0 {
		return []User{}, nil // No roles, no users
	}
	
	// Find users who have any of these roles
	cursor, err := usersCol.Find(ctx, bson.M{
		"roles": bson.M{"$in": roleNames},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []User
	if err = cursor.All(ctx, &users); err != nil {
		return nil, err
	}

	return users, nil
}

// GetUsersWithServiceRolesNew retrieves users with their roles in a specific service (ADR-001)
func GetUsersWithServiceRolesNew(serviceKey string) ([]UserWithServiceRoles, error) {
	ctx := context.Background()
	
	log.Printf("GetUsersWithServiceRolesNew: Looking for users in service: %s", serviceKey)
	
	// Get all user role assignments for this service
	pipeline := []bson.M{
		{"$match": bson.M{
			"service_key": serviceKey,
			"is_active":   true,
		}},
		{"$group": bson.M{
			"_id":   "$user_id",
			"roles": bson.M{"$push": "$role_name"},
		}},
		{"$lookup": bson.M{
			"from":         "users",
			"localField":   "_id",
			"foreignField": "_id",
			"as":           "user",
		}},
		{"$unwind": "$user"},
		{"$project": bson.M{
			"user":  1,
			"roles": 1,
		}},
	}
	
	log.Printf("GetUsersWithServiceRolesNew: Executing aggregation pipeline")
	cursor, err := userServiceRolesCol.Aggregate(ctx, pipeline)
	if err != nil {
		log.Printf("GetUsersWithServiceRolesNew: Error executing pipeline: %v", err)
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []UserWithServiceRoles
	for cursor.Next(ctx) {
		var result struct {
			User  User     `bson:"user"`
			Roles []string `bson:"roles"`
		}
		if err := cursor.Decode(&result); err != nil {
			log.Printf("GetUsersWithServiceRolesNew: Error decoding result: %v", err)
			continue
		}
		
		log.Printf("GetUsersWithServiceRolesNew: Found user %s (%s) with roles: %v", 
			result.User.Username, result.User.Email, result.Roles)
		
		userWithRoles := UserWithServiceRoles{
			User:         result.User,
			ServiceRoles: result.Roles,
		}
		results = append(results, userWithRoles)
	}
	
	log.Printf("GetUsersWithServiceRolesNew: Returning %d users for service %s", len(results), serviceKey)
	return results, nil
}

// CreateUser creates a new user
// CreateUserWithNames creates a user with separated name fields
func CreateUserWithNames(username, email, password, lastName, firstName, middleName, suffix string, roleNames []string) (primitive.ObjectID, error) {
	ctx := context.Background()

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return primitive.NilObjectID, err
	}

	// Create user document
	user := User{
		Username:   username,
		Email:      email,
		Password:   string(hashedPassword),
		Roles:      roleNames,
		LastName:   lastName,
		FirstName:  firstName,
		MiddleName: middleName,
		Suffix:     suffix,
	}

	result, err := usersCol.InsertOne(ctx, user)
	if err != nil {
		return primitive.NilObjectID, err
	}

	// Add email notification after successful user creation
	if err == nil && email != "" {
		// Get Russian email template - use GetFullName() method
		subject, body := GetAccountCreatedEmail(user.GetFullName(), username, password, roleNames)

		SendEmailNotificationNew(email, subject, body)
	}

	return result.InsertedID.(primitive.ObjectID), nil
}

// CreateUser creates a user with legacy fullName field (for backward compatibility)
func CreateUser(username, email, password string, fullName string, roleNames []string) (primitive.ObjectID, error) {
	ctx := context.Background()

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return primitive.NilObjectID, err
	}

	// Create user document
	user := User{
		Username: username,
		Email:    email,
		Password: string(hashedPassword),
		Roles:    roleNames,
		FullName: fullName, // Set legacy full name
	}

	result, err := usersCol.InsertOne(ctx, user)
	if err != nil {
		return primitive.NilObjectID, err
	}

	// Add email notification after successful user creation
	if err == nil && email != "" {
		// Get Russian email template
		subject, body := GetAccountCreatedEmail(fullName, username, password, roleNames)

		SendEmailNotificationNew(email, subject, body)
	}

	return result.InsertedID.(primitive.ObjectID), nil
}

// ImportUsersFromExcel imports users from an Excel file
func ImportUsersFromExcel(filePath string) (int, error) {
	file, err := excelize.OpenFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open Excel file: %v", err)
	}

	// Get the first sheet
	sheets := file.GetSheetList()
	if len(sheets) == 0 {
		return 0, fmt.Errorf("no sheets found in Excel file")
	}
	sheetName := sheets[0]

	// Get all the rows in the sheet
	rows, err := file.GetRows(sheetName)
	if err != nil {
		return 0, fmt.Errorf("failed to get rows from sheet: %v", err)
	}

	if len(rows) < 2 { // At least header row and one data row
		return 0, fmt.Errorf("excel file contains no data rows")
	}

	// Get header row and handle various column naming conventions
	headerRow := rows[0]

	// Debug: Print all headers
	fmt.Printf("Found headers: %v\n", headerRow)

	// Map to store column indices with case-insensitive matching
	columnMap := make(map[string]int)
	requiredColumns := []string{"username", "email", "password", "full_name"}
	optionalColumns := []string{"roles"} // Добавлен столбец с ролями как опциональный

	alternativeNames := map[string][]string{
		"username":  {"login", "user name", "имя пользователя", "логин"},
		"email":     {"e-mail", "почта", "email address", "электронная почта"},
		"password":  {"пароль", "pass"},
		"full_name": {"fullname", "name", "имя", "фио", "полное имя"},
		"roles":     {"роли", "role", "роль", "rights", "permissions", "разрешения"}, // Альтернативные имена для столбца ролей
	}

	// Find column indices with flexible matching
	for i, header := range headerRow {
		// Normalize header: lowercase and trim
		normalizedHeader := strings.ToLower(strings.TrimSpace(header))

		// Check for required and optional columns
		allColumns := append(requiredColumns, optionalColumns...)
		for _, col := range allColumns {
			if normalizedHeader == col {
				columnMap[col] = i
				break
			}

			// Check alternative names
			for _, altName := range alternativeNames[col] {
				if normalizedHeader == altName {
					columnMap[col] = i
					break
				}
			}
		}
	}

	// Check if all required columns were found
	missingColumns := []string{}
	for _, col := range requiredColumns {
		if _, exists := columnMap[col]; !exists {
			missingColumns = append(missingColumns, col)
		}
	}

	if len(missingColumns) > 0 {
		// Print found columns to help diagnose the issue
		foundColumns := []string{}
		for i, h := range headerRow {
			foundColumns = append(foundColumns, fmt.Sprintf("%d: %s", i, h))
		}

		return 0, fmt.Errorf("Excel file missing required columns (%s). Found columns: %s",
			strings.Join(missingColumns, ", "), strings.Join(foundColumns, ", "))
	}

	// Process data rows
	usersCreated := 0
	for i := 1; i < len(rows); i++ {
		row := rows[i]

		// Skip empty rows
		if len(row) == 0 || (len(row) == 1 && row[0] == "") {
			continue
		}

		// Ensure the row has enough columns
		if len(row) <= columnMap["username"] || len(row) <= columnMap["email"] ||
			len(row) <= columnMap["password"] || len(row) <= columnMap["full_name"] {
			fmt.Printf("Warning: Row %d doesn't have enough columns: %v\n", i+1, row)
			continue
		}

		username := strings.TrimSpace(row[columnMap["username"]])
		email := strings.TrimSpace(row[columnMap["email"]])
		password := strings.TrimSpace(row[columnMap["password"]])
		fullName := strings.TrimSpace(row[columnMap["full_name"]])

		// Skip if essential fields are empty
		if username == "" || password == "" {
			fmt.Printf("Warning: Row %d has empty username or password\n", i+1)
			continue
		}

		// Check if user already exists
		existingUser, err := GetUserByUsername(username)
		if err == nil && existingUser != nil {
			fmt.Printf("User %s already exists, skipping\n", username)
			continue
		}

		// Parse and set roles if available
		roles := []string{}
		if rolesIndex, exists := columnMap["roles"]; exists && len(row) > rolesIndex {
			rolesStr := strings.TrimSpace(row[rolesIndex])
			if rolesStr != "" {
				roles = ParseRolesString(rolesStr)
				fmt.Printf("Found roles for user %s: %v\n", username, roles)
			}
		}

		// If no roles are specified and a default role is needed, add it here
		if len(roles) == 0 {
			roles = append(roles, "user") // Добавляем роль "user" по умолчанию если не указано
		}

		// Create user
		_, err = CreateUser(username, email, password, fullName, roles)
		if err != nil {
			fmt.Printf("Error creating user %s: %v\n", username, err)
			continue
		}

		usersCreated++
		fmt.Printf("Created user %s with roles %v\n", username, roles)
	}

	return usersCreated, nil
}

// GetCollection returns a MongoDB collection by name
func GetCollection(name string) *mongo.Collection {
	return db.Collection(name)
}

func GetUserByUsername(username string) (*User, error) {
	ctx := context.Background()
	var user User

	err := usersCol.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // User not found
		}
		return nil, err // Other error
	}

	return &user, nil
}

// GetUserByEmailOrUsername retrieves a user by email or username
func GetUserByEmailOrUsername(identifier string) (*User, error) {
	ctx := context.Background()
	var user User

	// Search by email or username using $or operator
	filter := bson.M{
		"$or": []bson.M{
			{"email": identifier},
			{"username": identifier},
		},
	}

	err := usersCol.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // User not found
		}
		return nil, err // Other error
	}

	return &user, nil
}

// GetRolesByName retrieves roles by their name
// func GetRolesByName(name string) ([]*Role, error) {
// 	ctx := context.Background()

// 	// Create a filter for the query
// 	filter := bson.M{"name": name}

// 	// Execute the find operation
// 	cursor, err := rolesCol.Find(ctx, filter)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer cursor.Close(ctx)

// 	// Parse the results
// 	var roles []*Role
// 	if err := cursor.All(ctx, &roles); err != nil {
// 		return nil, err
// 	}

// 	return roles, nil
// }

// Helper function
// func contains(slice []string, str string) bool {
// 	for _, s := range slice {
// 		if s == str {
// 			return true
// 		}
// 	}
// 	return false
// }

// AssignRoleToUser assigns a role to a user
func AssignRoleToUser(userID primitive.ObjectID, roleName string) error {
	ctx := context.Background()

	// Get current user
	var user User
	err := usersCol.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		return err
	}

	// Check if user already has this role
	for _, existingRole := range user.Roles {
		if existingRole == roleName {
			return fmt.Errorf("пользователь уже имеет роль %s", roleName)
		}
	}

	// Add role to user's roles
	_, err = usersCol.UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{"$push": bson.M{"roles": roleName}},
	)

	return err
}

// RemoveRoleFromUser removes a role from a user
func RemoveRoleFromUser(userID primitive.ObjectID, roleName string) error {
	ctx := context.Background()

	// Remove role from user's roles
	_, err := usersCol.UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{"$pull": bson.M{"roles": roleName}},
	)

	return err
}

// AssignUserToServiceRole assigns a role to a user in a specific service
func AssignUserToServiceRole(userID primitive.ObjectID, serviceKey, roleName string, assignedBy primitive.ObjectID) error {
	ctx := context.Background()

	// Check if role exists in service
	role, err := GetRoleByServiceAndName(serviceKey, roleName)
	if err != nil {
		return fmt.Errorf("роль %s не найдена в сервисе %s: %v", roleName, serviceKey, err)
	}
	if role == nil {
		return fmt.Errorf("роль %s не существует в сервисе %s", roleName, serviceKey)
	}

	// Create user service role assignment
	userServiceRole := &UserServiceRole{
		UserID:     userID,
		ServiceKey: serviceKey,
		RoleName:   roleName,
		AssignedAt: time.Now(),
		AssignedBy: assignedBy,
		IsActive:   true,
	}

	// Use upsert to prevent duplicates
	filter := bson.M{
		"user_id":     userID,
		"service_key": serviceKey,
		"role_name":   roleName,
	}
	update := bson.M{
		"$set": userServiceRole,
		"$setOnInsert": bson.M{
			"_id": primitive.NewObjectID(),
		},
	}
	
	_, err = userServiceRolesCol.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true))
	return err
}

// GetUserServiceRoleAssignments returns all service role assignments for a user
func GetUserServiceRoleAssignments(userID primitive.ObjectID) ([]UserServiceRole, error) {
	ctx := context.Background()
	
	cursor, err := userServiceRolesCol.Find(ctx, bson.M{
		"user_id":   userID,
		"is_active": true,
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []UserServiceRole
	err = cursor.All(ctx, &roles)
	return roles, err
}

// GetUserAccessibleServices returns services where user has any role
func GetUserAccessibleServices(userID primitive.ObjectID) ([]string, error) {
	ctx := context.Background()
	
	// Use aggregation to get distinct service keys
	pipeline := []bson.M{
		{"$match": bson.M{
			"user_id":   userID,
			"is_active": true,
		}},
		{"$group": bson.M{
			"_id": "$service_key",
		}},
	}
	
	cursor, err := userServiceRolesCol.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var services []string
	for cursor.Next(ctx) {
		var result bson.M
		if err := cursor.Decode(&result); err != nil {
			continue
		}
		if serviceKey, ok := result["_id"].(string); ok {
			services = append(services, serviceKey)
		}
	}
	
	return services, nil
}

// RemoveUserFromServiceRole removes a role from user in a service
func RemoveUserFromServiceRole(userID primitive.ObjectID, serviceKey, roleName string) error {
	ctx := context.Background()
	
	_, err := userServiceRolesCol.UpdateOne(
		ctx,
		bson.M{
			"user_id":     userID,
			"service_key": serviceKey,
			"role_name":   roleName,
		},
		bson.M{"$set": bson.M{"is_active": false}},
	)
	
	return err
}

// CreateUserServiceRole creates a new user service role assignment
func CreateUserServiceRole(userServiceRole UserServiceRole) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Printf("CreateUserServiceRole: Checking for existing role - UserID: %s, ServiceKey: %s, RoleName: %s", 
		userServiceRole.UserID.Hex(), userServiceRole.ServiceKey, userServiceRole.RoleName)

	// Сначала проверим, есть ли уже активная роль
	var existingRole UserServiceRole
	err := userServiceRolesCol.FindOne(ctx, bson.M{
		"user_id":     userServiceRole.UserID,
		"service_key": userServiceRole.ServiceKey,
		"role_name":   userServiceRole.RoleName,
		"is_active":   true,
	}).Decode(&existingRole)

	if err == nil {
		// Роль уже существует и активна
		log.Printf("CreateUserServiceRole: Role already exists and is active")
		return nil
	}

	if err != mongo.ErrNoDocuments {
		log.Printf("CreateUserServiceRole: Error checking existing role: %v", err)
		return err
	}

	// Попробуем обновить существующую неактивную запись
	updateResult, err := userServiceRolesCol.UpdateOne(ctx, 
		bson.M{
			"user_id":     userServiceRole.UserID,
			"service_key": userServiceRole.ServiceKey,
			"role_name":   userServiceRole.RoleName,
			"is_active":   false,
		},
		bson.M{
			"$set": bson.M{
				"is_active":   true,
				"assigned_at": userServiceRole.AssignedAt,
				"assigned_by": userServiceRole.AssignedBy,
			},
		},
	)

	if err != nil {
		log.Printf("CreateUserServiceRole: Error updating existing role: %v", err)
		return err
	}

	// Если обновили существующую неактивную запись
	if updateResult.ModifiedCount > 0 {
		log.Printf("CreateUserServiceRole: Updated existing inactive role assignment")
		return nil
	}

	// Если запись не найдена, создаем новую
	log.Printf("CreateUserServiceRole: Creating new role assignment")
	_, err = userServiceRolesCol.InsertOne(ctx, userServiceRole)
	if err != nil {
		log.Printf("CreateUserServiceRole: Error inserting new role: %v", err)
		return err
	}
	
	log.Printf("CreateUserServiceRole: Successfully created role assignment")
	return nil
}

// RemoveUserFromServiceRoles removes all roles (both active and inactive) for a user in a specific service
func RemoveUserFromServiceRoles(userID primitive.ObjectID, serviceKey string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Полностью удаляем все записи для этого пользователя в этом сервисе
	_, err := userServiceRolesCol.DeleteMany(
		ctx,
		bson.M{
			"user_id":     userID,
			"service_key": serviceKey,
		},
	)
	
	return err
}

// GetAllServicesWithRoles returns all services with their roles
func GetAllServicesWithRoles() ([]Service, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := servicesCol.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var services []Service
	if err = cursor.All(ctx, &services); err != nil {
		return nil, err
	}

	// Note: This function returns basic services. Use GetAllServicesWithRolesForTemplate for template usage.
	return services, nil
}

// ServiceWithRoles represents a service with its roles for template usage
type ServiceWithRoles struct {
	Service
	Roles []Role `json:"roles"`
}

// GetAllServicesWithRolesForTemplate returns all services with their roles in template-friendly format
// Excludes the "system" service as system roles are handled separately
func GetAllServicesWithRolesForTemplate() ([]ServiceWithRoles, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Exclude system service as it's handled separately in the template
	cursor, err := servicesCol.Find(ctx, bson.M{
		"key": bson.M{"$ne": "system"},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var services []Service
	if err = cursor.All(ctx, &services); err != nil {
		return nil, err
	}

	var servicesWithRoles []ServiceWithRoles
	for _, service := range services {
		roles, err := GetRolesByService(service.Key)
		if err != nil {
			log.Printf("Warning: Failed to get roles for service %s: %v", service.Key, err)
			continue
		}
		
		servicesWithRoles = append(servicesWithRoles, ServiceWithRoles{
			Service: service,
			Roles:   roles,
		})
	}

	return servicesWithRoles, nil
}

// GetUserServiceRolesByUserID returns all service roles for a specific user
func GetUserServiceRolesByUserID(userID primitive.ObjectID) ([]UserServiceRole, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := userServiceRolesCol.Find(ctx, bson.M{
		"user_id": userID,
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var userServiceRoles []UserServiceRole
	if err = cursor.All(ctx, &userServiceRoles); err != nil {
		return nil, err
	}

	return userServiceRoles, nil
}

// RemoveAllUserServiceRoles removes all service roles for a user
func RemoveAllUserServiceRoles(userID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := userServiceRolesCol.DeleteMany(ctx, bson.M{
		"user_id": userID,
	})
	
	return err
}

// UpdateUserProfile updates user profile information
// UpdateUserProfile updates user profile with separated name fields
func UpdateUserProfile(userID primitive.ObjectID, email, lastName, firstName, middleName, suffix, phone, position, department string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Printf("UpdateUserProfile: userID=%s, email=%s, lastName=%s, firstName=%s, middleName=%s, suffix=%s, phone=%s, position=%s, department=%s\n", 
		userID.Hex(), email, lastName, firstName, middleName, suffix, phone, position, department)

	update := bson.M{
		"$set": bson.M{
			"email":       email,
			"last_name":   lastName,
			"first_name":  firstName,
			"middle_name": middleName,
			"suffix":      suffix,
			"phone":       phone,
			"position":    position,
			"department":  department,
			"updated_at":  time.Now(),
		},
	}

	result, err := usersCol.UpdateOne(ctx, bson.M{"_id": userID}, update)
	if err != nil {
		fmt.Printf("UpdateUserProfile error: %v\n", err)
		return err
	}
	
	fmt.Printf("UpdateUserProfile result: matched=%d, modified=%d\n", result.MatchedCount, result.ModifiedCount)
	return nil
}

// UpdateUserProfileLegacy updates user profile using legacy fullName field (for backward compatibility)
func UpdateUserProfileLegacy(userID primitive.ObjectID, email, fullName, phone, position, department string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Printf("UpdateUserProfileLegacy: userID=%s, email=%s, fullName=%s, phone=%s, position=%s, department=%s\n", 
		userID.Hex(), email, fullName, phone, position, department)

	update := bson.M{
		"$set": bson.M{
			"email":      email,
			"full_name":  fullName,
			"phone":      phone,
			"position":   position,
			"department": department,
			"updated_at": time.Now(),
		},
	}

	result, err := usersCol.UpdateOne(ctx, bson.M{"_id": userID}, update)
	if err != nil {
		fmt.Printf("UpdateUserProfileLegacy error: %v\n", err)
		return err
	}
	
	fmt.Printf("UpdateUserProfileLegacy result: matched=%d, modified=%d\n", result.MatchedCount, result.ModifiedCount)
	return nil
}

// UpdateUserAvatar updates user avatar path
func UpdateUserAvatar(userID primitive.ObjectID, avatarPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{
		"$set": bson.M{
			"avatar_path": avatarPath,
			"updated_at":  time.Now(),
		},
	}

	_, err := usersCol.UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}

// UpdateUserAvatarWithCrop updates user avatar paths and crop coordinates
func UpdateUserAvatarWithCrop(userID primitive.ObjectID, avatarPath, originalAvatarPath string, cropCoords *CropCoords) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Printf("UpdateUserAvatarWithCrop called for user %s\n", userID.Hex())
	fmt.Printf("Avatar path: %s\n", avatarPath)
	fmt.Printf("Original avatar path: %s\n", originalAvatarPath)
	fmt.Printf("Crop coordinates: %+v\n", cropCoords)

	update := bson.M{
		"$set": bson.M{
			"avatar_path":          avatarPath,
			"original_avatar_path": originalAvatarPath,
			"crop_coordinates":     cropCoords,
			"updated_at":           time.Now(),
		},
	}

	result, err := usersCol.UpdateOne(ctx, bson.M{"_id": userID}, update)
	if err != nil {
		fmt.Printf("UpdateUserAvatarWithCrop failed: %v\n", err)
		return err
	}
	
	fmt.Printf("UpdateUserAvatarWithCrop successful, matched: %d, modified: %d\n", result.MatchedCount, result.ModifiedCount)
	return nil
}

// UpdateUserEmail updates only the email address of a user
func UpdateUserEmail(userID primitive.ObjectID, email string) error {
	usersCol := client.Database("authdb").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if another user already has this email (only if not empty)
	if email != "" {
		existingUser, _ := GetUserByEmail(email)
		if existingUser != nil && existingUser.ID != userID {
			return fmt.Errorf("email already exists")
		}
	}

	update := bson.M{
		"$set": bson.M{
			"email":      email,
			"updated_at": time.Now(),
		},
	}

	result, err := usersCol.UpdateOne(ctx, bson.M{"_id": userID}, update)
	if err != nil {
		log.Printf("UpdateUserEmail failed: %v", err)
		return err
	}
	
	if result.MatchedCount == 0 {
		return fmt.Errorf("user not found")
	}
	
	log.Printf("UpdateUserEmail successful for user %s, email set to %s", userID.Hex(), email)
	return nil
}

// GetUsersWithAvatars получает всех пользователей, у которых есть путь к аватарке
func GetUsersWithAvatars() ([]User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ищем пользователей с непустым avatar_path
	filter := bson.M{
		"avatar_path": bson.M{
			"$exists": true,
			"$ne":     "",
		},
	}

	cursor, err := usersCol.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []User
	if err = cursor.All(ctx, &users); err != nil {
		return nil, err
	}

	return users, nil
}

// AddUserDocument adds a document to user's document list (legacy)
func AddUserDocument(userID primitive.ObjectID, doc Document) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	doc.ID = primitive.NewObjectID()
	doc.UploadedAt = time.Now()

	update := bson.M{
		"$push": bson.M{
			"legacy_docs": doc,
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	_, err := usersCol.UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}



// RemoveUserDocument removes a document from user's document list
func RemoveUserDocument(userID, docID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	update := bson.M{
		"$pull": bson.M{
			"legacy_docs": bson.M{"_id": docID},
		},
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	_, err := usersCol.UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}

// ChangeUserPassword changes user password
func ChangeUserPassword(userID primitive.ObjectID, newPassword string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	update := bson.M{
		"$set": bson.M{
			"password":   string(hashedPassword),
			"updated_at": time.Now(),
		},
	}

	_, err = usersCol.UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}

// AddDocumentAttachment adds an attachment to a user document
func AddDocumentAttachment(userID, docID primitive.ObjectID, attachment DocumentAttachment) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	attachment.ID = primitive.NewObjectID()
	attachment.UploadedAt = time.Now()

	update := bson.M{
		"$push": bson.M{
			"documents.$.attachments": attachment,
		},
		"$set": bson.M{
			"documents.$.updated_at": time.Now(),
			"updated_at":             time.Now(),
		},
	}

	_, err := usersCol.UpdateOne(
		ctx,
		bson.M{
			"_id":          userID,
			"documents.id": docID,
		},
		update,
	)
	return err
}

// RemoveDocumentAttachment removes an attachment from a user document
func RemoveDocumentAttachment(userID, docID, attachmentID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First, we need to pull the attachment from the specific document
	update := bson.M{
		"$pull": bson.M{
			"documents.$.attachments": bson.M{"_id": attachmentID},
		},
		"$set": bson.M{
			"documents.$.updated_at": time.Now(),
			"updated_at":             time.Now(),
		},
	}

	_, err := usersCol.UpdateOne(
		ctx,
		bson.M{
			"_id":          userID,
			"documents.id": docID,
		},
		update,
	)
	return err
}

// AddDocumentAttachmentByIndex adds an attachment to a user document by index
func AddDocumentAttachmentByIndex(userID primitive.ObjectID, docIndex int, attachment DocumentAttachment) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	attachment.ID = primitive.NewObjectID()
	attachment.UploadedAt = time.Now()

	// Create the positional update based on document index
	updateKey := fmt.Sprintf("documents.%d.attachments", docIndex)
	updatedAtKey := fmt.Sprintf("documents.%d.updated_at", docIndex)

	update := bson.M{
		"$push": bson.M{
			updateKey: attachment,
		},
		"$set": bson.M{
			updatedAtKey:  time.Now(),
			"updated_at": time.Now(),
		},
	}

	_, err := usersCol.UpdateOne(
		ctx,
		bson.M{"_id": userID},
		update,
	)
	return err
}

// RemoveDocumentAttachmentByIndex removes an attachment from a user document by index
func RemoveDocumentAttachmentByIndex(userID primitive.ObjectID, docIndex int, attachmentID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create the positional pull operation based on document index
	pullKey := fmt.Sprintf("documents.%d.attachments", docIndex)
	updatedAtKey := fmt.Sprintf("documents.%d.updated_at", docIndex)

	update := bson.M{
		"$pull": bson.M{
			pullKey: bson.M{"_id": attachmentID},
		},
		"$set": bson.M{
			updatedAtKey:  time.Now(),
			"updated_at": time.Now(),
		},
	}

	_, err := usersCol.UpdateOne(
		ctx,
		bson.M{"_id": userID},
		update,
	)
	return err
}

// UpdateUserDocumentFields updates the fields of a user document by index
func UpdateUserDocumentFields(userID primitive.ObjectID, docIndex int, fields map[string]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create update operations for each field
	setOps := bson.M{}
	
	// Update each field
	for fieldName, fieldValue := range fields {
		fieldKey := fmt.Sprintf("documents.%d.fields.%s", docIndex, fieldName)
		setOps[fieldKey] = fieldValue
	}
	
	// Also update the document's updated_at timestamp
	updatedAtKey := fmt.Sprintf("documents.%d.updated_at", docIndex)
	setOps[updatedAtKey] = time.Now()
	setOps["updated_at"] = time.Now()

	update := bson.M{
		"$set": setOps,
	}

	_, err := usersCol.UpdateOne(
		ctx,
		bson.M{"_id": userID},
		update,
	)
	return err
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id"`
	Email     string             `bson:"email" json:"email"`
	Token     string             `bson:"token" json:"token"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expires_at"`
	Used      bool               `bson:"used" json:"used"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// BlacklistedToken represents a blacklisted JWT token
type BlacklistedToken struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id"`
	TokenHash string             `bson:"token_hash" json:"token_hash"` // SHA256 hash of the token
	Reason    string             `bson:"reason" json:"reason"`         // Reason for blacklisting
	ExpiresAt time.Time          `bson:"expires_at" json:"expires_at"` // When the original token would expire
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// CreatePasswordResetToken creates a new password reset token
func CreatePasswordResetToken(email string) (*PasswordResetToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Find user by email
	var user User
	err := usersCol.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// SECURITY: Delete all existing password reset tokens for this user
	tokensCol := getPasswordResetTokensCollection()
	deleteResult, err := tokensCol.DeleteMany(ctx, bson.M{"user_id": user.ID})
	if err != nil {
		log.Printf("Warning: Failed to delete existing password reset tokens for user %s: %v", user.ID.Hex(), err)
	} else if deleteResult.DeletedCount > 0 {
		log.Printf("Security: Deleted %d existing password reset tokens for user %s", deleteResult.DeletedCount, user.Username)
	}

	// NOTE: We don't invalidate sessions here to allow user to continue working
	// Sessions will be invalidated only when password is actually changed
	// This provides better UX while maintaining security

	// Generate secure random token
	tokenBytes := make([]byte, 32)
	_, err = rand.Read(tokenBytes)
	if err != nil {
		return nil, err
	}
	token := fmt.Sprintf("%x", tokenBytes)

	// Create token document
	resetToken := &PasswordResetToken{
		UserID:    user.ID,
		Email:     email,
		Token:     token,
		ExpiresAt: time.Now().Add(15 * time.Minute), // Token expires in 15 minutes (security improvement)
		Used:      false,
		CreatedAt: time.Now(),
	}

	// Insert token into database
	result, err := getPasswordResetTokensCollection().InsertOne(ctx, resetToken)
	if err != nil {
		return nil, err
	}

	resetToken.ID = result.InsertedID.(primitive.ObjectID)
	return resetToken, nil
}

// ValidatePasswordResetToken validates and returns the reset token
func ValidatePasswordResetToken(token string) (*PasswordResetToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var resetToken PasswordResetToken
	err := getPasswordResetTokensCollection().FindOne(ctx, bson.M{
		"token": token,
		"used":  false,
		"expires_at": bson.M{"$gt": time.Now()},
	}).Decode(&resetToken)

	if err != nil {
		return nil, fmt.Errorf("invalid or expired token")
	}

	return &resetToken, nil
}

// UsePasswordResetToken marks the token as used and resets the password
func UsePasswordResetToken(token string, newPassword string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Validate token
	resetToken, err := ValidatePasswordResetToken(token)
	if err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update user password
	_, err = usersCol.UpdateOne(ctx, bson.M{"_id": resetToken.UserID}, bson.M{
		"$set": bson.M{
			"password":   string(hashedPassword),
			"updated_at": time.Now(),
		},
	})
	if err != nil {
		return err
	}

	// SECURITY: Invalidate all active sessions for this user
	err = InvalidateAllUserSessions(resetToken.UserID, "Password reset completed")
	if err != nil {
		log.Printf("Warning: Failed to invalidate user sessions after password reset: %v", err)
		// Don't fail the password reset if we can't invalidate sessions
	}

	// Delete ALL password reset tokens for this user (including the one we just used)
	_, err = getPasswordResetTokensCollection().DeleteMany(ctx, bson.M{"user_id": resetToken.UserID})
	if err != nil {
		log.Printf("Warning: Failed to clean up password reset tokens: %v", err)
		// Don't fail the password reset if we can't clean up tokens
	}

	log.Printf("Security: Password reset completed for user %s, all sessions invalidated", resetToken.UserID.Hex())
	return nil
}

// getPasswordResetTokensCollection returns the password reset tokens collection
func getPasswordResetTokensCollection() *mongo.Collection {
	if db == nil {
		log.Fatal("Database connection not initialized")
	}
	return db.Collection("password_reset_tokens")
}

// getBlacklistedTokensCollection returns the blacklisted tokens collection
func getBlacklistedTokensCollection() *mongo.Collection {
	if db == nil {
		log.Fatal("Database connection not initialized")
	}
	return db.Collection("blacklisted_tokens")
}

// CleanupExpiredBlacklistedTokens removes expired blacklisted tokens
func CleanupExpiredBlacklistedTokens() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	blacklistCol := getBlacklistedTokensCollection()
	result, err := blacklistCol.DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now()},
	})

	if err != nil {
		return err
	}

	if result.DeletedCount > 0 {
		log.Printf("Cleanup: Removed %d expired blacklisted tokens", result.DeletedCount)
	}

	return nil
}

// CleanupExpiredPasswordResetTokens removes expired tokens from database
func CleanupExpiredPasswordResetTokens() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := getPasswordResetTokensCollection().DeleteMany(ctx, bson.M{
		"expires_at": bson.M{"$lt": time.Now()},
	})

	return err
}

// MigrateUserNamesFromFullName migrates users who have FullName but empty separate name fields
func MigrateUserNamesFromFullName() error {
	ctx := context.Background()
	
	// Find users with FullName but without separate name fields
	cursor, err := usersCol.Find(ctx, bson.M{
		"full_name": bson.M{"$exists": true, "$ne": ""},
		"$or": []bson.M{
			{"last_name": bson.M{"$exists": false}},
			{"last_name": ""},
			{"first_name": bson.M{"$exists": false}},
			{"first_name": ""},
		},
	})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	var usersUpdated int
	for cursor.Next(ctx) {
		var user User
		if err := cursor.Decode(&user); err != nil {
			continue
		}

		// Simple name parsing - split by spaces
		parts := strings.Fields(strings.TrimSpace(user.FullName))
		if len(parts) == 0 {
			continue
		}

		var lastName, firstName, middleName string
		if len(parts) >= 1 {
			lastName = parts[0]
		}
		if len(parts) >= 2 {
			firstName = parts[1]
		}
		if len(parts) >= 3 {
			middleName = parts[2]
		}

		// Update user with parsed name fields
		update := bson.M{
			"$set": bson.M{
				"last_name":   lastName,
				"first_name":  firstName,
				"middle_name": middleName,
				"updated_at":  time.Now(),
			},
		}

		_, err := usersCol.UpdateOne(ctx, bson.M{"_id": user.ID}, update)
		if err != nil {
			log.Printf("Failed to update user %s: %v", user.Username, err)
			continue
		}

		usersUpdated++
		log.Printf("Migrated name fields for user %s: %s -> %s %s %s", 
			user.Username, user.FullName, lastName, firstName, middleName)
	}

	log.Printf("Migration completed: %d users updated with separated name fields", usersUpdated)
	return nil
}

// InvalidateAllUserSessions blacklists all active JWT tokens for a user
func InvalidateAllUserSessions(userID primitive.ObjectID, reason string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get user to determine current token expiration time
	user, err := GetUserByObjectID(userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %v", err)
	}

	// Create a blacklist entry that covers all tokens issued before NOW
	// This effectively invalidates all current sessions
	blacklistEntry := &BlacklistedToken{
		UserID:    userID,
		TokenHash: fmt.Sprintf("user_%s_all_sessions_%d", userID.Hex(), time.Now().Unix()),
		Reason:    reason,
		ExpiresAt: time.Now().Add(24 * time.Hour), // Keep blacklist entry for 24 hours
		CreatedAt: time.Now(),
	}

	blacklistCol := getBlacklistedTokensCollection()
	_, err = blacklistCol.InsertOne(ctx, blacklistEntry)
	if err != nil {
		return fmt.Errorf("failed to add blacklist entry: %v", err)
	}

	log.Printf("Security: Invalidated all sessions for user %s (ID: %s) - Reason: %s", 
		user.Username, userID.Hex(), reason)
	
	return nil
}

// IsTokenBlacklisted checks if a JWT token is blacklisted
func IsTokenBlacklisted(tokenString string) bool {
	// We'll implement a simple approach: if user has any blacklist entries
	// created after their last login, consider all their tokens invalid
	
	// Parse token to extract user ID and issued time
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			jwtSecret = "default_jwt_secret_change_in_production"
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		log.Printf("Warning: Failed to parse token for blacklist check: %v", err)
		return true // If we can't parse it, consider it invalid
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		log.Printf("Warning: Invalid token claims for blacklist check")
		return true
	}

	userID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		log.Printf("Warning: Invalid user ID in token: %v", err)
		return true
	}

	// Check if there are any blacklist entries for this user
	// that were created AFTER the token was issued (meaning session should be invalidated)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tokenIssuedAt := time.Unix(claims.IssuedAt, 0)
	
	blacklistCol := getBlacklistedTokensCollection()
	count, err := blacklistCol.CountDocuments(ctx, bson.M{
		"user_id": userID,
		"created_at": bson.M{
			"$gt": tokenIssuedAt, // Blacklist entries created AFTER token was issued
		},
		"expires_at": bson.M{
			"$gt": time.Now(), // And still active
		},
	})

	if err != nil {
		log.Printf("Warning: Failed to check blacklist: %v", err)
		return false // Don't block user if we can't check
	}

	isBlacklisted := count > 0
	if isBlacklisted {
		log.Printf("Security: Token issued at %v is blacklisted (found %d active blacklist entries)", 
			tokenIssuedAt, count)
	}

	return isBlacklisted
}

// ResetUserPassword generates a new temporary password for user
func ResetUserPassword(userID primitive.ObjectID) (string, error) {
	// Generate a new random password
	tempPassword := generateRandomPassword(12)
	
	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %v", err)
	}

	ctx := context.Background()
	_, err = usersCol.UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{
				"password":   string(hashedPassword),
				"updated_at": time.Now(),
			},
		},
	)

	if err != nil {
		return "", err
	}

	return tempPassword, nil
}

// generateRandomPassword generates a random password of specified length
func generateRandomPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	password := make([]byte, length)
	
	for i := range password {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		password[i] = charset[num.Int64()]
	}
	
	return string(password)
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// BanUser bans a user with reason
func BanUser(userID primitive.ObjectID, reason string) error {
	ctx := context.Background()
	now := time.Now()
	
	_, err := usersCol.UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{
				"is_banned":  true,
				"banned_at":  &now,
				"ban_reason": reason,
				"updated_at": time.Now(),
			},
		},
	)

	if err != nil {
		return fmt.Errorf("failed to ban user: %v", err)
	}

	log.Printf("User %s has been banned. Reason: %s", userID.Hex(), reason)
	return nil
}

// UnbanUser removes ban from user
func UnbanUser(userID primitive.ObjectID) error {
	ctx := context.Background()
	
	_, err := usersCol.UpdateOne(
		ctx,
		bson.M{"_id": userID},
		bson.M{
			"$set": bson.M{
				"is_banned":  false,
				"updated_at": time.Now(),
			},
			"$unset": bson.M{
				"banned_at":  "",
				"ban_reason": "",
			},
		},
	)

	if err != nil {
		return fmt.Errorf("failed to unban user: %v", err)
	}

	log.Printf("User %s has been unbanned", userID.Hex())
	return nil
}

// UserExportData represents user data for Excel export
type UserExportData struct {
	Username   string
	LastName   string
	FirstName  string
	MiddleName string
	Suffix     string
	Email      string
	Phone      string
	Roles      string
}

// ExportUsersToExcel creates an Excel file with user data
func ExportUsersToExcel(users []interface{}) (string, error) {
	file := excelize.NewFile()
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("Error closing Excel file: %v", err)
		}
	}()

	sheetName := "Users"
	index, err := file.NewSheet(sheetName)
	if err != nil {
		return "", fmt.Errorf("failed to create sheet: %v", err)
	}
	
	file.SetActiveSheet(index)

	// Headers
	headers := []string{
		"Username", "Фамилия", "Имя", "Отчество", "Частица", 
		"Email", "Телефон", "Роли в сервисах",
	}
	
	for i, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		file.SetCellValue(sheetName, cell, header)
	}

	// Style headers
	style, err := file.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
	})
	if err == nil {
		file.SetCellStyle(sheetName, "A1", fmt.Sprintf("H1"), style)
	}

	// Data rows
	for i, userData := range users {
		row := i + 2
		if user, ok := userData.(UserExportData); ok {
			file.SetCellValue(sheetName, fmt.Sprintf("A%d", row), user.Username)
			file.SetCellValue(sheetName, fmt.Sprintf("B%d", row), user.LastName)
			file.SetCellValue(sheetName, fmt.Sprintf("C%d", row), user.FirstName)
			file.SetCellValue(sheetName, fmt.Sprintf("D%d", row), user.MiddleName)
			file.SetCellValue(sheetName, fmt.Sprintf("E%d", row), user.Suffix)
			file.SetCellValue(sheetName, fmt.Sprintf("F%d", row), user.Email)
			file.SetCellValue(sheetName, fmt.Sprintf("G%d", row), user.Phone)
			file.SetCellValue(sheetName, fmt.Sprintf("H%d", row), user.Roles)
		}
	}

	// Auto-fit columns
	for i := 1; i <= len(headers); i++ {
		colName, _ := excelize.ColumnNumberToName(i)
		file.SetColWidth(sheetName, colName, colName, 15)
	}

	// Save to temporary file
	filename := fmt.Sprintf("users_export_%d.xlsx", time.Now().Unix())
	if err := file.SaveAs(filename); err != nil {
		return "", fmt.Errorf("failed to save file: %v", err)
	}

	return filename, nil
}

// GenerateUsersImportTemplate creates Excel template for user import
func GenerateUsersImportTemplate() (string, error) {
	file := excelize.NewFile()
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("Error closing Excel file: %v", err)
		}
	}()

	sheetName := "Template"
	index, err := file.NewSheet(sheetName)
	if err != nil {
		return "", fmt.Errorf("failed to create sheet: %v", err)
	}
	
	file.SetActiveSheet(index)

	// Headers
	headers := []string{
		"username", "last_name", "first_name", "middle_name", "suffix",
		"email", "phone", "position", "department", "password",
	}
	
	for i, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		file.SetCellValue(sheetName, cell, header)
	}

	// Instructions
	instructions := []string{
		"Заполните данные пользователей начиная со строки 2",
		"username - обязательно, уникальное имя пользователя",
		"last_name - обязательно, фамилия пользователя",
		"first_name - обязательно, имя пользователя", 
		"middle_name - отчество (необязательно)",
		"suffix - частица (Jr., Sr., III и т.д.)",
		"email - обязательно, уникальный email адрес",
		"phone - номер телефона в формате +998XXXXXXXXX",
		"position - должность (необязательно)",
		"department - отдел (необязательно)",
		"password - пароль (если не указан, будет сгенерирован автоматически)",
	}

	// Add instructions sheet
	instructionSheet := "Инструкции"
	_, err = file.NewSheet(instructionSheet)
	if err == nil {
		for i, instruction := range instructions {
			file.SetCellValue(instructionSheet, fmt.Sprintf("A%d", i+1), instruction)
		}
		file.SetColWidth(instructionSheet, "A", "A", 60)
	}

	// Style headers in template sheet
	style, err := file.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "#FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"#4472C4"}, Pattern: 1},
	})
	if err == nil {
		file.SetCellStyle(sheetName, "A1", fmt.Sprintf("J1"), style)
	}

	// Auto-fit columns in template
	for i := 1; i <= len(headers); i++ {
		colName, _ := excelize.ColumnNumberToName(i)
		file.SetColWidth(sheetName, colName, colName, 12)
	}

	// Add example data
	file.SetCellValue(sheetName, "A2", "john_doe")
	file.SetCellValue(sheetName, "B2", "Иванов")
	file.SetCellValue(sheetName, "C2", "Иван")
	file.SetCellValue(sheetName, "D2", "Иванович")
	file.SetCellValue(sheetName, "E2", "")
	file.SetCellValue(sheetName, "F2", "john.doe@example.com")
	file.SetCellValue(sheetName, "G2", "+998901234567")
	file.SetCellValue(sheetName, "H2", "Менеджер")
	file.SetCellValue(sheetName, "I2", "IT отдел")
	file.SetCellValue(sheetName, "J2", "password123")

	filename := fmt.Sprintf("users_import_template_%d.xlsx", time.Now().Unix())
	if err := file.SaveAs(filename); err != nil {
		return "", fmt.Errorf("failed to save template: %v", err)
	}

	return filename, nil
}

// UpdateUserComplete updates all user fields including roles
func UpdateUserComplete(user User) error {
	ctx := context.Background()
	
	filter := bson.M{"_id": user.ID}
	update := bson.M{
		"$set": bson.M{
			"username":     user.Username,
			"email":        user.Email,
			"last_name":    user.LastName,
			"first_name":   user.FirstName,
			"middle_name":  user.MiddleName,
			"suffix":       user.Suffix,
			"phone":        user.Phone,
			"position":     user.Position,
			"department":   user.Department,
			"roles":        user.Roles,
			"updated_at":   user.UpdatedAt,
		},
	}
	
	// Only update password if it's not empty
	if user.Password != "" {
		update["$set"].(bson.M)["password"] = user.Password
	}
	
	_, err := usersCol.UpdateOne(ctx, filter, update)
	return err
}

// DeactivateUserServiceRoles deactivates all service roles for a user
func DeactivateUserServiceRoles(userID primitive.ObjectID) error {
	ctx := context.Background()
	
	filter := bson.M{
		"user_id":   userID,
		"is_active": true,
	}
	
	update := bson.M{
		"$set": bson.M{
			"is_active": false,
		},
	}
	
	_, err := userServiceRolesCol.UpdateMany(ctx, filter, update)
	return err
}

// CreateUserFromStruct creates a user from a User struct
func CreateUserFromStruct(user User) (primitive.ObjectID, error) {
	ctx := context.Background()
	
	result, err := usersCol.InsertOne(ctx, user)
	if err != nil {
		return primitive.NilObjectID, err
	}
	
	return result.InsertedID.(primitive.ObjectID), nil
}

// UpdateUserDocuments updates the documents field for a user
func UpdateUserDocuments(userID primitive.ObjectID, documents []UserDocument) error {
	ctx := context.Background()
	
	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"documents":  documents,
			"updated_at": time.Now(),
		},
	}
	
	_, err := usersCol.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update user documents: %v", err)
	}
	
	return nil
}

// GetUserPermissionsForService returns all permissions for a user in a specific service
func GetUserPermissionsForService(userID primitive.ObjectID, serviceKey string) ([]string, error) {
	ctx := context.Background()
	
	// Get user's active roles in the service
	pipeline := []bson.M{
		{
			"$match": bson.M{
				"userId":     userID,
				"serviceKey": serviceKey,
				"isActive":   true,
			},
		},
		{
			"$lookup": bson.M{
				"from": "roles",
				"let":  bson.M{"roleName": "$roleName", "serviceKey": "$serviceKey"},
				"pipeline": []bson.M{
					{
						"$match": bson.M{
							"$expr": bson.M{
								"$and": []bson.M{
									{"$eq": []interface{}{"$name", "$$roleName"}},
									{"$eq": []interface{}{"$service", "$$serviceKey"}},
								},
							},
						},
					},
				},
				"as": "roleDetails",
			},
		},
		{
			"$match": bson.M{
				"roleDetails": bson.M{"$ne": []interface{}{}},
			},
		},
	}
	
	cursor, err := userServiceRolesCol.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate user service roles: %v", err)
	}
	defer cursor.Close(ctx)
	
	permissionSet := make(map[string]bool)
	
	for cursor.Next(ctx) {
		var result struct {
			RoleDetails []struct {
				Permissions []string `bson:"permissions"`
			} `bson:"roleDetails"`
		}
		
		if err := cursor.Decode(&result); err != nil {
			continue
		}
		
		// Collect all permissions from all roles
		for _, role := range result.RoleDetails {
			for _, permission := range role.Permissions {
				permissionSet[permission] = true
			}
		}
	}
	
	// Convert set to slice
	permissions := make([]string, 0, len(permissionSet))
	for perm := range permissionSet {
		permissions = append(permissions, perm)
	}
	
	return permissions, nil
}

// GetUserRolesForService returns all role names for a user in a specific service
func GetUserRolesForService(userID primitive.ObjectID, serviceKey string) ([]string, error) {
	ctx := context.Background()
	
	filter := bson.M{
		"userId":     userID,
		"serviceKey": serviceKey,
		"isActive":   true,
	}
	
	cursor, err := userServiceRolesCol.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find user service roles: %v", err)
	}
	defer cursor.Close(ctx)
	
	var roles []string
	for cursor.Next(ctx) {
		var usr UserServiceRole
		if err := cursor.Decode(&usr); err != nil {
			continue
		}
		roles = append(roles, usr.RoleName)
	}
	
	return roles, nil
}

// GetUserDocuments returns all documents for a user
func GetUserDocuments(userID string) ([]UserDocument, error) {
	ctx := context.Background()
	
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, err
	}
	
	var user User
	err = usersCol.FindOne(ctx, bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		return nil, err
	}
	
	return user.Documents, nil
}

