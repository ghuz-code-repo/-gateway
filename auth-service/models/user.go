package models

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
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
	permsCol            *mongo.Collection
	servicesCol         *mongo.Collection
	userServiceRolesCol *mongo.Collection
	documentTypesCol    *mongo.Collection
)

// DocumentType represents a document type configuration
type DocumentType struct {
	ID          string            `bson:"_id" json:"id"`
	Name        string            `bson:"name" json:"name"`
	Description string            `bson:"description" json:"description"`
	Fields      []DocumentField   `bson:"fields" json:"fields"`
	IsActive    bool              `bson:"is_active" json:"is_active"`
	Order       int               `bson:"order" json:"order"`
	CreatedAt   time.Time         `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time         `bson:"updated_at" json:"updated_at"`
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
	ID          primitive.ObjectID           `bson:"_id,omitempty" json:"id"`
	DocumentType string                      `bson:"document_type" json:"document_type"`
	Title       string                       `bson:"title" json:"title"`
	Fields      map[string]interface{}       `bson:"fields" json:"fields"`
	Attachments []DocumentAttachment         `bson:"attachments" json:"attachments"`
	Status      string                       `bson:"status" json:"status"` // draft, completed, archived
	CreatedAt   time.Time                    `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time                    `bson:"updated_at" json:"updated_at"`
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
	FullName   string             `bson:"full_name" json:"full_name"` // Add full name field
	Phone      string             `bson:"phone,omitempty" json:"phone,omitempty"`
	Position   string             `bson:"position,omitempty" json:"position,omitempty"`
	Department string             `bson:"department,omitempty" json:"department,omitempty"`
	AvatarPath string             `bson:"avatar_path,omitempty" json:"avatar_path,omitempty"`
	OriginalAvatarPath string     `bson:"original_avatar_path,omitempty" json:"original_avatar_path,omitempty"`
	CropCoordinates    *CropCoords `bson:"crop_coordinates,omitempty" json:"crop_coordinates,omitempty"`
	Documents  []UserDocument     `bson:"documents,omitempty" json:"documents,omitempty"`      // New document system
	LegacyDocs []Document         `bson:"legacy_docs,omitempty" json:"legacy_docs,omitempty"` // Legacy documents
	CreatedAt  time.Time          `bson:"created_at,omitempty" json:"created_at,omitempty"`
	UpdatedAt  time.Time          `bson:"updated_at,omitempty" json:"updated_at,omitempty"`
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

// EnsureAdminExists creates an admin user and role if not present
func EnsureAdminExists() {
	ctx := context.Background()

	// Create default permissions if needed
	CreateDefaultPermissions()

	// Ensure admin role (system-wide role)
	var adminRole Role
	err := rolesCol.FindOne(ctx, bson.M{"service": "system", "name": "admin"}).Decode(&adminRole)
	if err == mongo.ErrNoDocuments {
		// Create admin role
		adminRole = Role{
			ServiceKey:  "system",
			Name:        "admin",
			Description: "Administrator",
			Permissions: []string{},
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
			log.Println("Created admin role with all permissions")
			adminRole.ID = result.InsertedID.(primitive.ObjectID)
		}
	}

	// Always ensure admin user has all permissions
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
						bson.M{"name": "admin"},
						bson.M{"$set": bson.M{"permissions": permServices}},
					)
					if err != nil {
						log.Printf("Warning: Failed to update admin role permissions: %v", err)
					}
				}
			}
			cursor.Close(ctx)
		}
	}

	// Ensure admin user exists with password "admin"
	var count int64
	count, err = usersCol.CountDocuments(ctx, bson.M{"username": "admin"})
	if err != nil || count == 0 {
		// Create admin user with password "admin"
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Warning: Failed to hash password: %v", err)
			return
		}

		adminUser := User{
			Username: "admin",
			Email:    "admin@example.com",
			Password: string(hashedPassword),
			Roles:    []string{"admin"},
		}

		_, err = usersCol.InsertOne(ctx, adminUser)
		if err != nil {
			log.Printf("Warning: Failed to create admin user: %v", err)
			return
		}

		log.Println("Created admin user with password: admin")
	} else {
		// Update admin password to ensure it's "admin"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		_, err = usersCol.UpdateOne(
			ctx,
			bson.M{"username": "admin"},
			bson.M{"$set": bson.M{"password": string(hashedPassword)}},
		)
		if err != nil {
			log.Printf("Warning: Failed to update admin password: %v", err)
		} else {
			log.Println("Reset admin user password to: admin")
		}
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
	err := usersCol.FindOne(ctx, bson.M{"username": username}).Decode(&user)
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
	claims := &Claims{
		Username: user.Username,
		UserID:   user.ID.Hex(),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
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

		go SendEmailNotification(email, subject, body)
	}

	return nil
}

// DeleteUser deletes a user from the database
func DeleteUser(id primitive.ObjectID) error {
	// Get the user first so we have their email
	user, err := GetUserByObjectID(id)
	if err != nil {
		return fmt.Errorf("user not found: %v", err)
	}

	// Store user data before deletion for email
	email := user.Email
	username := user.Username
	fullName := user.FullName

	// Get a handle to the users collection
	collection := client.Database("authdb").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Delete the user
	_, err = collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}

	// Send email notification if email is available
	if email != "" {
		// Get Russian email template
		subject, body := GetAccountDeletedEmail(fullName, username)

		go SendEmailNotification(email, subject, body)
	}

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
		FullName: fullName, // Set full name
	}

	result, err := usersCol.InsertOne(ctx, user)
	if err != nil {
		return primitive.NilObjectID, err
	}

	// Add email notification after successful user creation
	if err == nil && email != "" {
		// Get Russian email template
		subject, body := GetAccountCreatedEmail(fullName, username, password, roleNames)

		SendEmailNotification(email, subject, body)
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
func UpdateUserProfile(userID primitive.ObjectID, email, fullName, phone, position, department string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

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

	_, err := usersCol.UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
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
