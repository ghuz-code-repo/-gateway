package models

import (
	"context"
	"fmt"
	"log"
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
	client   *mongo.Client
	db       *mongo.Database
	usersCol *mongo.Collection
	rolesCol *mongo.Collection
	permsCol *mongo.Collection
)

// User struct represents a user in the system
type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username string             `bson:"username" json:"username"`
	Email    string             `bson:"email" json:"email"`
	Password string             `bson:"password" json:"-"`          // Never return password in JSON
	Roles    []string           `bson:"roles" json:"roles"`         // Store role names
	FullName string             `bson:"full_name" json:"full_name"` // Add full name field
}

// Claims struct for JWT
type Claims struct {
	Username string `json:"username"`
	UserID   string `json:"user_id"`
	jwt.StandardClaims
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

	// Create indexes for unique fields
	_, err = usersCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"username", 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("Warning: Failed to create username index: %v", err)
	}
	_, err = rolesCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"name", 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("Warning: Failed to create role name index: %v", err)
	}
	_, err = permsCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"service", 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("Warning: Failed to create service index: %v", err)
	}

	// Create default permissions
	CreateDefaultPermissions()

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

	// Ensure admin role
	var adminRole Role
	err := rolesCol.FindOne(ctx, bson.M{"name": "admin"}).Decode(&adminRole)
	if err == mongo.ErrNoDocuments {
		// Create admin role
		adminRole = Role{
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
