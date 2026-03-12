package models

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// ValidateUsername validates username format
func ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	
	// Length check
	if len(username) < 3 || len(username) > 50 {
		return fmt.Errorf("username must be between 3 and 50 characters")
	}
	
	// Only allow letters, numbers, dots, dashes and underscores
	validUsernameRegex := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if !validUsernameRegex.MatchString(username) {
		return fmt.Errorf("username can only contain letters, numbers, dots, dashes and underscores")
	}
	
	// Don't allow usernames starting or ending with special characters
	if strings.HasPrefix(username, ".") || strings.HasPrefix(username, "-") || 
	   strings.HasPrefix(username, "_") || strings.HasSuffix(username, ".") || 
	   strings.HasSuffix(username, "-") || strings.HasSuffix(username, "_") {
		return fmt.Errorf("username cannot start or end with special characters")
	}
	
	return nil
}

// ValidateEmail validates email format
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}
	
	// Basic email validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	
	if len(email) > 254 {
		return fmt.Errorf("email is too long")
	}
	
	return nil
}

// ValidatePassword validates password strength
func ValidatePassword(password string) error {
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	
	// Minimum length
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	
	// Maximum length (to prevent DoS)
	if len(password) > 128 {
		return fmt.Errorf("password is too long (max 128 characters)")
	}
	
	// Check for at least one uppercase letter
	hasUpper := false
	hasLower := false
	hasDigit := false
	
	for _, char := range password {
		if unicode.IsUpper(char) {
			hasUpper = true
		}
		if unicode.IsLower(char) {
			hasLower = true
		}
		if unicode.IsDigit(char) {
			hasDigit = true
		}
	}
	
	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	
	return nil
}

// ValidateServiceKey validates service key format
func ValidateServiceKey(serviceKey string) error {
	if serviceKey == "" {
		return fmt.Errorf("service key cannot be empty")
	}
	
	// Only allow lowercase letters, numbers and dashes
	validServiceKeyRegex := regexp.MustCompile(`^[a-z0-9-]+$`)
	if !validServiceKeyRegex.MatchString(serviceKey) {
		return fmt.Errorf("service key can only contain lowercase letters, numbers and dashes")
	}
	
	if len(serviceKey) < 2 || len(serviceKey) > 50 {
		return fmt.Errorf("service key must be between 2 and 50 characters")
	}
	
	return nil
}

// ValidateRoleName validates role name format
func ValidateRoleName(roleName string) error {
	if roleName == "" {
		return fmt.Errorf("role name cannot be empty")
	}
	
	// Allow letters, numbers, dots and underscores
	validRoleNameRegex := regexp.MustCompile(`^[a-zA-Z0-9._]+$`)
	if !validRoleNameRegex.MatchString(roleName) {
		return fmt.Errorf("role name can only contain letters, numbers, dots and underscores")
	}
	
	if len(roleName) < 2 || len(roleName) > 50 {
		return fmt.Errorf("role name must be between 2 and 50 characters")
	}
	
	return nil
}

// SanitizeString removes potentially dangerous characters from string
func SanitizeString(input string) string {
	// Remove null bytes and other control characters
	cleaned := strings.Map(func(r rune) rune {
		if r == 0 || (r < 32 && r != '\n' && r != '\r' && r != '\t') {
			return -1
		}
		return r
	}, input)
	
	return strings.TrimSpace(cleaned)
}

// ValidateObjectIDHex validates if a string is a valid MongoDB ObjectID hex string
func ValidateObjectIDHex(id string) error {
	if id == "" {
		return fmt.Errorf("object ID cannot be empty")
	}
	
	// MongoDB ObjectID is 24 character hex string
	if len(id) != 24 {
		return fmt.Errorf("invalid object ID length")
	}
	
	validHexRegex := regexp.MustCompile(`^[0-9a-fA-F]{24}$`)
	if !validHexRegex.MatchString(id) {
		return fmt.Errorf("invalid object ID format")
	}
	
	return nil
}
