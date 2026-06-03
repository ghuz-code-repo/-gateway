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
		return fmt.Errorf("имя пользователя не может быть пустым")
	}
	
	// Length check
	if len(username) < 3 || len(username) > 50 {
		return fmt.Errorf("имя пользователя должно содержать от 3 до 50 символов")
	}
	
	// Only allow letters, numbers, dots, dashes and underscores
	validUsernameRegex := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if !validUsernameRegex.MatchString(username) {
		return fmt.Errorf("имя пользователя может содержать только буквы, цифры, точки, дефисы и подчёркивания")
	}
	
	// Don't allow usernames starting or ending with special characters
	if strings.HasPrefix(username, ".") || strings.HasPrefix(username, "-") || 
	   strings.HasPrefix(username, "_") || strings.HasSuffix(username, ".") || 
	   strings.HasSuffix(username, "-") || strings.HasSuffix(username, "_") {
		return fmt.Errorf("имя пользователя не может начинаться или заканчиваться специальными символами")
	}
	
	return nil
}

// ValidateEmail validates email format
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email не может быть пустым")
	}
	
	// Basic email validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("неверный формат email")
	}
	
	if len(email) > 254 {
		return fmt.Errorf("email слишком длинный")
	}
	
	return nil
}

// ValidatePassword validates password strength
func ValidatePassword(password string) error {
	if password == "" {
		return fmt.Errorf("пароль не может быть пустым")
	}
	
	// Minimum length
	if len(password) < 8 {
		return fmt.Errorf("пароль должен содержать не менее 8 символов")
	}
	
	// Maximum length (to prevent DoS)
	if len(password) > 128 {
		return fmt.Errorf("пароль слишком длинный (максимум 128 символов)")
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
		return fmt.Errorf("пароль должен содержать хотя бы одну заглавную букву")
	}
	if !hasLower {
		return fmt.Errorf("пароль должен содержать хотя бы одну строчную букву")
	}
	if !hasDigit {
		return fmt.Errorf("пароль должен содержать хотя бы одну цифру")
	}
	
	return nil
}

// ValidateServiceKey validates service key format
func ValidateServiceKey(serviceKey string) error {
	if serviceKey == "" {
		return fmt.Errorf("ключ сервиса не может быть пустым")
	}
	
	// Only allow lowercase letters, numbers and dashes
	validServiceKeyRegex := regexp.MustCompile(`^[a-z0-9-]+$`)
	if !validServiceKeyRegex.MatchString(serviceKey) {
		return fmt.Errorf("ключ сервиса может содержать только строчные буквы, цифры и дефисы")
	}
	
	if len(serviceKey) < 2 || len(serviceKey) > 50 {
		return fmt.Errorf("ключ сервиса должен содержать от 2 до 50 символов")
	}
	
	return nil
}

// ValidateRoleName validates role name format
func ValidateRoleName(roleName string) error {
	if roleName == "" {
		return fmt.Errorf("название роли не может быть пустым")
	}
	
	// Allow letters, numbers, dots and underscores
	validRoleNameRegex := regexp.MustCompile(`^[a-zA-Z0-9._]+$`)
	if !validRoleNameRegex.MatchString(roleName) {
		return fmt.Errorf("название роли может содержать только буквы, цифры, точки и подчёркивания")
	}
	
	if len(roleName) < 2 || len(roleName) > 50 {
		return fmt.Errorf("название роли должно содержать от 2 до 50 символов")
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
		return fmt.Errorf("идентификатор объекта не может быть пустым")
	}
	
	// MongoDB ObjectID is 24 character hex string
	if len(id) != 24 {
		return fmt.Errorf("неверная длина идентификатора объекта")
	}
	
	validHexRegex := regexp.MustCompile(`^[0-9a-fA-F]{24}$`)
	if !validHexRegex.MatchString(id) {
		return fmt.Errorf("неверный формат идентификатора объекта")
	}
	
	return nil
}
