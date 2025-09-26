package handlers

import (
	"math/rand"
	"time"
)

// generateComplexPassword generates a secure password with uppercase, lowercase, digits and special characters
func generateComplexPassword() string {
	const (
		uppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lowercaseLetters = "abcdefghijklmnopqrstuvwxyz"
		digits           = "0123456789"
		specialChars     = "!@#$%^&*()_+-=[]{}|;:,.<>?"
		passwordLength   = 12
	)

	// Ensure at least one character from each category
	password := make([]byte, passwordLength)
	
	// Use time-based seed for randomization with standard library
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	
	// Add at least one character from each category
	password[0] = uppercaseLetters[rng.Intn(len(uppercaseLetters))]
	password[1] = lowercaseLetters[rng.Intn(len(lowercaseLetters))]
	password[2] = digits[rng.Intn(len(digits))]
	password[3] = specialChars[rng.Intn(len(specialChars))]

	// Fill the rest with random characters from all categories
	allChars := uppercaseLetters + lowercaseLetters + digits + specialChars
	for i := 4; i < passwordLength; i++ {
		password[i] = allChars[rng.Intn(len(allChars))]
	}

	// Shuffle the password to avoid predictable patterns
	for i := passwordLength - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		password[i], password[j] = password[j], password[i]
	}

	return string(password)
}