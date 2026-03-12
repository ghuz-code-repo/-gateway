package models

import (
	"log"
	"os"
	"sync"
)

var (
	jwtSecretOnce sync.Once
	jwtSecretKey  []byte
)

// GetJWTSecret returns the JWT signing key.
// Reads from JWT_SECRET env var. Logs a fatal warning if not set in production.
// Caches the result for subsequent calls.
func GetJWTSecret() []byte {
	jwtSecretOnce.Do(func() {
		secret := os.Getenv("JWT_SECRET")
		if secret == "" {
			env := os.Getenv("ENVIRONMENT")
			if env == "production" {
				log.Fatal("FATAL: JWT_SECRET environment variable is not set in production!")
			}
			log.Println("WARNING: JWT_SECRET not set, using default development secret. DO NOT use in production!")
			secret = "default_jwt_secret_change_in_production"
		}
		jwtSecretKey = []byte(secret)
	})
	return jwtSecretKey
}
