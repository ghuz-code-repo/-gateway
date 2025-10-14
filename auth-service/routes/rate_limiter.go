package routes

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// LoginAttempt tracks login attempts for rate limiting
type LoginAttempt struct {
	Count     int
	ResetTime time.Time
}

var (
	// loginAttempts stores login attempts by IP address
	loginAttempts = make(map[string]*LoginAttempt)
	// mutex for thread-safe access to loginAttempts
	loginMutex sync.RWMutex
	// Max login attempts per window
	maxLoginAttempts = 5
	// Time window for rate limiting (1 minute)
	loginRateWindow = 1 * time.Minute
	// cleanupOnce ensures cleanup goroutine starts only once
	cleanupOnce sync.Once
)

// RateLimitMiddleware implements rate limiting for login attempts
func RateLimitMiddleware() gin.HandlerFunc {
	// Start cleanup goroutine once
	cleanupOnce.Do(func() {
		go cleanupExpiredAttempts()
	})
	
	return func(c *gin.Context) {
		ip := c.ClientIP()
		
		loginMutex.RLock()
		attempt, exists := loginAttempts[ip]
		loginMutex.RUnlock()
		
		now := time.Now()
		
		// Check if rate limit exceeded
		if exists && !now.After(attempt.ResetTime) && attempt.Count >= maxLoginAttempts {
			remainingTime := time.Until(attempt.ResetTime)
			c.HTML(http.StatusTooManyRequests, "login_clean.html", gin.H{
				"error": "Слишком много попыток входа. Попробуйте снова через " + 
					formatDuration(remainingTime) + ".",
				"redirect": c.Query("redirect"),
			})
			c.Abort()
			return
		}
		
		// Allow the request to proceed
		c.Next()
	}
}

// RecordFailedLogin increments failed login attempts (called on failed login)
func RecordFailedLogin(ip string) {
	loginMutex.Lock()
	defer loginMutex.Unlock()
	
	now := time.Now()
	attempt, exists := loginAttempts[ip]
	
	if !exists || now.After(attempt.ResetTime) {
		// Create new attempt record
		loginAttempts[ip] = &LoginAttempt{
			Count:     1,
			ResetTime: now.Add(loginRateWindow),
		}
	} else {
		// Increment existing attempt count
		attempt.Count++
	}
}

// ResetLoginAttempts resets login attempts for a specific IP (called on successful login)
func ResetLoginAttempts(ip string) {
	loginMutex.Lock()
	defer loginMutex.Unlock()
	delete(loginAttempts, ip)
}

// cleanupExpiredAttempts removes expired attempt records periodically
func cleanupExpiredAttempts() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		loginMutex.Lock()
		now := time.Now()
		for ip, attempt := range loginAttempts {
			if now.After(attempt.ResetTime) {
				delete(loginAttempts, ip)
			}
		}
		loginMutex.Unlock()
	}
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	seconds := int(d.Seconds())
	if seconds < 60 {
		return "несколько секунд"
	}
	minutes := seconds / 60
	if minutes == 1 {
		return "1 минуту"
	}
	return "несколько минут"
}
