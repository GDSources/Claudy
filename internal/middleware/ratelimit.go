package middleware

import (
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimitConfig holds configuration for rate limiting middleware
type RateLimitConfig struct {
	RequestsPerMinute int                              // Number of requests allowed per minute
	BurstSize         int                              // Maximum number of requests allowed in a burst
	KeyFunc           func(c *gin.Context) string      // Function to generate rate limit key (e.g., IP, user ID)
	OnLimitReached    func(c *gin.Context)             // Handler called when rate limit is exceeded
}

// rateLimiter holds the rate limiting state for a single key
type rateLimiter struct {
	tokens     int       // Current number of available tokens
	lastRefill time.Time // Last time tokens were refilled
	mutex      sync.Mutex
}

// RateLimitMiddleware manages rate limiting for different keys
type RateLimitMiddleware struct {
	config   RateLimitConfig
	limiters map[string]*rateLimiter
	mutex    sync.RWMutex
}

// NewRateLimitMiddleware creates a new rate limiting middleware
func NewRateLimitMiddleware(config RateLimitConfig) gin.HandlerFunc {
	middleware := &RateLimitMiddleware{
		config:   config,
		limiters: make(map[string]*rateLimiter),
	}

	return func(c *gin.Context) {
		key := config.KeyFunc(c)
		if key == "" {
			// If no key is generated, skip rate limiting
			c.Next()
			return
		}

		allowed, remaining, resetTime := middleware.checkRateLimit(key)
		
		// Set rate limit headers
		c.Header("X-RateLimit-Limit", strconv.Itoa(config.RequestsPerMinute))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

		if !allowed {
			// Rate limit exceeded
			config.OnLimitReached(c)
			c.Abort()
			return
		}

		c.Next()
	}
}

// checkRateLimit checks if a request should be allowed based on the rate limit
func (rlm *RateLimitMiddleware) checkRateLimit(key string) (allowed bool, remaining int, resetTime time.Time) {
	now := time.Now()
	
	// Get or create rate limiter for this key
	limiter := rlm.getLimiter(key)
	
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	
	// Calculate how many tokens to add based on time passed
	timePassed := now.Sub(limiter.lastRefill)
	tokensToAdd := int(timePassed.Minutes() * float64(rlm.config.RequestsPerMinute))
	
	if tokensToAdd > 0 {
		limiter.tokens += tokensToAdd
		if limiter.tokens > rlm.config.BurstSize {
			limiter.tokens = rlm.config.BurstSize
		}
		limiter.lastRefill = now
	}
	
	// Check if request can be allowed
	if limiter.tokens > 0 {
		limiter.tokens--
		remaining = limiter.tokens
		allowed = true
	} else {
		remaining = 0
		allowed = false
	}
	
	// Calculate reset time (next minute boundary)
	resetTime = now.Add(time.Minute).Truncate(time.Minute)
	
	return allowed, remaining, resetTime
}

// getLimiter gets or creates a rate limiter for the given key
func (rlm *RateLimitMiddleware) getLimiter(key string) *rateLimiter {
	rlm.mutex.RLock()
	limiter, exists := rlm.limiters[key]
	rlm.mutex.RUnlock()
	
	if exists {
		return limiter
	}
	
	// Create new limiter
	rlm.mutex.Lock()
	defer rlm.mutex.Unlock()
	
	// Double-check after acquiring write lock
	if limiter, exists := rlm.limiters[key]; exists {
		return limiter
	}
	
	limiter = &rateLimiter{
		tokens:     rlm.config.BurstSize,
		lastRefill: time.Now(),
	}
	rlm.limiters[key] = limiter
	
	return limiter
}