package middleware

import (
	"github.com/gin-gonic/gin"
)

// MiddlewareConfig holds configuration for all middleware components
type MiddlewareConfig struct {
	CORS      CORSConfig      // CORS middleware configuration
	RateLimit RateLimitConfig // Rate limiting middleware configuration
	Security  SecurityConfig  // Security headers middleware configuration
}

// ApplyMiddleware applies all configured middleware to a Gin router in the optimal order
func ApplyMiddleware(router *gin.Engine, config MiddlewareConfig) {
	// Apply middleware in optimal order:
	// 1. Security headers first (applied to all responses)
	// 2. CORS second (handles preflight requests early)
	// 3. Rate limiting third (after CORS validation)
	
	// Security headers middleware
	router.Use(NewSecurityHeadersMiddleware(config.Security))
	
	// CORS middleware
	router.Use(NewCORSMiddleware(config.CORS))
	
	// Rate limiting middleware
	router.Use(NewRateLimitMiddleware(config.RateLimit))
}

// DefaultMiddlewareConfig returns a sensible default configuration for all middleware
func DefaultMiddlewareConfig() MiddlewareConfig {
	return MiddlewareConfig{
		Security: SecurityConfig{
			ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
			XFrameOptions:         "DENY",
			XContentTypeOptions:   "nosniff",
			ReferrerPolicy:        "strict-origin-when-cross-origin",
			StrictTransportSecurity: StrictTransportSecurityConfig{
				MaxAge:            31536000, // 1 year
				IncludeSubDomains: true,
				Preload:           true,
			},
			XSSProtection: XSSProtectionConfig{
				Enable: true,
				Mode:   "block",
			},
			PermissionsPolicy: map[string][]string{
				"camera":      {"'none'"},
				"microphone":  {"'none'"},
				"geolocation": {"'self'"},
				"payment":     {"'none'"},
				"usb":         {"'none'"},
			},
		},
		CORS: CORSConfig{
			AllowedOrigins:   []string{"https://localhost:3000", "https://app.claudy.dev"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Requested-With"},
			ExposedHeaders:   []string{"X-Total-Count", "X-Request-ID"},
			AllowCredentials: true,
			MaxAge:           3600, // 1 hour
		},
		RateLimit: RateLimitConfig{
			RequestsPerMinute: 100,
			BurstSize:         20,
			KeyFunc: func(c *gin.Context) string {
				// Use IP address as the default rate limiting key
				return c.ClientIP()
			},
			OnLimitReached: func(c *gin.Context) {
				c.JSON(429, gin.H{
					"error":   "rate_limit_exceeded",
					"message": "Too many requests, please try again later",
				})
			},
		},
	}
}