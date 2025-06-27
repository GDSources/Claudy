package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSConfig holds configuration for CORS middleware
type CORSConfig struct {
	AllowedOrigins   []string // List of allowed origins
	AllowedMethods   []string // List of allowed HTTP methods
	AllowedHeaders   []string // List of allowed headers
	ExposedHeaders   []string // List of headers to expose to the client
	AllowCredentials bool     // Whether to allow credentials
	MaxAge           int      // Max age for preflight cache in seconds
}

// NewCORSMiddleware creates a new CORS middleware with the given configuration
func NewCORSMiddleware(config CORSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		
		// Handle same-origin requests (no Origin header)
		if origin == "" {
			c.Next()
			return
		}
		
		// Check if origin is allowed
		if !isOriginAllowed(origin, config.AllowedOrigins) {
			// Origin not allowed, continue without CORS headers
			c.Next()
			return
		}
		
		// Handle preflight OPTIONS request
		if c.Request.Method == "OPTIONS" {
			handlePreflightRequest(c, config, origin)
			return
		}
		
		// Handle actual CORS request
		handleActualRequest(c, config, origin)
		c.Next()
	}
}

// isOriginAllowed checks if the given origin is in the allowed origins list
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	for _, allowedOrigin := range allowedOrigins {
		if origin == allowedOrigin {
			return true
		}
	}
	return false
}

// handlePreflightRequest handles CORS preflight OPTIONS requests
func handlePreflightRequest(c *gin.Context, config CORSConfig, origin string) {
	requestMethod := c.GetHeader("Access-Control-Request-Method")
	requestHeaders := c.GetHeader("Access-Control-Request-Headers")
	
	// Validate requested method
	if requestMethod != "" && !isMethodAllowed(requestMethod, config.AllowedMethods) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	
	// Validate requested headers
	if requestHeaders != "" && !areHeadersAllowed(requestHeaders, config.AllowedHeaders) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	
	// Set CORS headers for successful preflight
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
	c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
	
	if config.AllowCredentials {
		c.Header("Access-Control-Allow-Credentials", "true")
	}
	
	if config.MaxAge > 0 {
		c.Header("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
	}
	
	c.AbortWithStatus(http.StatusNoContent)
}

// handleActualRequest handles actual CORS requests
func handleActualRequest(c *gin.Context, config CORSConfig, origin string) {
	// Set CORS headers for actual request
	c.Header("Access-Control-Allow-Origin", origin)
	
	if len(config.ExposedHeaders) > 0 {
		c.Header("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
	}
	
	if config.AllowCredentials {
		c.Header("Access-Control-Allow-Credentials", "true")
	}
}

// isMethodAllowed checks if the given method is in the allowed methods list
func isMethodAllowed(method string, allowedMethods []string) bool {
	for _, allowedMethod := range allowedMethods {
		if method == allowedMethod {
			return true
		}
	}
	return false
}

// areHeadersAllowed checks if all requested headers are in the allowed headers list
func areHeadersAllowed(requestHeaders string, allowedHeaders []string) bool {
	headers := strings.Split(requestHeaders, ",")
	for _, header := range headers {
		header = strings.TrimSpace(header)
		if header != "" && !isHeaderAllowed(header, allowedHeaders) {
			return false
		}
	}
	return true
}

// isHeaderAllowed checks if the given header is in the allowed headers list
func isHeaderAllowed(header string, allowedHeaders []string) bool {
	for _, allowedHeader := range allowedHeaders {
		if strings.EqualFold(header, allowedHeader) {
			return true
		}
	}
	return false
}