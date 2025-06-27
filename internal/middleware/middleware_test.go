package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestApplyMiddleware(t *testing.T) {
	// Test the convenience function for applying all middleware
	gin.SetMode(gin.TestMode)

	router := gin.New()
	config := DefaultMiddlewareConfig()
	
	// Override some defaults for testing
	config.CORS.AllowedOrigins = []string{"https://test.com"}
	config.RateLimit.BurstSize = 2
	
	ApplyMiddleware(router, config)
	
	router.GET("/api/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	t.Run("all_middleware_applied", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Origin", "https://test.com")
		req.RemoteAddr = "192.168.1.200:12345"

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

		// Check that all middleware is applied
		// Security headers
		assert.NotEmpty(t, w.Header().Get("Content-Security-Policy"), "Should have security headers")
		assert.NotEmpty(t, w.Header().Get("X-Frame-Options"), "Should have frame options")
		
		// CORS headers
		assert.Equal(t, "https://test.com", w.Header().Get("Access-Control-Allow-Origin"), "Should have CORS headers")
		
		// Rate limit headers
		assert.Equal(t, "100", w.Header().Get("X-RateLimit-Limit"), "Should have rate limit headers")
	})
}

func TestDefaultMiddlewareConfig(t *testing.T) {
	// Test that default configuration is valid
	config := DefaultMiddlewareConfig()

	// Check security config
	assert.NotEmpty(t, config.Security.ContentSecurityPolicy, "Should have default CSP")
	assert.Equal(t, "DENY", config.Security.XFrameOptions, "Should have secure frame options")
	assert.True(t, config.Security.XSSProtection.Enable, "Should enable XSS protection")
	assert.True(t, config.Security.StrictTransportSecurity.IncludeSubDomains, "Should include subdomains in HSTS")

	// Check CORS config
	assert.NotEmpty(t, config.CORS.AllowedOrigins, "Should have allowed origins")
	assert.Contains(t, config.CORS.AllowedMethods, "GET", "Should allow GET")
	assert.Contains(t, config.CORS.AllowedMethods, "POST", "Should allow POST")
	assert.True(t, config.CORS.AllowCredentials, "Should allow credentials")

	// Check rate limit config
	assert.Greater(t, config.RateLimit.RequestsPerMinute, 0, "Should have positive rate limit")
	assert.Greater(t, config.RateLimit.BurstSize, 0, "Should have positive burst size")
	assert.NotNil(t, config.RateLimit.KeyFunc, "Should have key function")
	assert.NotNil(t, config.RateLimit.OnLimitReached, "Should have limit handler")

	// Test key function works
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request.RemoteAddr = "127.0.0.1:12345"
	
	key := config.RateLimit.KeyFunc(c)
	assert.NotEmpty(t, key, "Key function should return a key")
}