package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestMiddlewareIntegration(t *testing.T) {
	// Test that all middleware components work together without conflicts
	gin.SetMode(gin.TestMode)

	// Create router with all middleware components
	router := gin.New()

	// Add security headers middleware first
	securityConfig := SecurityConfig{
		ContentSecurityPolicy: "default-src 'self'",
		XFrameOptions:         "DENY",
		XContentTypeOptions:   "nosniff",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		XSSProtection: XSSProtectionConfig{
			Enable: true,
			Mode:   "block",
		},
		CustomHeaders: map[string]string{
			"X-API-Version": "v1.0",
		},
	}
	router.Use(NewSecurityHeadersMiddleware(securityConfig))

	// Add CORS middleware second
	corsConfig := CORSConfig{
		AllowedOrigins:   []string{"https://example.com"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           3600,
	}
	router.Use(NewCORSMiddleware(corsConfig))

	// Add rate limiting middleware third
	rateLimitConfig := RateLimitConfig{
		RequestsPerMinute: 10,
		BurstSize:         3,
		KeyFunc: func(c *gin.Context) string {
			return c.ClientIP()
		},
		OnLimitReached: func(c *gin.Context) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate_limit_exceeded"})
		},
	}
	router.Use(NewRateLimitMiddleware(rateLimitConfig))

	// Add test endpoints
	router.GET("/api/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "message": "all middleware applied"})
	})

	router.POST("/api/data", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "created"})
	})

	// Test CORS preflight with all middleware
	t.Run("cors_preflight_with_all_middleware", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/test", nil)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "Content-Type")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should handle CORS preflight properly
		assert.Equal(t, http.StatusNoContent, w.Code, "Preflight should succeed")

		// Check CORS headers
		assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"), "Should set CORS origin")
		assert.Equal(t, "GET, POST, OPTIONS", w.Header().Get("Access-Control-Allow-Methods"), "Should set CORS methods")

		// Check security headers are still applied
		assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"), "Should set CSP")
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"), "Should set X-Frame-Options")
		assert.Equal(t, "v1.0", w.Header().Get("X-API-Version"), "Should set custom header")

		// Rate limiting headers may not be set for preflight requests (depending on middleware order)
		// This is acceptable behavior as preflight requests are handled by CORS middleware early
	})

	// Test actual request with all middleware
	t.Run("actual_request_with_all_middleware", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Origin", "https://example.com")
		req.RemoteAddr = "192.168.1.100:12345"

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should succeed
		assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

		// Check response body
		assert.Contains(t, w.Body.String(), "all middleware applied", "Should reach endpoint")

		// Check all middleware headers are present
		// Security headers
		assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"), "Should set CSP")
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"), "Should set X-Frame-Options")
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"), "Should set X-Content-Type-Options")
		assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"), "Should set XSS protection")
		assert.Equal(t, "v1.0", w.Header().Get("X-API-Version"), "Should set custom header")

		// CORS headers
		assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"), "Should set CORS origin")
		assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"), "Should allow credentials")

		// Rate limiting headers
		assert.Equal(t, "10", w.Header().Get("X-RateLimit-Limit"), "Should set rate limit")
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"), "Should set remaining requests")
	})

	// Test rate limiting with CORS and security
	t.Run("rate_limiting_with_cors_and_security", func(t *testing.T) {
		testRouter := gin.New()
		testRouter.Use(NewSecurityHeadersMiddleware(securityConfig))
		testRouter.Use(NewCORSMiddleware(corsConfig))
		
		// Stricter rate limit for testing
		strictRateConfig := RateLimitConfig{
			RequestsPerMinute: 5,
			BurstSize:         1,
			KeyFunc: func(c *gin.Context) string {
				return c.ClientIP()
			},
			OnLimitReached: func(c *gin.Context) {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate_limit_exceeded"})
			},
		}
		testRouter.Use(NewRateLimitMiddleware(strictRateConfig))
		testRouter.GET("/api/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		// First request should succeed
		req1 := httptest.NewRequest("GET", "/api/test", nil)
		req1.Header.Set("Origin", "https://example.com")
		req1.RemoteAddr = "192.168.1.101:12345"
		w1 := httptest.NewRecorder()
		testRouter.ServeHTTP(w1, req1)

		assert.Equal(t, http.StatusOK, w1.Code, "First request should succeed")
		assert.Equal(t, "https://example.com", w1.Header().Get("Access-Control-Allow-Origin"), "Should set CORS")
		assert.Equal(t, "default-src 'self'", w1.Header().Get("Content-Security-Policy"), "Should set CSP")

		// Second request should be rate limited
		req2 := httptest.NewRequest("GET", "/api/test", nil)
		req2.Header.Set("Origin", "https://example.com")
		req2.RemoteAddr = "192.168.1.101:12345"
		w2 := httptest.NewRecorder()
		testRouter.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusTooManyRequests, w2.Code, "Second request should be rate limited")
		assert.Contains(t, w2.Body.String(), "rate_limit_exceeded", "Should return rate limit error")

		// Security and rate limit headers should still be present
		assert.Equal(t, "default-src 'self'", w2.Header().Get("Content-Security-Policy"), "Should set CSP even for rate limited")
		assert.Equal(t, "5", w2.Header().Get("X-RateLimit-Limit"), "Should set rate limit header")
		assert.Equal(t, "0", w2.Header().Get("X-RateLimit-Remaining"), "Should show 0 remaining")

		// CORS headers should still be present for rate limited requests
		assert.Equal(t, "https://example.com", w2.Header().Get("Access-Control-Allow-Origin"), "Should set CORS for rate limited")
	})

	// Test middleware order independence
	t.Run("middleware_order_independence", func(t *testing.T) {
		// Create router with different middleware order
		reverseRouter := gin.New()
		
		// Add middleware in reverse order
		reverseRouter.Use(NewRateLimitMiddleware(rateLimitConfig))
		reverseRouter.Use(NewCORSMiddleware(corsConfig))
		reverseRouter.Use(NewSecurityHeadersMiddleware(securityConfig))
		
		reverseRouter.GET("/api/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Origin", "https://example.com")
		req.RemoteAddr = "192.168.1.102:12345"

		w := httptest.NewRecorder()
		reverseRouter.ServeHTTP(w, req)

		// Should still work regardless of order
		assert.Equal(t, http.StatusOK, w.Code, "Request should succeed with reverse middleware order")

		// All headers should still be present
		assert.NotEmpty(t, w.Header().Get("Content-Security-Policy"), "Should have security headers")
		assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Origin"), "Should have CORS headers")
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"), "Should have rate limit headers")
	})

	// Test disallowed origin with all middleware
	t.Run("disallowed_origin_with_all_middleware", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Origin", "https://malicious.com") // Not in allowed origins
		req.RemoteAddr = "192.168.1.103:12345"

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should succeed but without CORS headers
		assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

		// Security headers should still be present
		assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"), "Should set CSP")
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"), "Should set X-Frame-Options")

		// Rate limiting headers should still be present
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"), "Should set rate limit headers")

		// CORS headers should not be present for disallowed origin
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"), "Should not set CORS for disallowed origin")
	})

	// Test error handling with all middleware
	t.Run("error_handling_with_all_middleware", func(t *testing.T) {
		errorRouter := gin.New()
		errorRouter.Use(NewSecurityHeadersMiddleware(securityConfig))
		errorRouter.Use(NewCORSMiddleware(corsConfig))
		errorRouter.Use(NewRateLimitMiddleware(rateLimitConfig))
		
		// Add endpoint that returns an error
		errorRouter.GET("/api/error", func(c *gin.Context) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_server_error"})
		})

		req := httptest.NewRequest("GET", "/api/error", nil)
		req.Header.Set("Origin", "https://example.com")
		req.RemoteAddr = "192.168.1.104:12345"

		w := httptest.NewRecorder()
		errorRouter.ServeHTTP(w, req)

		// Should return error status
		assert.Equal(t, http.StatusInternalServerError, w.Code, "Should return server error")

		// All middleware headers should still be present even for errors
		assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"), "Should set CSP for errors")
		assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"), "Should set CORS for errors")
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"), "Should set rate limit for errors")
	})
}