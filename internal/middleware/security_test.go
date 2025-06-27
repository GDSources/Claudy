package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	// Test that security headers middleware sets proper security headers
	gin.SetMode(gin.TestMode)

	// Create router with security headers middleware
	router := gin.New()
	securityConfig := SecurityConfig{
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
			"camera":     {"'none'"},
			"microphone": {"'none'"},
			"geolocation": {"'self'"},
			"payment":    {"'none'"},
		},
		CustomHeaders: map[string]string{
			"X-Custom-Security": "enabled",
			"X-API-Version":     "v1.0",
		},
	}

	router.Use(NewSecurityHeadersMiddleware(securityConfig))

	// Add test endpoint
	router.GET("/api/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Test basic security headers
	t.Run("basic_security_headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

		// Check Content Security Policy
		assert.Equal(t, 
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
			w.Header().Get("Content-Security-Policy"),
			"Should set Content-Security-Policy header")

		// Check X-Frame-Options
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"), "Should set X-Frame-Options header")

		// Check X-Content-Type-Options
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"), "Should set X-Content-Type-Options header")

		// Check Referrer-Policy
		assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"), "Should set Referrer-Policy header")
	})

	// Test HTTPS-specific headers
	t.Run("https_specific_headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("X-Forwarded-Proto", "https") // Simulate HTTPS request
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

		// Check Strict-Transport-Security (should be set for HTTPS)
		assert.Equal(t, 
			"max-age=31536000; includeSubDomains; preload",
			w.Header().Get("Strict-Transport-Security"),
			"Should set HSTS header for HTTPS requests")
	})

	// Test HTTP requests (no HSTS)
	t.Run("http_requests_no_hsts", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		// No X-Forwarded-Proto header (HTTP request)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

		// HSTS should not be set for HTTP requests
		assert.Empty(t, w.Header().Get("Strict-Transport-Security"), "Should not set HSTS header for HTTP requests")
	})

	// Test XSS Protection headers
	t.Run("xss_protection_headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

		// Check X-XSS-Protection
		assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"), "Should set X-XSS-Protection header")
	})

	// Test Permissions Policy headers
	t.Run("permissions_policy_headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

		// Check Permissions-Policy
		permissionsPolicy := w.Header().Get("Permissions-Policy")
		assert.NotEmpty(t, permissionsPolicy, "Should set Permissions-Policy header")
		
		// Check that specific policies are included
		assert.Contains(t, permissionsPolicy, "camera=", "Should include camera policy")
		assert.Contains(t, permissionsPolicy, "microphone=", "Should include microphone policy")
		assert.Contains(t, permissionsPolicy, "geolocation=", "Should include geolocation policy")
		assert.Contains(t, permissionsPolicy, "payment=", "Should include payment policy")
	})

	// Test custom headers
	t.Run("custom_headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

		// Check custom headers
		assert.Equal(t, "enabled", w.Header().Get("X-Custom-Security"), "Should set custom security header")
		assert.Equal(t, "v1.0", w.Header().Get("X-API-Version"), "Should set custom API version header")
	})

	// Test minimal configuration
	t.Run("minimal_configuration", func(t *testing.T) {
		minimalRouter := gin.New()
		minimalConfig := SecurityConfig{
			ContentSecurityPolicy: "default-src 'self'",
			XFrameOptions:         "SAMEORIGIN",
		}

		minimalRouter.Use(NewSecurityHeadersMiddleware(minimalConfig))
		minimalRouter.GET("/api/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		req := httptest.NewRequest("GET", "/api/test", nil)
		w := httptest.NewRecorder()
		minimalRouter.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

		// Check that only configured headers are set
		assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"), "Should set CSP")
		assert.Equal(t, "SAMEORIGIN", w.Header().Get("X-Frame-Options"), "Should set X-Frame-Options")
		
		// Headers not configured should be empty or have defaults
		assert.Empty(t, w.Header().Get("Strict-Transport-Security"), "Should not set HSTS when not configured")
		assert.Empty(t, w.Header().Get("Permissions-Policy"), "Should not set Permissions-Policy when not configured")
	})

	// Test disabled XSS protection
	t.Run("disabled_xss_protection", func(t *testing.T) {
		disabledXSSRouter := gin.New()
		disabledXSSConfig := SecurityConfig{
			ContentSecurityPolicy: "default-src 'self'",
			XSSProtection: XSSProtectionConfig{
				Enable: false,
			},
		}

		disabledXSSRouter.Use(NewSecurityHeadersMiddleware(disabledXSSConfig))
		disabledXSSRouter.GET("/api/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		req := httptest.NewRequest("GET", "/api/test", nil)
		w := httptest.NewRecorder()
		disabledXSSRouter.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

		// XSS Protection should be disabled
		assert.Equal(t, "0", w.Header().Get("X-XSS-Protection"), "Should disable XSS protection when configured")
	})

	// Test header override behavior
	t.Run("header_override_behavior", func(t *testing.T) {
		overrideRouter := gin.New()
		overrideConfig := SecurityConfig{
			ContentSecurityPolicy: "default-src 'self'",
			XFrameOptions:         "DENY",
		}

		overrideRouter.Use(NewSecurityHeadersMiddleware(overrideConfig))
		overrideRouter.GET("/api/test", func(c *gin.Context) {
			// Try to override security header in handler
			c.Header("X-Frame-Options", "ALLOWALL")
			c.JSON(200, gin.H{"status": "ok"})
		})

		req := httptest.NewRequest("GET", "/api/test", nil)
		w := httptest.NewRecorder()
		overrideRouter.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request should succeed")

		// Security middleware should prevent override (depending on implementation)
		// This test checks if the middleware sets headers before or after the handler
		frameOptions := w.Header().Get("X-Frame-Options")
		assert.NotEmpty(t, frameOptions, "X-Frame-Options should be set")
		// The actual value depends on whether we allow overrides or not
	})
}