package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestCORSMiddlewareBasicFunctionality(t *testing.T) {
	// Test that CORS middleware sets proper headers for cross-origin requests
	gin.SetMode(gin.TestMode)
	
	// Create router with CORS middleware
	router := gin.New()
	corsConfig := CORSConfig{
		AllowedOrigins:   []string{"https://example.com", "https://app.claudy.dev"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Requested-With"},
		ExposedHeaders:   []string{"X-Total-Count", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           3600, // 1 hour
	}
	
	router.Use(NewCORSMiddleware(corsConfig))
	
	// Add test endpoint
	router.GET("/api/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	
	// Test preflight OPTIONS request
	t.Run("preflight_request", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/test", nil)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "Content-Type")
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		// Should return 204 No Content for preflight
		assert.Equal(t, http.StatusNoContent, w.Code, "Preflight should return 204")
		
		// Check CORS headers
		assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"), "Should allow specified origin")
		assert.Equal(t, "GET, POST, PUT, DELETE, OPTIONS", w.Header().Get("Access-Control-Allow-Methods"), "Should include allowed methods")
		assert.Equal(t, "Content-Type, Authorization, X-Requested-With", w.Header().Get("Access-Control-Allow-Headers"), "Should include allowed headers")
		assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"), "Should allow credentials")
		assert.Equal(t, "3600", w.Header().Get("Access-Control-Max-Age"), "Should set max age")
	})
	
	// Test actual CORS request
	t.Run("actual_request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Origin", "https://app.claudy.dev")
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		// Should return 200 OK for actual request
		assert.Equal(t, http.StatusOK, w.Code, "Actual request should return 200")
		
		// Check CORS headers
		assert.Equal(t, "https://app.claudy.dev", w.Header().Get("Access-Control-Allow-Origin"), "Should allow specified origin")
		assert.Equal(t, "X-Total-Count, X-Request-ID", w.Header().Get("Access-Control-Expose-Headers"), "Should expose specified headers")
		assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"), "Should allow credentials")
		
		// Should not include preflight-only headers
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Methods"), "Should not include methods in actual response")
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Headers"), "Should not include allow-headers in actual response")
		assert.Empty(t, w.Header().Get("Access-Control-Max-Age"), "Should not include max-age in actual response")
	})
	
	// Test disallowed origin
	t.Run("disallowed_origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Origin", "https://malicious.com")
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		// Should still return 200 OK but without CORS headers
		assert.Equal(t, http.StatusOK, w.Code, "Should process request but without CORS headers")
		
		// Should not include CORS headers for disallowed origin
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"), "Should not allow disallowed origin")
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"), "Should not set credentials for disallowed origin")
	})
	
	// Test no origin header (same-origin request)
	t.Run("no_origin_header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		// No Origin header set
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		// Should return 200 OK
		assert.Equal(t, http.StatusOK, w.Code, "Should process same-origin request")
		
		// Should not include CORS headers for same-origin requests
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"), "Should not set CORS headers for same-origin")
	})
	
	// Test method not allowed in preflight
	t.Run("method_not_allowed_preflight", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/test", nil)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "PATCH") // Not in allowed methods
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		// Should return 403 Forbidden for disallowed method
		assert.Equal(t, http.StatusForbidden, w.Code, "Should reject disallowed method in preflight")
		
		// Should not include CORS headers for rejected preflight
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"), "Should not set CORS headers for rejected preflight")
	})
	
	// Test header not allowed in preflight
	t.Run("header_not_allowed_preflight", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/test", nil)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "X-Custom-Header") // Not in allowed headers
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		// Should return 403 Forbidden for disallowed header
		assert.Equal(t, http.StatusForbidden, w.Code, "Should reject disallowed header in preflight")
		
		// Should not include CORS headers for rejected preflight
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"), "Should not set CORS headers for rejected preflight")
	})
}