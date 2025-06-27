package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRateLimitMiddleware(t *testing.T) {
	// Test that rate limiting middleware properly enforces request limits
	gin.SetMode(gin.TestMode)

	// Create router with rate limiting middleware
	router := gin.New()
	rateLimitConfig := RateLimitConfig{
		RequestsPerMinute: 5,  // Allow 5 requests per minute
		BurstSize:         3,  // Allow bursts of up to 3 requests
		KeyFunc: func(c *gin.Context) string {
			// Use IP address as the key for rate limiting
			return c.ClientIP()
		},
		OnLimitReached: func(c *gin.Context) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests, please try again later",
			})
		},
	}

	router.Use(NewRateLimitMiddleware(rateLimitConfig))

	// Add test endpoint
	router.GET("/api/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Test normal requests within limit
	t.Run("requests_within_limit", func(t *testing.T) {
		// Make 3 requests (within burst size)
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/api/test", nil)
			req.RemoteAddr = "192.168.1.100:12345"
			
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			
			assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
			
			// Check rate limit headers
			assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"), "Should include rate limit header")
			assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"), "Should include remaining requests header")
			assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"), "Should include reset time header")
		}
	})

	// Test rate limit exceeded
	t.Run("rate_limit_exceeded", func(t *testing.T) {
		router2 := gin.New()
		router2.Use(NewRateLimitMiddleware(rateLimitConfig))
		router2.GET("/api/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		// Make requests beyond the burst limit
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "/api/test", nil)
			req.RemoteAddr = "192.168.1.101:12345"
			
			w := httptest.NewRecorder()
			router2.ServeHTTP(w, req)
			
			if i < 3 {
				assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed", i+1)
			} else {
				assert.Equal(t, http.StatusTooManyRequests, w.Code, "Request %d should be rate limited", i+1)
				assert.Contains(t, w.Body.String(), "rate_limit_exceeded", "Should return rate limit error")
				
				// Check rate limit headers are still present
				assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"), "Should include rate limit header")
				assert.Equal(t, "0", w.Header().Get("X-RateLimit-Remaining"), "Should show 0 remaining requests")
			}
		}
	})

	// Test different IP addresses get separate limits
	t.Run("separate_limits_per_ip", func(t *testing.T) {
		router3 := gin.New()
		router3.Use(NewRateLimitMiddleware(rateLimitConfig))
		router3.GET("/api/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		// First IP makes 3 requests
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/api/test", nil)
			req.RemoteAddr = "192.168.1.102:12345"
			
			w := httptest.NewRecorder()
			router3.ServeHTTP(w, req)
			
			assert.Equal(t, http.StatusOK, w.Code, "First IP request %d should succeed", i+1)
		}

		// Second IP should also be able to make 3 requests
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/api/test", nil)
			req.RemoteAddr = "192.168.1.103:12345"
			
			w := httptest.NewRecorder()
			router3.ServeHTTP(w, req)
			
			assert.Equal(t, http.StatusOK, w.Code, "Second IP request %d should succeed", i+1)
		}
	})

	// Test rate limit reset over time
	t.Run("rate_limit_reset", func(t *testing.T) {
		// Create config with very short window for testing
		fastConfig := RateLimitConfig{
			RequestsPerMinute: 60, // 1 request per second
			BurstSize:         1,  // Only 1 request allowed at once
			KeyFunc: func(c *gin.Context) string {
				return c.ClientIP()
			},
			OnLimitReached: func(c *gin.Context) {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate_limit_exceeded"})
			},
		}

		router4 := gin.New()
		router4.Use(NewRateLimitMiddleware(fastConfig))
		router4.GET("/api/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		// First request should succeed
		req1 := httptest.NewRequest("GET", "/api/test", nil)
		req1.RemoteAddr = "192.168.1.104:12345"
		w1 := httptest.NewRecorder()
		router4.ServeHTTP(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code, "First request should succeed")

		// Immediate second request should fail
		req2 := httptest.NewRequest("GET", "/api/test", nil)
		req2.RemoteAddr = "192.168.1.104:12345"
		w2 := httptest.NewRecorder()
		router4.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusTooManyRequests, w2.Code, "Immediate second request should be rate limited")

		// Wait for rate limit to reset (1 second + buffer)
		time.Sleep(1100 * time.Millisecond)

		// Third request should succeed after reset
		req3 := httptest.NewRequest("GET", "/api/test", nil)
		req3.RemoteAddr = "192.168.1.104:12345"
		w3 := httptest.NewRecorder()
		router4.ServeHTTP(w3, req3)
		assert.Equal(t, http.StatusOK, w3.Code, "Request after reset should succeed")
	})

	// Test concurrent requests from same IP
	t.Run("concurrent_requests", func(t *testing.T) {
		router5 := gin.New()
		router5.Use(NewRateLimitMiddleware(rateLimitConfig))
		router5.GET("/api/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		const numConcurrent = 10
		results := make([]int, numConcurrent)
		var wg sync.WaitGroup

		// Launch concurrent requests
		for i := 0; i < numConcurrent; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				
				req := httptest.NewRequest("GET", "/api/test", nil)
				req.RemoteAddr = "192.168.1.105:12345"
				
				w := httptest.NewRecorder()
				router5.ServeHTTP(w, req)
				
				results[index] = w.Code
			}(i)
		}

		wg.Wait()

		// Count successful and rate-limited requests
		successCount := 0
		rateLimitedCount := 0
		
		for _, code := range results {
			if code == http.StatusOK {
				successCount++
			} else if code == http.StatusTooManyRequests {
				rateLimitedCount++
			}
		}

		// Should have exactly burst size (3) successful requests
		assert.Equal(t, 3, successCount, "Should have exactly 3 successful requests")
		assert.Equal(t, 7, rateLimitedCount, "Should have 7 rate-limited requests")
	})

	// Test custom key function
	t.Run("custom_key_function", func(t *testing.T) {
		userBasedConfig := RateLimitConfig{
			RequestsPerMinute: 5,
			BurstSize:         2,
			KeyFunc: func(c *gin.Context) string {
				// Use user ID from header for rate limiting
				return c.GetHeader("User-ID")
			},
			OnLimitReached: func(c *gin.Context) {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate_limit_exceeded"})
			},
		}

		router6 := gin.New()
		router6.Use(NewRateLimitMiddleware(userBasedConfig))
		router6.GET("/api/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		// User A makes 2 requests (should succeed)
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/api/test", nil)
			req.Header.Set("User-ID", "user-a")
			
			w := httptest.NewRecorder()
			router6.ServeHTTP(w, req)
			
			assert.Equal(t, http.StatusOK, w.Code, "User A request %d should succeed", i+1)
		}

		// User A makes 3rd request (should fail)
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("User-ID", "user-a")
		w := httptest.NewRecorder()
		router6.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code, "User A 3rd request should be rate limited")

		// User B should still be able to make requests
		req2 := httptest.NewRequest("GET", "/api/test", nil)
		req2.Header.Set("User-ID", "user-b")
		w2 := httptest.NewRecorder()
		router6.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusOK, w2.Code, "User B request should succeed")
	})
}