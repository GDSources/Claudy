package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"claudy/internal/server"
)

// createTestKeysForSecurity generates temporary RSA key pair for security testing
func createTestKeysForSecurity(t *testing.T) (privateKeyPath, publicKeyPath string, cleanup func()) {
	tempDir, err := ioutil.TempDir("", "claudy-security-test-keys-")
	require.NoError(t, err)

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create private key file
	privateKeyPath = filepath.Join(tempDir, "private.pem")
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	err = ioutil.WriteFile(privateKeyPath, privateKeyPEM, 0600)
	require.NoError(t, err)

	// Create public key file
	publicKeyPath = filepath.Join(tempDir, "public.pem")
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	err = ioutil.WriteFile(publicKeyPath, publicKeyPEM, 0644)
	require.NoError(t, err)

	cleanup = func() {
		os.RemoveAll(tempDir)
	}

	return privateKeyPath, publicKeyPath, cleanup
}

// setupSecurityTestEnvironment sets up complete environment for WebSocket security testing
func setupSecurityTestEnvironment(t *testing.T) func() {
	privateKeyPath, publicKeyPath, keyCleanup := createTestKeysForSecurity(t)
	
	tempWorkspace, err := ioutil.TempDir("", "claudy-security-test-workspace-")
	require.NoError(t, err)

	// Set all required environment variables for WebSocket security testing
	originalEnv := make(map[string]string)
	envVars := map[string]string{
		"ENVIRONMENT":                    "development",
		"DEBUG":                          "true",
		"WEBSOCKET_ENABLED":              "true",
		"WEBSOCKET_PATH":                 "/ws",
		"WEBSOCKET_MAX_CONNECTIONS_PER_USER": "3",
		"JWT_PRIVATE_KEY_PATH":           privateKeyPath,
		"JWT_PUBLIC_KEY_PATH":            publicKeyPath,
		"JWT_ISSUER":                     "claudy-test",
		"JWT_EXPIRY_DURATION":            "24h",
		"SECURITY_ENCRYPTION_KEY":        "test-32-byte-key-for-testing!!!!", // Exactly 32 bytes
		"SECURITY_ENABLE_HSTS":           "true",
		"SECURITY_ENABLE_CSP":            "true",
		"SECURITY_ENABLE_FRAME_DENY":     "true",
		"SECURITY_HSTS_MAX_AGE":          "31536000",
		"SECURITY_CSP_POLICY":            "default-src 'self'",
		"CLAUDE_WORKSPACE_BASE_PATH":     tempWorkspace,
		"CLAUDE_API_BASE_URL":            "https://api.anthropic.com",
		"CLAUDE_CODE_PATH":               "claude-code",
		"MONITORING_ENABLED":             "true",
		"MONITORING_METRICS_PATH":        "/metrics",
		"MONITORING_HEALTH_PATH":         "/health",
		"MONITORING_READINESS_PATH":      "/ready",
		"RATE_LIMIT_ENABLED":             "true",
		"RATE_LIMIT_REQUESTS_PER_SECOND": "100.0",
		"RATE_LIMIT_BURST_SIZE":          "10",
		"RATE_LIMIT_KEY_FUNC":            "ip",
		"DATABASE_URI":                   "mongodb://localhost:27017",
		"DATABASE_DATABASE":              "claudy-test",
		"REDIS_ADDR":                     "localhost:6379",
	}

	for key, value := range envVars {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, value)
	}

	return func() {
		// Restore original environment
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
		keyCleanup()
		os.RemoveAll(tempWorkspace)
	}
}

// TestWebSocketSecurityHeaders verifies security headers are applied to WebSocket upgrade responses
func TestWebSocketSecurityHeaders(t *testing.T) {
	// Set up test environment first (before server creation)
	cleanup := setupSecurityTestEnvironment(t)
	defer cleanup()

	// Create server (config loading will now work with environment variables)
	srv := server.NewServer()
	require.NotNil(t, srv)

	// Initialize server to set up WebSocket routes
	err := srv.Initialize()
	require.NoError(t, err)

	// Create test HTTP server
	router := srv.GetRouter()
	testServer := httptest.NewServer(router)
	defer testServer.Close()

	// Test WebSocket upgrade request (without valid authentication)
	req, err := http.NewRequest("GET", testServer.URL+"/ws", nil)
	require.NoError(t, err)

	// Add WebSocket upgrade headers
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Origin", "http://localhost:3000") // Valid origin

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify security headers are present (applied by middleware)
	assert.NotEmpty(t, resp.Header.Get("X-Frame-Options"), "X-Frame-Options header should be set")
	assert.NotEmpty(t, resp.Header.Get("X-Content-Type-Options"), "X-Content-Type-Options header should be set")

	// Should get 401 Unauthorized due to missing authentication
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Should require authentication")
}

// TestWebSocketOriginValidation verifies Origin header validation
func TestWebSocketOriginValidation(t *testing.T) {
	tests := []struct {
		name           string
		origin         string
		expectUpgrade  bool
		expectedStatus int
	}{
		{
			name:           "Valid origin should be accepted",
			origin:         "http://localhost:3000",
			expectUpgrade:  false, // Will still fail auth, but origin check passes
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid origin should be rejected",
			origin:         "https://malicious-site.com",
			expectUpgrade:  false,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Missing origin should be rejected",
			origin:         "",
			expectUpgrade:  false,
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up test environment first (before server creation)
			cleanup := setupSecurityTestEnvironment(t)
			defer cleanup()

			// Create server (config loading will now work with environment variables)
			srv := server.NewServer()
			require.NotNil(t, srv)

			// Initialize server to set up WebSocket routes
			err := srv.Initialize()
			require.NoError(t, err)

			// Create test HTTP server
			router := srv.GetRouter()
			testServer := httptest.NewServer(router)
			defer testServer.Close()

			// Prepare WebSocket connection
			wsURL := strings.Replace(testServer.URL, "http://", "ws://", 1) + "/ws"
			
			// Create dialer with custom headers
			dialer := websocket.Dialer{}
			headers := http.Header{}
			if tt.origin != "" {
				headers.Set("Origin", tt.origin)
			}

			// Attempt WebSocket connection
			_, resp, err := dialer.Dial(wsURL, headers)
			
			if resp != nil {
				defer resp.Body.Close()
				
				// Check response status
				if tt.expectedStatus == http.StatusForbidden {
					assert.Equal(t, http.StatusForbidden, resp.StatusCode, 
						"Invalid origin should return 403 Forbidden")
				} else if tt.expectedStatus == http.StatusUnauthorized {
					assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
						"Valid origin but no auth should return 401 Unauthorized")
				}
			}

			if !tt.expectUpgrade {
				assert.Error(t, err, "WebSocket upgrade should fail")
			}
		})
	}
}

// TestWebSocketAuthenticationRequired verifies authentication is required before upgrade
func TestWebSocketAuthenticationRequired(t *testing.T) {
	// Set up test environment first (before server creation)
	cleanup := setupSecurityTestEnvironment(t)
	defer cleanup()

	// Create server (config loading will now work with environment variables)
	srv := server.NewServer()
	require.NotNil(t, srv)

	// Initialize server to set up WebSocket routes
	err := srv.Initialize()
	require.NoError(t, err)

	// Create test HTTP server
	router := srv.GetRouter()
	testServer := httptest.NewServer(router)
	defer testServer.Close()

	// Test WebSocket connection without authentication
	wsURL := strings.Replace(testServer.URL, "http://", "ws://", 1) + "/ws"
	
	dialer := websocket.Dialer{}
	headers := http.Header{}
	headers.Set("Origin", "http://localhost:3000") // Valid origin

	// Attempt connection without auth token
	_, resp, err := dialer.Dial(wsURL, headers)
	
	require.Error(t, err, "WebSocket connection should fail without authentication")
	require.NotNil(t, resp)
	defer resp.Body.Close()
	
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, 
		"Should return 401 Unauthorized for missing authentication")
}

// TestWebSocketRateLimitingIntegration verifies rate limiting applies to WebSocket endpoints
func TestWebSocketRateLimitingIntegration(t *testing.T) {
	// Set up test environment with low rate limits
	cleanup := setupSecurityTestEnvironment(t)
	defer cleanup()
	
	// Override rate limiting to be more restrictive for testing
	os.Setenv("RATE_LIMIT_REQUESTS_PER_SECOND", "2")  // Very low limit
	os.Setenv("RATE_LIMIT_BURST_SIZE", "1")

	// Create server
	srv := server.NewServer()
	require.NotNil(t, srv)

	// Initialize server to set up WebSocket routes
	err := srv.Initialize()
	require.NoError(t, err)

	// Create test HTTP server
	router := srv.GetRouter()
	testServer := httptest.NewServer(router)
	defer testServer.Close()

	// Make multiple rapid requests to trigger rate limiting
	client := &http.Client{}
	normalRequests := 0
	rateLimitedRequests := 0

	for i := 0; i < 10; i++ {
		req, err := http.NewRequest("GET", testServer.URL+"/ws", nil)
		require.NoError(t, err)

		// Add WebSocket headers
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Origin", "http://localhost:3000")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimitedRequests++
		} else {
			normalRequests++
		}

		// Small delay between requests
		time.Sleep(10 * time.Millisecond)
	}

	// Should have some rate limited requests due to the low limits
	assert.Greater(t, rateLimitedRequests, 0, 
		"Should have some rate limited requests with low rate limits")
	assert.Greater(t, normalRequests, 0, 
		"Should have some normal requests before hitting rate limit")
}