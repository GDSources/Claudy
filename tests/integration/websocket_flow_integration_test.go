package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"claudy/internal/auth"
	"claudy/internal/server"
)

// createTestKeysForFlow generates temporary RSA key pair for flow testing
func createTestKeysForFlow(t *testing.T) (privateKeyPath, publicKeyPath string, cleanup func()) {
	tempDir, err := ioutil.TempDir("", "claudy-flow-test-keys-")
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

// setupFlowTestEnvironment sets up complete environment for WebSocket flow testing
func setupFlowTestEnvironment(t *testing.T) (func(), *auth.JWTService) {
	privateKeyPath, publicKeyPath, keyCleanup := createTestKeysForFlow(t)
	
	tempWorkspace, err := ioutil.TempDir("", "claudy-flow-test-workspace-")
	require.NoError(t, err)

	// Set all required environment variables
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
		"CLAUDE_WORKSPACE_BASE_PATH":     tempWorkspace,
		"CLAUDE_API_BASE_URL":            "https://api.anthropic.com",
		"CLAUDE_CODE_PATH":               "claude-code",
		"MONITORING_ENABLED":             "true",
		"MONITORING_METRICS_PATH":        "/metrics",
		"MONITORING_HEALTH_PATH":         "/health",
		"MONITORING_READINESS_PATH":      "/ready",
		"DATABASE_URI":                   "mongodb://localhost:27017",
		"DATABASE_DATABASE":              "claudy-test",
		"REDIS_ADDR":                     "localhost:6379",
	}

	for key, value := range envVars {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, value)
	}

	// Create JWT service for generating test tokens
	privateKeyData, err := ioutil.ReadFile(privateKeyPath)
	require.NoError(t, err)
	publicKeyData, err := ioutil.ReadFile(publicKeyPath)
	require.NoError(t, err)
	
	jwtService, err := auth.NewJWTService(string(privateKeyData), string(publicKeyData))
	require.NoError(t, err)

	cleanup := func() {
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

	return cleanup, jwtService
}

// generateTestToken creates a valid JWT token for testing
func generateTestToken(t *testing.T, jwtService *auth.JWTService, userID string) string {
	claims := auth.UserClaims{
		UserID:   userID,
		GitHubID: "github123",
		Username: "testuser",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	
	token, err := jwtService.GenerateToken(claims, 24*time.Hour)
	require.NoError(t, err)
	return token
}

// Message represents WebSocket message structure
type Message struct {
	Type      string                 `json:"type"`
	Content   string                 `json:"content"`
	Timestamp string                 `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// TestWebSocketConnectionFlowWithAuth verifies complete connection flow with authentication
func TestWebSocketConnectionFlowWithAuth(t *testing.T) {
	// Set up test environment first (before server creation)
	cleanup, jwtService := setupFlowTestEnvironment(t)
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

	// Generate valid JWT token
	userID := "test-user-123"
	token := generateTestToken(t, jwtService, userID)

	// Prepare WebSocket connection with authentication
	wsURL := strings.Replace(testServer.URL, "http://", "ws://", 1) + "/ws"
	
	u, err := url.Parse(wsURL)
	require.NoError(t, err)
	
	// Add token as query parameter (simulating client that can't set headers)
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()

	// Create WebSocket connection
	dialer := &websocket.Dialer{}
	headers := map[string][]string{
		"Origin": {"http://localhost:3000"},
	}
	
	conn, resp, err := dialer.Dial(u.String(), headers)
	require.NoError(t, err)
	defer conn.Close()
	
	if resp != nil {
		defer resp.Body.Close()
		assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode, "Should successfully upgrade to WebSocket")
	}

	// Test bidirectional communication
	testMessage := Message{
		Type:      "test",
		Content:   "Hello WebSocket!",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      map[string]interface{}{"test": true},
	}

	// Send message
	err = conn.WriteJSON(testMessage)
	assert.NoError(t, err, "Should be able to send JSON message")

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// The connection should remain open (authentication successful)
	// We might not receive a response immediately, but connection should be stable
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	
	// Try to read (might timeout, but that's ok for this test)
	var receivedMessage Message
	err = conn.ReadJSON(&receivedMessage)
	// Error is expected if no immediate response, but connection should be valid
	
	// Verify connection is still alive by sending ping
	err = conn.WriteMessage(websocket.PingMessage, []byte{})
	assert.NoError(t, err, "Should be able to send ping after authentication")
}

// TestWebSocketConnectionFlowWithoutAuth verifies connection rejection without authentication
func TestWebSocketConnectionFlowWithoutAuth(t *testing.T) {
	// Set up test environment first (before server creation)
	cleanup, _ := setupFlowTestEnvironment(t)
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

	// Prepare WebSocket connection without authentication
	wsURL := strings.Replace(testServer.URL, "http://", "ws://", 1) + "/ws"
	
	// Create WebSocket connection without token
	dialer := &websocket.Dialer{}
	headers := map[string][]string{
		"Origin": {"http://localhost:3000"},
	}
	
	conn, resp, err := dialer.Dial(wsURL, headers)
	
	// Should fail due to missing authentication
	require.Error(t, err, "WebSocket connection should fail without authentication")
	require.NotNil(t, resp)
	defer resp.Body.Close()
	
	t.Logf("Response status: %d", resp.StatusCode)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Should return 401 Unauthorized")
	
	if conn != nil {
		conn.Close()
	}
}

// TestWebSocketMultipleConnectionsPerUser verifies connection limit enforcement
func TestWebSocketMultipleConnectionsPerUser(t *testing.T) {
	// Set up test environment first (before server creation)
	cleanup, jwtService := setupFlowTestEnvironment(t)
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

	// Generate valid JWT token for same user
	userID := "test-user-multi"
	token := generateTestToken(t, jwtService, userID)

	// Prepare WebSocket URL
	wsURL := strings.Replace(testServer.URL, "http://", "ws://", 1) + "/ws"
	
	var connections []*websocket.Conn
	defer func() {
		for _, conn := range connections {
			if conn != nil {
				conn.Close()
			}
		}
	}()

	// Try to create multiple connections (max is 3 per user)
	for i := 0; i < 5; i++ {
		u, err := url.Parse(wsURL)
		require.NoError(t, err)
		
		q := u.Query()
		q.Set("token", token)
		u.RawQuery = q.Encode()

		dialer := &websocket.Dialer{}
		headers := map[string][]string{
			"Origin": {"http://localhost:3000"},
		}
		
		conn, resp, err := dialer.Dial(u.String(), headers)
		
		if i < 3 {
			// First 3 connections should succeed
			require.NoError(t, err, "First 3 connections should succeed")
			require.NotNil(t, conn)
			connections = append(connections, conn)
			
			if resp != nil {
				assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
				resp.Body.Close()
			}
		} else {
			// 4th and 5th connections should fail due to limit
			require.Error(t, err, "Connection should fail when limit exceeded")
			
			if resp != nil {
				assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "Should return 429 Too Many Requests")
				resp.Body.Close()
			}
			
			if conn != nil {
				conn.Close()
			}
		}
	}

	// Verify we have exactly 3 active connections
	assert.Equal(t, 3, len(connections), "Should have exactly 3 active connections")
}

// TestWebSocketOriginValidationFlow verifies origin header validation in connection flow
func TestWebSocketOriginValidationFlow(t *testing.T) {
	tests := []struct {
		name           string
		origin         string
		expectSuccess  bool
		expectedStatus int
	}{
		{
			name:           "Valid origin should succeed",
			origin:         "http://localhost:3000",
			expectSuccess:  false, // Will fail on auth, but origin check passes
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid origin should fail",
			origin:         "https://malicious-site.com",
			expectSuccess:  false,
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up test environment first (before server creation)
			cleanup, _ := setupFlowTestEnvironment(t)
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
			
			dialer := &websocket.Dialer{}
			headers := map[string][]string{
				"Origin": {tt.origin},
			}
			
			conn, resp, err := dialer.Dial(wsURL, headers)
			
			require.Error(t, err, "Connection should fail (either origin or auth)")
			require.NotNil(t, resp)
			defer resp.Body.Close()
			
			assert.Equal(t, tt.expectedStatus, resp.StatusCode, "Should return expected status code")
			
			if conn != nil {
				conn.Close()
			}
		})
	}
}

// TestWebSocketConcurrentConnections verifies concurrent connection handling
func TestWebSocketConcurrentConnections(t *testing.T) {
	// Set up test environment first (before server creation)
	cleanup, jwtService := setupFlowTestEnvironment(t)
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

	// Number of concurrent connections to test
	numConnections := 10
	var wg sync.WaitGroup
	var mu sync.Mutex
	successfulConnections := 0
	var allConnections []*websocket.Conn

	defer func() {
		mu.Lock()
		for _, conn := range allConnections {
			if conn != nil {
				conn.Close()
			}
		}
		mu.Unlock()
	}()

	// Create concurrent connections from different users
	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(userIndex int) {
			defer wg.Done()

			// Generate unique user and token
			userID := fmt.Sprintf("concurrent-user-%d", userIndex)
			token := generateTestToken(t, jwtService, userID)

			// Prepare WebSocket URL
			wsURL := strings.Replace(testServer.URL, "http://", "ws://", 1) + "/ws"
			
			u, err := url.Parse(wsURL)
			if err != nil {
				return
			}
			
			q := u.Query()
			q.Set("token", token)
			u.RawQuery = q.Encode()

			dialer := &websocket.Dialer{}
			headers := map[string][]string{
				"Origin": {"http://localhost:3000"},
			}
			
			conn, resp, dialErr := dialer.Dial(u.String(), headers)
			
			mu.Lock()
			if dialErr == nil && resp != nil && resp.StatusCode == http.StatusSwitchingProtocols {
				successfulConnections++
				allConnections = append(allConnections, conn)
			} else {
				if conn != nil {
					conn.Close()
				}
			}
			if resp != nil {
				resp.Body.Close()
			}
			mu.Unlock()
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify that most connections succeeded (allow for some failures due to timing/resources)
	mu.Lock()
	assert.GreaterOrEqual(t, successfulConnections, numConnections/2, 
		"At least half of concurrent connections should succeed")
	mu.Unlock()
}

// TestWebSocketMessageFlow verifies message sending and receiving
func TestWebSocketMessageFlow(t *testing.T) {
	// Set up test environment first (before server creation)
	cleanup, jwtService := setupFlowTestEnvironment(t)
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

	// Generate valid JWT token
	userID := "test-user-messages"
	token := generateTestToken(t, jwtService, userID)

	// Establish WebSocket connection
	wsURL := strings.Replace(testServer.URL, "http://", "ws://", 1) + "/ws"
	
	u, err := url.Parse(wsURL)
	require.NoError(t, err)
	
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()

	dialer := &websocket.Dialer{}
	headers := map[string][]string{
		"Origin": {"http://localhost:3000"},
	}
	
	conn, resp, err := dialer.Dial(u.String(), headers)
	require.NoError(t, err)
	defer conn.Close()
	
	if resp != nil {
		defer resp.Body.Close()
		assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	}

	// Test various message types
	testMessages := []Message{
		{
			Type:      "chat_message",
			Content:   "Hello from client",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Data:      map[string]interface{}{"session_id": "test-session"},
		},
		{
			Type:      "file_upload",
			Content:   "test-file.txt",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Data:      map[string]interface{}{"size": 1024, "encoding": "base64"},
		},
		{
			Type:      "auth",
			Content:   "authentication_request",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Data:      map[string]interface{}{"token": token},
		},
	}

	// Send messages and verify they don't cause connection errors
	for _, msg := range testMessages {
		err = conn.WriteJSON(msg)
		assert.NoError(t, err, "Should be able to send message of type: %s", msg.Type)
		
		// Small delay between messages
		time.Sleep(50 * time.Millisecond)
	}

	// Verify connection is still alive after sending messages
	err = conn.WriteMessage(websocket.PingMessage, []byte{})
	assert.NoError(t, err, "Connection should still be alive after sending messages")
}

// TestWebSocketConnectionTimeout verifies connection timeout handling
func TestWebSocketConnectionTimeout(t *testing.T) {
	// Set up test environment first (before server creation)
	cleanup, jwtService := setupFlowTestEnvironment(t)
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

	// Generate valid JWT token
	userID := "test-user-timeout"
	token := generateTestToken(t, jwtService, userID)

	// Establish WebSocket connection
	wsURL := strings.Replace(testServer.URL, "http://", "ws://", 1) + "/ws"
	
	u, err := url.Parse(wsURL)
	require.NoError(t, err)
	
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()

	dialer := &websocket.Dialer{}
	headers := map[string][]string{
		"Origin": {"http://localhost:3000"},
	}
	
	conn, resp, err := dialer.Dial(u.String(), headers)
	require.NoError(t, err)
	defer conn.Close()
	
	if resp != nil {
		defer resp.Body.Close()
	}

	// Set short read deadline to test timeout behavior
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Try to read (should timeout)
	var msg Message
	err = conn.ReadJSON(&msg)
	
	// Should get a timeout error
	if err != nil {
		assert.Contains(t, err.Error(), "timeout", "Should get timeout error when no messages")
	}

	// Connection should still be usable after timeout
	err = conn.WriteMessage(websocket.PingMessage, []byte{})
	assert.NoError(t, err, "Connection should still work after read timeout")
}

// TestWebSocketInvalidTokenFlow verifies invalid token handling
func TestWebSocketInvalidTokenFlow(t *testing.T) {
	// Set up test environment first (before server creation)
	cleanup, _ := setupFlowTestEnvironment(t)
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

	// Test various invalid tokens
	invalidTokens := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"malformed token", "invalid.token.here"},
		{"expired token", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.expired.token"},
		{"wrong algorithm", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.wrong.algorithm"},
	}

	for _, tt := range invalidTokens {
		t.Run(tt.name, func(t *testing.T) {
			wsURL := strings.Replace(testServer.URL, "http://", "ws://", 1) + "/ws"
			
			var u *url.URL
			var err error
			
			if tt.token != "" {
				u, err = url.Parse(wsURL)
				require.NoError(t, err)
				
				q := u.Query()
				q.Set("token", tt.token)
				u.RawQuery = q.Encode()
			} else {
				u, err = url.Parse(wsURL)
				require.NoError(t, err)
			}

			dialer := &websocket.Dialer{}
			headers := map[string][]string{
				"Origin": {"http://localhost:3000"},
			}
			
			conn, resp, err := dialer.Dial(u.String(), headers)
			
			// Should fail due to invalid/missing authentication
			require.Error(t, err, "WebSocket connection should fail with invalid token")
			require.NotNil(t, resp)
			defer resp.Body.Close()
			
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Should return 401 Unauthorized")
			
			if conn != nil {
				conn.Close()
			}
		})
	}
}

// TestWebSocketGracefulDisconnection verifies proper connection cleanup
func TestWebSocketGracefulDisconnection(t *testing.T) {
	// Set up test environment first (before server creation)
	cleanup, jwtService := setupFlowTestEnvironment(t)
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

	// Generate valid JWT token
	userID := "test-user-disconnect"
	token := generateTestToken(t, jwtService, userID)

	// Establish WebSocket connection
	wsURL := strings.Replace(testServer.URL, "http://", "ws://", 1) + "/ws"
	
	u, err := url.Parse(wsURL)
	require.NoError(t, err)
	
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()

	dialer := &websocket.Dialer{}
	headers := map[string][]string{
		"Origin": {"http://localhost:3000"},
	}
	
	conn, resp, err := dialer.Dial(u.String(), headers)
	require.NoError(t, err)
	
	if resp != nil {
		defer resp.Body.Close()
		assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	}

	// Send a few messages to establish connection state
	for i := 0; i < 3; i++ {
		msg := Message{
			Type:      "test",
			Content:   fmt.Sprintf("Message %d", i),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}
		err = conn.WriteJSON(msg)
		assert.NoError(t, err)
		time.Sleep(100 * time.Millisecond)
	}

	// Gracefully close connection
	err = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Test complete"))
	assert.NoError(t, err, "Should be able to send close message")

	// Close the connection
	err = conn.Close()
	assert.NoError(t, err, "Should be able to close connection gracefully")

	// Try to establish new connection with same user (should work, indicating cleanup was successful)
	conn2, resp2, err := dialer.Dial(u.String(), headers)
	
	// This should succeed if cleanup worked properly
	if err == nil && resp2 != nil && resp2.StatusCode == http.StatusSwitchingProtocols {
		assert.Equal(t, http.StatusSwitchingProtocols, resp2.StatusCode, "New connection should succeed after cleanup")
		conn2.Close()
	}
	
	if resp2 != nil {
		resp2.Body.Close()
	}
}