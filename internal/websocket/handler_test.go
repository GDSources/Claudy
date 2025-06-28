package websocket

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"claudy/internal/auth"
	"claudy/internal/files"
	"claudy/internal/session"
)

// MockJWTService implements a mock JWT service for testing
type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) ValidateToken(tokenString string) (*auth.UserClaims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.UserClaims), args.Error(1)
}

func (m *MockJWTService) GenerateToken(userClaims auth.UserClaims, duration time.Duration) (string, error) {
	args := m.Called(userClaims, duration)
	return args.String(0), args.Error(1)
}

// MockRedisService implements a mock Redis service for testing
type MockRedisService struct {
	mock.Mock
}

func (m *MockRedisService) SetConnectionCount(userID string, count int) error {
	args := m.Called(userID, count)
	return args.Error(0)
}

func (m *MockRedisService) GetConnectionCount(userID string) (int, error) {
	args := m.Called(userID)
	return args.Int(0), args.Error(1)
}

func (m *MockRedisService) IncrementConnectionCount(userID string) (int, error) {
	args := m.Called(userID)
	return args.Int(0), args.Error(1)
}

func (m *MockRedisService) DecrementConnectionCount(userID string) (int, error) {
	args := m.Called(userID)
	return args.Int(0), args.Error(1)
}

func (m *MockRedisService) IsAvailable() bool {
	args := m.Called()
	return args.Bool(0)
}

// MockFileManager implements a mock file manager for testing
type MockFileManager struct {
	mock.Mock
}

func (m *MockFileManager) UploadFile(ctx context.Context, workspacePath, filename, content, encoding string) (*files.UploadResult, error) {
	args := m.Called(ctx, workspacePath, filename, content, encoding)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*files.UploadResult), args.Error(1)
}

func (m *MockFileManager) ListFiles(ctx context.Context, workspacePath string) ([]files.FileInfo, error) {
	args := m.Called(ctx, workspacePath)
	return args.Get(0).([]files.FileInfo), args.Error(1)
}

func (m *MockFileManager) CleanupWorkspace(ctx context.Context, workspacePath string) error {
	args := m.Called(ctx, workspacePath)
	return args.Error(0)
}

func (m *MockFileManager) GetWorkspaceSize(ctx context.Context, workspacePath string) (int64, error) {
	args := m.Called(ctx, workspacePath)
	return args.Get(0).(int64), args.Error(1)
}

// MockSessionManager implements a mock session manager for testing
type MockSessionManager struct {
	mock.Mock
}

func (m *MockSessionManager) GetSession(sessionID string) *session.ClaudeSession {
	args := m.Called(sessionID)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*session.ClaudeSession)
}

func (m *MockSessionManager) GetUserSessions(userID string) []string {
	args := m.Called(userID)
	return args.Get(0).([]string)
}

// Helper function to create a test WebSocket handler
func createTestHandler(jwtService JWTService, redisService RedisService, fileManager FileManagerInterface, sessionManager SessionManagerInterface) *Handler {
	config := Config{
		MaxConnectionsPerUser: 3,
		AllowedOrigins:       []string{"http://localhost:3000", "https://claudy.example.com"},
		ReadTimeout:          30 * time.Second,
		WriteTimeout:         30 * time.Second,
		PingInterval:         54 * time.Second,
	}
	return NewHandler(jwtService, redisService, fileManager, sessionManager, config)
}

// Helper function to create a test WebSocket client with authentication
func createTestClient(t *testing.T, handler *Handler, headers http.Header, token string) (*websocket.Conn, *httptest.Server) {
	server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	
	// Convert http://... to ws://...
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) + "/ws"
	
	// Add token as query parameter if provided
	if token != "" {
		wsURL += "?token=" + token
	}
	
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, headers)
	require.NoError(t, err)
	
	return conn, server
}

// Helper function to create a test WebSocket client without authentication (for negative tests)
func createTestClientNoAuth(t *testing.T, handler *Handler, headers http.Header) (*websocket.Conn, *httptest.Server, error) {
	server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	
	// Convert http://... to ws://...
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) + "/ws"
	
	dialer := websocket.Dialer{}
	conn, resp, err := dialer.Dial(wsURL, headers)
	
	// For tests that expect failure, return the error
	if err != nil && resp != nil {
		resp.Body.Close()
	}
	
	return conn, server, err
}

// Helper function to create valid user claims
func createValidUserClaims() *auth.UserClaims {
	return &auth.UserClaims{
		UserID:   "user123",
		GitHubID: "github123",
		Username: "testuser",
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

// Helper function to create an auth message
func createAuthMessage(token string) Message {
	return Message{
		Type:      "auth",
		Content:   token,
		Timestamp: time.Now().Format(time.RFC3339),
		Data:      map[string]interface{}{},
	}
}

// TestWebSocketConnectionEstablishment tests successful WebSocket connection upgrade with authentication
func TestWebSocketConnectionEstablishment(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	// Setup mocks
	validClaims := createValidUserClaims()
	validToken := "valid-jwt-token"
	
	mockJWT.On("ValidateToken", validToken).Return(validClaims, nil)
	mockRedis.On("GetConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(0, nil)
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	// Set valid origin header
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	
	// Attempt connection with authentication
	conn, server := createTestClient(t, handler, headers, validToken)
	defer server.Close()
	defer conn.Close()
	
	// Assertions - connection should be successfully established
	assert.NotNil(t, conn, "Connection should not be nil")
}

// TestWebSocketJWTAuthentication tests successful JWT authentication during connection
func TestWebSocketJWTAuthentication(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	mockFileManager := &MockFileManager{}
	mockSessionManager := &MockSessionManager{}
	
	// Setup mocks
	validClaims := createValidUserClaims()
	validToken := "valid-jwt-token"
	
	mockJWT.On("ValidateToken", validToken).Return(validClaims, nil)
	mockRedis.On("GetConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(0, nil)
	
	handler := createTestHandler(mockJWT, mockRedis, mockFileManager, mockSessionManager)
	
	// Create connection with valid origin and authentication
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	conn, server := createTestClient(t, handler, headers, validToken)
	defer server.Close()
	defer conn.Close()
	
	// Connection should be established and authenticated
	assert.NotNil(t, conn, "Connection should be established with valid authentication")
}

// TestWebSocketConnectionWithoutJWT tests rejection of unauthenticated connections
func TestWebSocketConnectionWithoutJWT(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	
	// Attempt connection without authentication - should fail
	conn, server, err := createTestClientNoAuth(t, handler, headers)
	defer server.Close()
	if conn != nil {
		defer conn.Close()
	}
	
	// Assertions - connection should be rejected
	assert.Error(t, err, "Connection without authentication should be rejected")
	assert.Nil(t, conn, "Connection should be nil when authentication fails")
}

// TestWebSocketConnectionWithExpiredJWT tests handling of expired tokens
func TestWebSocketConnectionWithExpiredJWT(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	// Setup mocks - expired token should return error
	expiredToken := "expired-jwt-token"
	mockJWT.On("ValidateToken", expiredToken).Return(nil, fmt.Errorf("token expired"))
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	defer server.Close()
	
	// Try with expired token in URL
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) + "/ws?token=" + expiredToken
	dialer := websocket.Dialer{}
	conn, resp, err := dialer.Dial(wsURL, headers)
	if conn != nil {
		defer conn.Close()
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	
	// Assertions - connection should be rejected due to expired token
	assert.Error(t, err, "Connection with expired token should be rejected")
	if resp != nil {
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Should return 401 for expired token")
	}
}

// TestWebSocketMessageBeforeAuthentication tests that connections without auth are rejected at handshake
func TestWebSocketMessageBeforeAuthentication(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	
	// Attempt connection without authentication - should fail during handshake
	conn, server, err := createTestClientNoAuth(t, handler, headers)
	defer server.Close()
	if conn != nil {
		defer conn.Close()
	}
	
	// Assertions - connection should be rejected during handshake
	assert.Error(t, err, "Connection without authentication should be rejected during handshake")
	assert.Nil(t, conn, "Connection should be nil when authentication fails during handshake")
}

// TestWebSocketConnectionDropDuringAuthentication tests handling invalid tokens during handshake
func TestWebSocketConnectionDropDuringAuthentication(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	// Setup mocks - invalid token should return error during handshake
	invalidToken := "invalid-token"
	mockJWT.On("ValidateToken", invalidToken).Return(nil, fmt.Errorf("invalid token"))
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	defer server.Close()
	
	// Convert to WebSocket URL with invalid token
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) + "/ws?token=" + invalidToken
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	
	dialer := websocket.Dialer{}
	conn, resp, err := dialer.Dial(wsURL, headers)
	if conn != nil {
		defer conn.Close()
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	
	// Assertions - connection should be rejected due to invalid token
	assert.Error(t, err, "Connection with invalid token should be rejected during handshake")
	if resp != nil {
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Should return 401 for invalid token")
	}
}

// TestWebSocketMalformedMessageHandling tests handling of invalid JSON/message format with authenticated connection
func TestWebSocketMalformedMessageHandling(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	// Setup mocks for authentication
	validClaims := createValidUserClaims()
	validToken := "valid-jwt-token"
	
	mockJWT.On("ValidateToken", validToken).Return(validClaims, nil)
	mockRedis.On("GetConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(0, nil)
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	
	// Create authenticated connection
	conn, server := createTestClient(t, handler, headers, validToken)
	defer server.Close()
	defer conn.Close()
	
	// Send malformed JSON
	err := conn.WriteMessage(websocket.TextMessage, []byte(`{invalid json`))
	require.NoError(t, err)
	
	// Read error response
	var response Message
	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	
	// Assertions
	assert.Equal(t, "error", response.Type)
	assert.Contains(t, response.Content, "invalid message format")
}

// TestWebSocketMaxConnectionsPerUser tests enforcement of connection limits
func TestWebSocketMaxConnectionsPerUser(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	// Setup mocks
	validClaims := createValidUserClaims()
	validToken := "valid-jwt-token"
	
	// Mock successful validation for both attempts
	mockJWT.On("ValidateToken", validToken).Return(validClaims, nil)
	// First connection succeeds (count = 2, under limit)
	mockRedis.On("GetConnectionCount", validClaims.UserID).Return(2, nil).Once()
	// Second connection exceeds limit (count = 4, over limit of 3)
	mockRedis.On("GetConnectionCount", validClaims.UserID).Return(4, nil).Once()
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(0, nil)
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	
	// Create first connection (should succeed - under limit)
	conn1, server1 := createTestClient(t, handler, headers, validToken)
	defer server1.Close()
	defer conn1.Close()
	
	// First connection should succeed
	assert.NotNil(t, conn1, "First connection should succeed when under limit")
	
	// Try to create second connection (should be rejected - over limit)
	server2 := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	defer server2.Close()
	
	wsURL := strings.Replace(server2.URL, "http://", "ws://", 1) + "/ws?token=" + validToken
	dialer := websocket.Dialer{}
	conn2, resp, err := dialer.Dial(wsURL, headers)
	if conn2 != nil {
		defer conn2.Close()
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	
	// Second connection should be rejected due to connection limit
	assert.Error(t, err, "Second connection should be rejected due to connection limit")
	if resp != nil {
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "Should return 429 for connection limit exceeded")
	}
}

// TestWebSocketRedisUnavailableDuringConnection tests handling Redis failures during handshake
func TestWebSocketRedisUnavailableDuringConnection(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	// Setup mocks
	validClaims := createValidUserClaims()
	validToken := "valid-jwt-token"
	
	mockJWT.On("ValidateToken", validToken).Return(validClaims, nil)
	mockRedis.On("GetConnectionCount", validClaims.UserID).Return(0, fmt.Errorf("redis connection failed"))
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	defer server.Close()
	
	// Convert to WebSocket URL with valid token
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) + "/ws?token=" + validToken
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	
	dialer := websocket.Dialer{}
	conn, resp, err := dialer.Dial(wsURL, headers)
	if conn != nil {
		defer conn.Close()
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	
	// Assertions - connection should be rejected due to Redis failure
	assert.Error(t, err, "Connection should fail when Redis is unavailable")
	if resp != nil {
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "Should return 500 for Redis failure")
	}
	
	mockJWT.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
}

// TestWebSocketConcurrentConnectionsFromSameUser tests handling multiple simultaneous connections
func TestWebSocketConcurrentConnectionsFromSameUser(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	// Setup mocks
	validClaims := createValidUserClaims()
	validToken := "valid-jwt-token"
	
	mockJWT.On("ValidateToken", validToken).Return(validClaims, nil)
	// First connection - should succeed
	mockRedis.On("GetConnectionCount", validClaims.UserID).Return(1, nil).Once()
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(2, nil).Once()
	// Second connection - should succeed  
	mockRedis.On("GetConnectionCount", validClaims.UserID).Return(2, nil).Once()
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(3, nil).Once()
	// Cleanup
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(2, nil).Once()
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(1, nil).Once()
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	var wg sync.WaitGroup
	wg.Add(2)
	
	var conn1, conn2 *websocket.Conn
	var server1, server2 *httptest.Server
	
	// Function to create and authenticate connection
	connectAndAuth := func(connNum int) {
		defer wg.Done()
		
		headers := http.Header{
			"Origin": []string{"http://localhost:3000"},
		}
		
		// Create authenticated connection
		conn, server := createTestClient(t, handler, headers, validToken)
		
		// Store connections so we can close them later
		if connNum == 1 {
			conn1, server1 = conn, server
		} else {
			conn2, server2 = conn, server
		}
		
		// Keep connection open briefly
		time.Sleep(100 * time.Millisecond)
	}
	
	// Create two concurrent connections
	go connectAndAuth(1)
	go connectAndAuth(2)
	
	wg.Wait()
	
	// Verify both connections are established
	assert.NotNil(t, conn1, "First connection should be established")
	assert.NotNil(t, conn2, "Second connection should be established")
	
	// Close connections explicitly to trigger cleanup
	if conn1 != nil {
		conn1.Close()
	}
	if conn2 != nil {
		conn2.Close()
	}
	if server1 != nil {
		server1.Close()
	}
	if server2 != nil {
		server2.Close()
	}
	
	// Wait for cleanup to complete
	time.Sleep(150 * time.Millisecond)
	
	mockJWT.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
}

// TestWebSocketOriginValidation tests rejection of connections from unauthorized origins
func TestWebSocketOriginValidation(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	defer server.Close()
	
	// Convert to WebSocket URL
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
	
	// Set invalid origin header
	headers := http.Header{
		"Origin": []string{"https://malicious-site.com"},
	}
	
	// Attempt connection with invalid origin
	dialer := websocket.Dialer{}
	conn, resp, err := dialer.Dial(wsURL, headers)
	
	// Assertions - connection should be rejected
	if conn != nil {
		conn.Close()
	}
	
	// Should either fail to connect or get 403 status
	if err == nil && resp != nil {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	} else {
		// Connection was rejected during handshake
		assert.Error(t, err)
	}
}

// TestWebSocketConnectionCleanupOnProcessExit tests graceful shutdown and resource cleanup
func TestWebSocketConnectionCleanupOnProcessExit(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	// Setup mocks
	validClaims := createValidUserClaims()
	validToken := "valid-jwt-token"
	
	mockJWT.On("ValidateToken", validToken).Return(validClaims, nil)
	mockRedis.On("GetConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(0, nil)
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	
	// Create authenticated connection
	conn, server := createTestClient(t, handler, headers, validToken)
	defer server.Close()
	
	// Verify connection is established
	assert.NotNil(t, conn, "Connection should be established")
	
	// Test cleanup by calling handler's cleanup method
	handler.Shutdown()
	
	// Close connection and verify cleanup occurred
	conn.Close()
	
	// Wait a moment for cleanup
	time.Sleep(100 * time.Millisecond)
	
	mockJWT.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
}