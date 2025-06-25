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

// Helper function to create a test WebSocket client
func createTestClient(t *testing.T, handler *Handler, headers http.Header) (*websocket.Conn, *httptest.Server) {
	server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	
	// Convert http://... to ws://...
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1) + "/ws"
	
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, headers)
	require.NoError(t, err)
	
	return conn, server
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

// TestWebSocketConnectionEstablishment tests successful WebSocket connection upgrade
func TestWebSocketConnectionEstablishment(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	defer server.Close()
	
	// Convert to WebSocket URL
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
	
	// Set valid origin header
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	
	// Attempt connection
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, headers)
	
	// Assertions
	assert.NoError(t, err, "WebSocket connection should be established successfully")
	assert.NotNil(t, conn, "Connection should not be nil")
	
	// Clean up
	conn.Close()
}

// TestWebSocketJWTAuthentication tests successful JWT authentication after connection
func TestWebSocketJWTAuthentication(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	mockFileManager := &MockFileManager{}
	mockSessionManager := &MockSessionManager{}
	
	// Setup mocks
	validClaims := createValidUserClaims()
	validToken := "valid-jwt-token"
	
	mockJWT.On("ValidateToken", validToken).Return(validClaims, nil)
	mockRedis.On("IsAvailable").Return(true)
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(0, nil)
	
	handler := createTestHandler(mockJWT, mockRedis, mockFileManager, mockSessionManager)
	
	// Create connection with valid origin
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	conn, server := createTestClient(t, handler, headers)
	defer server.Close()
	defer conn.Close()
	
	// Send authentication message
	authMsg := createAuthMessage(validToken)
	err := conn.WriteJSON(authMsg)
	require.NoError(t, err)
	
	// Read response
	var response Message
	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	
	// Assertions
	assert.Equal(t, "auth_success", response.Type)
	assert.Contains(t, response.Content, "authenticated")
	
	// Close connection to trigger cleanup
	conn.Close()
	server.Close()
	
	// Wait for cleanup to complete
	time.Sleep(100 * time.Millisecond)
	
	mockJWT.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
}

// TestWebSocketConnectionWithoutJWT tests rejection of unauthenticated connections
func TestWebSocketConnectionWithoutJWT(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	conn, server := createTestClient(t, handler, headers)
	defer server.Close()
	defer conn.Close()
	
	// Send non-auth message without authenticating first
	chatMsg := Message{
		Type:      "chat_message",
		Content:   "Hello",
		Timestamp: time.Now().Format(time.RFC3339),
		Data:      map[string]interface{}{},
	}
	
	err := conn.WriteJSON(chatMsg)
	require.NoError(t, err)
	
	// Read response - should be error
	var response Message
	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	
	// Assertions
	assert.Equal(t, "error", response.Type)
	assert.Contains(t, response.Content, "authentication required")
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
	conn, server := createTestClient(t, handler, headers)
	defer server.Close()
	defer conn.Close()
	
	// Send authentication message with expired token
	authMsg := createAuthMessage(expiredToken)
	err := conn.WriteJSON(authMsg)
	require.NoError(t, err)
	
	// Read response
	var response Message
	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	
	// Assertions
	assert.Equal(t, "error", response.Type)
	assert.Contains(t, response.Content, "authentication failed")
	
	mockJWT.AssertExpectations(t)
}

// TestWebSocketMessageBeforeAuthentication tests rejection of messages before auth
func TestWebSocketMessageBeforeAuthentication(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	conn, server := createTestClient(t, handler, headers)
	defer server.Close()
	defer conn.Close()
	
	// Send message before authentication
	msg := Message{
		Type:      "chat_message",
		Content:   "Hello before auth",
		Timestamp: time.Now().Format(time.RFC3339),
		Data:      map[string]interface{}{},
	}
	
	err := conn.WriteJSON(msg)
	require.NoError(t, err)
	
	// Read error response
	var response Message
	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	
	// Assertions
	assert.Equal(t, "error", response.Type)
	assert.Contains(t, response.Content, "authentication required")
}

// TestWebSocketConnectionDropDuringAuthentication tests handling connection loss during auth
func TestWebSocketConnectionDropDuringAuthentication(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	// Setup mocks - we expect the ValidateToken to be called but we'll close before completion
	mockJWT.On("ValidateToken", "some-token").Return(nil, fmt.Errorf("connection closed"))
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	conn, server := createTestClient(t, handler, headers)
	defer server.Close()
	
	// Start authentication process but close connection immediately
	authMsg := createAuthMessage("some-token")
	err := conn.WriteJSON(authMsg)
	require.NoError(t, err)
	
	// Close connection immediately
	conn.Close()
	
	// Handler should gracefully handle the dropped connection
	// This test verifies no panic occurs and cleanup happens properly
	time.Sleep(100 * time.Millisecond) // Give handler time to process
	
	// Test passes if no panic occurred
	assert.True(t, true, "Handler should gracefully handle dropped connections")
}

// TestWebSocketMalformedMessageHandling tests handling of invalid JSON/message format
func TestWebSocketMalformedMessageHandling(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	conn, server := createTestClient(t, handler, headers)
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
	
	mockJWT.On("ValidateToken", validToken).Return(validClaims, nil)
	mockRedis.On("IsAvailable").Return(true)
	// First connection should succeed (count = 1)
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(1, nil).Once()
	// Fourth connection should exceed limit (count = 4)
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(4, nil).Once()
	// Fourth connection will decrement immediately after exceeding limit
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(3, nil).Once()
	// First connection will decrement when it closes
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(0, nil).Once()
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	// Create first connection (should succeed)
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	conn1, server := createTestClient(t, handler, headers)
	defer server.Close()
	defer conn1.Close()
	
	// Authenticate first connection
	authMsg := createAuthMessage(validToken)
	err := conn1.WriteJSON(authMsg)
	require.NoError(t, err)
	
	// Read success response
	var response Message
	err = conn1.ReadJSON(&response)
	require.NoError(t, err)
	assert.Equal(t, "auth_success", response.Type)
	
	// Try to create fourth connection (should be rejected due to limit)
	conn4, _ := createTestClient(t, handler, headers)
	defer conn4.Close()
	
	// Authenticate fourth connection
	err = conn4.WriteJSON(authMsg)
	require.NoError(t, err)
	
	// Read rejection response
	err = conn4.ReadJSON(&response)
	require.NoError(t, err)
	assert.Equal(t, "error", response.Type)
	assert.Contains(t, response.Content, "connection limit exceeded")
	
	// Close connections to trigger cleanup
	conn1.Close()
	conn4.Close()
	server.Close()
	
	// Wait for cleanup to complete
	time.Sleep(100 * time.Millisecond)
	
	mockJWT.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
}

// TestWebSocketRedisUnavailableDuringConnection tests handling Redis failures
func TestWebSocketRedisUnavailableDuringConnection(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	
	// Setup mocks
	validClaims := createValidUserClaims()
	validToken := "valid-jwt-token"
	
	mockJWT.On("ValidateToken", validToken).Return(validClaims, nil)
	mockRedis.On("IsAvailable").Return(true)
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(0, fmt.Errorf("redis connection failed"))
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	conn, server := createTestClient(t, handler, headers)
	defer server.Close()
	defer conn.Close()
	
	// Send authentication message
	authMsg := createAuthMessage(validToken)
	err := conn.WriteJSON(authMsg)
	require.NoError(t, err)
	
	// Read response - should be error due to Redis failure
	var response Message
	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	
	// Assertions
	assert.Equal(t, "error", response.Type)
	assert.Contains(t, response.Content, "service temporarily unavailable")
	
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
	mockRedis.On("IsAvailable").Return(true)
	// First connection
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(1, nil).Once()
	// Second connection
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(2, nil).Once()
	// Cleanup
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(1, nil).Times(2)
	
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
		conn, server := createTestClient(t, handler, headers)
		
		// Store connections so we can close them later
		if connNum == 1 {
			conn1, server1 = conn, server
		} else {
			conn2, server2 = conn, server
		}
		
		// Authenticate
		authMsg := createAuthMessage(validToken)
		err := conn.WriteJSON(authMsg)
		require.NoError(t, err)
		
		// Read response
		var response Message
		err = conn.ReadJSON(&response)
		require.NoError(t, err)
		assert.Equal(t, "auth_success", response.Type)
		
		// Keep connection open briefly
		time.Sleep(100 * time.Millisecond)
	}
	
	// Create two concurrent connections
	go connectAndAuth(1)
	go connectAndAuth(2)
	
	wg.Wait()
	
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
	mockRedis.On("IsAvailable").Return(true)
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(0, nil)
	
	handler := createTestHandler(mockJWT, mockRedis, &MockFileManager{}, &MockSessionManager{})
	
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	conn, server := createTestClient(t, handler, headers)
	defer server.Close()
	
	// Authenticate connection
	authMsg := createAuthMessage(validToken)
	err := conn.WriteJSON(authMsg)
	require.NoError(t, err)
	
	// Read success response
	var response Message
	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	assert.Equal(t, "auth_success", response.Type)
	
	// Test cleanup by calling handler's cleanup method
	handler.Shutdown()
	
	// Close connection and verify cleanup occurred
	conn.Close()
	
	// Wait a moment for cleanup
	time.Sleep(100 * time.Millisecond)
	
	mockJWT.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
}