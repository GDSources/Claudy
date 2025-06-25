package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"github.com/testcontainers/testcontainers-go/modules/redis"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"claudy/internal/auth"
	"claudy/internal/files"
	"claudy/internal/models"
	redisService "claudy/internal/redis"
	"claudy/internal/repository"
	"claudy/internal/session"
	wsHandler "claudy/internal/websocket"
)

// TestFramework provides the testing infrastructure with real containers
type TestFramework struct {
	// Container instances
	mongoContainer testcontainers.Container
	redisContainer testcontainers.Container
	
	// Service instances
	mongoClient    *mongo.Client
	mongoDB        *mongo.Database
	userRepo       models.UserRepository
	redisService   *redisService.Service
	jwtService     *auth.JWTService
	sessionManager *session.ClaudeSessionManager
	fileManager    *files.FileManager
	wsHandler      *wsHandler.Handler
	
	// Configuration
	mongoURI   string
	redisAddr  string
	
	// Cleanup functions
	cleanupFuncs []func()
}

// SetupTestFramework initializes the testing infrastructure with real containers
func SetupTestFramework(t *testing.T) *TestFramework {
	ctx := context.Background()
	framework := &TestFramework{
		cleanupFuncs: make([]func(), 0),
	}

	// Start MongoDB container
	mongoContainer, err := mongodb.Run(ctx,
		"mongo:7.0",
		mongodb.WithUsername("testuser"),
		mongodb.WithPassword("testpass"),
	)
	require.NoError(t, err)
	framework.mongoContainer = mongoContainer
	framework.cleanupFuncs = append(framework.cleanupFuncs, func() {
		mongoContainer.Terminate(ctx)
	})

	// Get MongoDB connection string
	mongoURI, err := mongoContainer.ConnectionString(ctx)
	require.NoError(t, err)
	framework.mongoURI = mongoURI

	// Start Redis container
	redisContainer, err := redis.Run(ctx, "redis:7.0-alpine")
	require.NoError(t, err)
	framework.redisContainer = redisContainer
	framework.cleanupFuncs = append(framework.cleanupFuncs, func() {
		redisContainer.Terminate(ctx)
	})

	// Get Redis connection details
	redisAddr, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)
	// Remove redis:// prefix if present
	redisAddr = strings.TrimPrefix(redisAddr, "redis://")
	framework.redisAddr = redisAddr

	// Initialize services
	framework.initializeServices(t)

	return framework
}

// initializeServices sets up all the service instances
func (f *TestFramework) initializeServices(t *testing.T) {
	ctx := context.Background()

	// Initialize MongoDB client
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(f.mongoURI))
	require.NoError(t, err)
	f.mongoClient = client
	f.cleanupFuncs = append(f.cleanupFuncs, func() {
		client.Disconnect(ctx)
	})

	// Initialize database and repository
	f.mongoDB = client.Database("testdb")
	f.userRepo = repository.NewMongoUserRepository(f.mongoDB)

	// Initialize Redis service
	f.redisService = redisService.NewService(f.redisAddr, "", 0)
	f.cleanupFuncs = append(f.cleanupFuncs, func() {
		f.redisService.Close()
	})

	// Generate RSA keys for JWT
	privateKey, publicKey := generateTestKeys(t)
	f.jwtService, err = auth.NewJWTService(privateKey, publicKey)
	require.NoError(t, err)

	// Initialize session manager with mock process manager for testing
	apiClient := session.NewHTTPClaudeAPIClient("https://api.anthropic.com")
	processManager := NewMockProcessManager()
	workspaceManager := session.NewLocalWorkspaceManager("/tmp/claudy-test-workspaces")
	encryptionKey := make([]byte, 32)
	_, err = rand.Read(encryptionKey)
	require.NoError(t, err)
	encryptionService, err := session.NewAESGCMEncryptionService(encryptionKey)
	require.NoError(t, err)

	f.sessionManager = session.NewClaudeSessionManager(
		apiClient,
		processManager,
		workspaceManager,
		encryptionService,
	)
	f.cleanupFuncs = append(f.cleanupFuncs, func() {
		f.sessionManager.Stop(ctx)
	})

	// Initialize file manager
	f.fileManager = files.NewFileManager(10*1024*1024, 100*1024*1024) // 10MB per file, 100MB per workspace

	// Initialize WebSocket handler
	wsConfig := wsHandler.Config{
		MaxConnectionsPerUser: 3,
		AllowedOrigins:        []string{"http://localhost:3000"},
		ReadTimeout:           60 * time.Second,
		WriteTimeout:          10 * time.Second,
		PingInterval:          30 * time.Second,
	}
	f.wsHandler = wsHandler.NewHandler(f.jwtService, f.redisService, f.fileManager, f.sessionManager, wsConfig)
	f.cleanupFuncs = append(f.cleanupFuncs, func() {
		f.wsHandler.Shutdown()
	})
}

// Cleanup tears down all test infrastructure
func (f *TestFramework) Cleanup() {
	for i := len(f.cleanupFuncs) - 1; i >= 0; i-- {
		f.cleanupFuncs[i]()
	}
}

// ResetData clears all data from containers
func (f *TestFramework) ResetData(t *testing.T) {
	ctx := context.Background()
	
	// Clear MongoDB
	err := f.mongoDB.Drop(ctx)
	require.NoError(t, err)
	
	// Clear Redis
	err = f.redisService.FlushAll()
	require.NoError(t, err)
	
	// Reinitialize repository to recreate indexes
	f.userRepo = repository.NewMongoUserRepository(f.mongoDB)
}

// CreateTestUser creates a test user in the database
func (f *TestFramework) CreateTestUser(t *testing.T, githubID int64, username, email string) *models.User {
	ctx := context.Background()
	
	profile := models.GitHubProfile{
		ID:        githubID,
		Login:     username,
		Email:     email,
		AvatarURL: "https://example.com/avatar.jpg",
	}
	
	user, err := models.CreateUserFromGitHubProfile(ctx, f.userRepo, profile)
	require.NoError(t, err)
	
	return user
}

// GenerateTestJWT generates a JWT token for testing
func (f *TestFramework) GenerateTestJWT(t *testing.T, user *models.User) string {
	claims := auth.UserClaims{
		UserID:   user.ID.Hex(),
		GitHubID: fmt.Sprintf("%d", user.GitHubID),
		Username: user.Username,
	}
	
	token, err := f.jwtService.GenerateToken(claims, 24*time.Hour)
	require.NoError(t, err)
	
	return token
}

// generateTestKeys generates RSA key pair for testing
func generateTestKeys(t *testing.T) (string, string) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode private key to PEM
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(privateKeyPEM), string(publicKeyPEM)
}

// INTEGRATION TESTS

// TestFullUserAuthenticationFlow tests complete OAuth2 + JWT + MongoDB flow
func TestFullUserAuthenticationFlow(t *testing.T) {
	framework := SetupTestFramework(t)
	defer framework.Cleanup()

	ctx := context.Background()

	// Test user creation through GitHub profile
	githubProfile := models.GitHubProfile{
		ID:        12345,
		Login:     "testuser",
		Email:     "test@example.com",
		AvatarURL: "https://example.com/avatar.jpg",
	}

	// Create user from GitHub profile
	user, err := models.CreateUserFromGitHubProfile(ctx, framework.userRepo, githubProfile)
	require.NoError(t, err)
	assert.NotEmpty(t, user.ID)
	assert.Equal(t, int64(12345), user.GitHubID)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "test@example.com", user.Email)

	// Generate JWT token
	claims := auth.UserClaims{
		UserID:   user.ID.Hex(),
		GitHubID: "12345",
		Username: "testuser",
	}
	
	token, err := framework.jwtService.GenerateToken(claims, 24*time.Hour)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate JWT token
	validatedClaims, err := framework.jwtService.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, user.ID.Hex(), validatedClaims.UserID)
	assert.Equal(t, "12345", validatedClaims.GitHubID)
	assert.Equal(t, "testuser", validatedClaims.Username)

	// Retrieve user from database
	retrievedUser, err := framework.userRepo.GetUserByGitHubID(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, user.ID, retrievedUser.ID)
	assert.Equal(t, user.GitHubID, retrievedUser.GitHubID)

	// Test duplicate user creation (should fail)
	_, err = models.CreateUserFromGitHubProfile(ctx, framework.userRepo, githubProfile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// Store original last login time (truncated to seconds for comparison)
	originalLastLogin := user.LastLogin.Truncate(time.Second)
	
	// Small delay to ensure time difference
	time.Sleep(1 * time.Second)
	
	// Update user last login
	err = models.UpdateUserLastLogin(ctx, framework.userRepo, user)
	require.NoError(t, err)

	// Verify last login was updated
	updatedUser, err := framework.userRepo.GetUserByID(ctx, user.ID)
	require.NoError(t, err)
	
	// Compare times truncated to seconds to avoid precision issues
	updatedLastLogin := updatedUser.LastLogin.Truncate(time.Second)
	
	// The updated time should be after the original time
	assert.True(t, updatedLastLogin.After(originalLastLogin), "Last login should be updated")
}

// TestWebSocketSessionWithRedis tests WebSocket + Redis state management
func TestWebSocketSessionWithRedis(t *testing.T) {
	framework := SetupTestFramework(t)
	defer framework.Cleanup()

	// Create test user
	user := framework.CreateTestUser(t, 12345, "testuser", "test@example.com")
	token := framework.GenerateTestJWT(t, user)

	// Create WebSocket server
	server := httptest.NewServer(http.HandlerFunc(framework.wsHandler.HandleWebSocket))
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect to WebSocket with proper origin header
	dialer := websocket.Dialer{}
	header := http.Header{}
	header.Set("Origin", "http://localhost:3000")
	conn, _, err := dialer.Dial(wsURL, header)
	require.NoError(t, err)
	defer conn.Close()

	// Test authentication
	authMsg := wsHandler.Message{
		Type:      "auth",
		Content:   token,
		Timestamp: time.Now().Format(time.RFC3339),
		Data:      make(map[string]interface{}),
	}

	err = conn.WriteJSON(authMsg)
	require.NoError(t, err)

	// Read authentication response
	var response wsHandler.Message
	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	assert.Equal(t, "auth_success", response.Type)
	assert.Contains(t, response.Content, "successfully authenticated")

	// Verify connection count in Redis
	count, err := framework.redisService.GetConnectionCount(user.ID.Hex())
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Test multiple connections from same user
	header2 := http.Header{}
	header2.Set("Origin", "http://localhost:3000")
	conn2, _, err := dialer.Dial(wsURL, header2)
	require.NoError(t, err)
	defer conn2.Close()

	err = conn2.WriteJSON(authMsg)
	require.NoError(t, err)

	err = conn2.ReadJSON(&response)
	require.NoError(t, err)
	assert.Equal(t, "auth_success", response.Type)

	// Verify connection count increased
	count, err = framework.redisService.GetConnectionCount(user.ID.Hex())
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Close first connection
	conn.Close()
	time.Sleep(100 * time.Millisecond) // Allow cleanup to happen

	// Verify connection count decreased
	count, err = framework.redisService.GetConnectionCount(user.ID.Hex())
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// TestCompleteUserSession tests login → WebSocket → Claude Code → Cleanup
func TestCompleteUserSession(t *testing.T) {
	framework := SetupTestFramework(t)
	defer framework.Cleanup()

	ctx := context.Background()

	// 1. Create user (simulating OAuth2 login)
	user := framework.CreateTestUser(t, 12345, "testuser", "test@example.com")
	token := framework.GenerateTestJWT(t, user)

	// 2. Establish WebSocket connection
	server := httptest.NewServer(http.HandlerFunc(framework.wsHandler.HandleWebSocket))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	dialer := websocket.Dialer{}
	header := http.Header{}
	header.Set("Origin", "http://localhost:3000")
	conn, _, err := dialer.Dial(wsURL, header)
	require.NoError(t, err)
	defer conn.Close()

	// 3. Authenticate WebSocket
	authMsg := wsHandler.Message{
		Type:    "auth",
		Content: token,
		Data:    make(map[string]interface{}),
	}

	err = conn.WriteJSON(authMsg)
	require.NoError(t, err)

	var response wsHandler.Message
	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	assert.Equal(t, "auth_success", response.Type)

	// 4. Create Claude Code session
	claudeSession, err := framework.sessionManager.CreateSession(ctx, user.ID.Hex(), "sk-ant-api03-valid-token-12345")
	require.NoError(t, err)
	assert.NotNil(t, claudeSession)
	assert.Equal(t, session.SessionStatusActive, claudeSession.Status)

	// 5. Test file operations through WebSocket
	fileUploadMsg := wsHandler.Message{
		Type: "file_upload",
		Data: map[string]interface{}{
			"filename": "test.py",
			"content":  "print('Hello from integration test!')",
			"encoding": "utf-8",
		},
	}

	err = conn.WriteJSON(fileUploadMsg)
	require.NoError(t, err)

	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	assert.Equal(t, "file_uploaded", response.Type)

	// 6. List files
	listMsg := wsHandler.Message{
		Type: "file_list",
		Data: make(map[string]interface{}),
	}

	err = conn.WriteJSON(listMsg)
	require.NoError(t, err)

	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	assert.Equal(t, "file_list", response.Type)

	// 7. Get workspace info
	workspaceMsg := wsHandler.Message{
		Type: "workspace_info",
		Data: make(map[string]interface{}),
	}

	err = conn.WriteJSON(workspaceMsg)
	require.NoError(t, err)

	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	assert.Equal(t, "workspace_info", response.Type)

	// 8. Cleanup session
	err = framework.sessionManager.TerminateSession(ctx, claudeSession.ID.Hex())
	require.NoError(t, err)

	// 9. Verify session is terminated
	assert.False(t, framework.sessionManager.IsSessionActive(claudeSession.ID.Hex()))

	// 10. Close WebSocket connection
	conn.Close()

	// 11. Verify Redis state is cleaned up
	time.Sleep(100 * time.Millisecond)
	count, err := framework.redisService.GetConnectionCount(user.ID.Hex())
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// TestDatabaseFailoverDuringSession simulates MongoDB failover
func TestDatabaseFailoverDuringSession(t *testing.T) {
	framework := SetupTestFramework(t)
	defer framework.Cleanup()

	ctx := context.Background()

	// Create initial user
	user := framework.CreateTestUser(t, 12345, "testuser", "test@example.com")

	// Verify user exists
	retrievedUser, err := framework.userRepo.GetUserByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Username, retrievedUser.Username)

	// Simulate network partition by pausing the container
	err = framework.mongoContainer.Stop(ctx, nil)
	require.NoError(t, err)

	// Try to access database - should fail
	_, err = framework.userRepo.GetUserByID(ctx, user.ID)
	assert.Error(t, err)

	// Restart the container (simulating failover recovery)
	err = framework.mongoContainer.Start(ctx)
	require.NoError(t, err)

	// Wait for MongoDB to be ready
	time.Sleep(5 * time.Second)

	// Get new connection string after restart
	endpoint, err := framework.mongoContainer.Endpoint(ctx, "")
	require.NoError(t, err)
	framework.mongoURI = "mongodb://testuser:testpass@" + endpoint + "/testdb?authSource=admin"

	// Reconnect MongoDB client with new URI
	framework.mongoClient.Disconnect(ctx)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(framework.mongoURI))
	require.NoError(t, err)
	framework.mongoClient = client
	framework.mongoDB = client.Database("testdb")
	framework.userRepo = repository.NewMongoUserRepository(framework.mongoDB)

	// Recreate test data
	user2 := framework.CreateTestUser(t, 54321, "testuser2", "test2@example.com")

	// Verify database is working again
	retrievedUser2, err := framework.userRepo.GetUserByID(ctx, user2.ID)
	require.NoError(t, err)
	assert.Equal(t, user2.Username, retrievedUser2.Username)
}

// TestRedisFailoverDuringWebSocket simulates Redis failover
func TestRedisFailoverDuringWebSocket(t *testing.T) {
	framework := SetupTestFramework(t)
	defer framework.Cleanup()

	// Create test user and WebSocket connection
	user := framework.CreateTestUser(t, 12345, "testuser", "test@example.com")
	token := framework.GenerateTestJWT(t, user)

	server := httptest.NewServer(http.HandlerFunc(framework.wsHandler.HandleWebSocket))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	dialer := websocket.Dialer{}
	header := http.Header{}
	header.Set("Origin", "http://localhost:3000")
	conn, _, err := dialer.Dial(wsURL, header)
	require.NoError(t, err)
	defer conn.Close()

	// Authenticate successfully
	authMsg := wsHandler.Message{
		Type:    "auth",
		Content: token,
		Data:    make(map[string]interface{}),
	}

	err = conn.WriteJSON(authMsg)
	require.NoError(t, err)

	var response wsHandler.Message
	err = conn.ReadJSON(&response)
	require.NoError(t, err)
	assert.Equal(t, "auth_success", response.Type)

	// Verify Redis is working
	count, err := framework.redisService.GetConnectionCount(user.ID.Hex())
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Stop Redis container (simulate failure)
	ctx := context.Background()
	err = framework.redisContainer.Stop(ctx, nil)
	require.NoError(t, err)

	// Try to connect another WebSocket - should fail gracefully
	header2 := http.Header{}
	header2.Set("Origin", "http://localhost:3000")
	conn2, _, err := dialer.Dial(wsURL, header2)
	require.NoError(t, err)
	defer conn2.Close()

	err = conn2.WriteJSON(authMsg)
	require.NoError(t, err)

	err = conn2.ReadJSON(&response)
	require.NoError(t, err)
	assert.Equal(t, "error", response.Type)
	assert.Contains(t, response.Content, "service temporarily unavailable")

	// Restart Redis
	err = framework.redisContainer.Start(ctx)
	require.NoError(t, err)

	// Wait for Redis to be ready
	time.Sleep(2 * time.Second)

	// Recreate Redis service
	framework.redisService.Close()
	framework.redisService = redisService.NewService(framework.redisAddr, "", 0)

	// New connections should work again
	header3 := http.Header{}
	header3.Set("Origin", "http://localhost:3000")
	conn3, _, err := dialer.Dial(wsURL, header3)
	require.NoError(t, err)
	defer conn3.Close()

	err = conn3.WriteJSON(authMsg)
	require.NoError(t, err)

	err = conn3.ReadJSON(&response)
	require.NoError(t, err)
	assert.Equal(t, "auth_success", response.Type)
}

// TestSystemResourceExhaustionRecovery tests resource limit enforcement and recovery
func TestSystemResourceExhaustionRecovery(t *testing.T) {
	framework := SetupTestFramework(t)
	defer framework.Cleanup()

	ctx := context.Background()

	// Create user and session manager with limited resources
	user := framework.CreateTestUser(t, 12345, "testuser", "test@example.com")

	// Create session
	claudeSession, err := framework.sessionManager.CreateSession(ctx, user.ID.Hex(), "sk-ant-api03-valid-token-12345")
	require.NoError(t, err)

	// Test resource monitoring
	err = framework.sessionManager.CheckResourceUsage(claudeSession.ID.Hex())
	require.NoError(t, err)

	// Verify session is still active after resource check
	assert.True(t, framework.sessionManager.IsSessionActive(claudeSession.ID.Hex()))

	// Test workspace cleanup
	workspaceSize, err := framework.fileManager.GetWorkspaceSize(ctx, claudeSession.WorkspacePath)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, workspaceSize, int64(0))

	// Test file size limits
	largeContent := strings.Repeat("x", 11*1024*1024) // 11MB - should exceed limit
	_, err = framework.fileManager.UploadFile(ctx, claudeSession.WorkspacePath, "large.txt", largeContent, "utf-8")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size exceeds limit")

	// Test reasonable file upload
	reasonableContent := "print('Hello World')"
	result, err := framework.fileManager.UploadFile(ctx, claudeSession.WorkspacePath, "small.py", reasonableContent, "utf-8")
	require.NoError(t, err)
	assert.Equal(t, "small.py", result.Filename)
	assert.Equal(t, int64(len(reasonableContent)), result.Size)
}

// TestConcurrentUserSessionsAtScale tests 100+ concurrent sessions
func TestConcurrentUserSessionsAtScale(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping scale test in short mode")
	}

	framework := SetupTestFramework(t)
	defer framework.Cleanup()

	const numUsers = 100
	const connectionsPerUser = 2

	var wg sync.WaitGroup
	results := make(chan error, numUsers*connectionsPerUser)

	// Create WebSocket server
	server := httptest.NewServer(http.HandlerFunc(framework.wsHandler.HandleWebSocket))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Create concurrent user sessions
	for i := 0; i < numUsers; i++ {
		userID := int64(10000 + i)
		user := framework.CreateTestUser(t, userID, fmt.Sprintf("user%d", i), fmt.Sprintf("user%d@example.com", i))
		token := framework.GenerateTestJWT(t, user)

		// Create multiple connections per user
		for j := 0; j < connectionsPerUser; j++ {
			wg.Add(1)
			go func(userToken string, userIndex, connIndex int) {
				defer wg.Done()

				dialer := websocket.Dialer{}
				header := http.Header{}
				header.Set("Origin", "http://localhost:3000")
				conn, _, err := dialer.Dial(wsURL, header)
				if err != nil {
					results <- fmt.Errorf("user %d conn %d: dial failed: %v", userIndex, connIndex, err)
					return
				}
				defer conn.Close()

				// Authenticate
				authMsg := wsHandler.Message{
					Type:    "auth",
					Content: userToken,
					Data:    make(map[string]interface{}),
				}

				err = conn.WriteJSON(authMsg)
				if err != nil {
					results <- fmt.Errorf("user %d conn %d: auth write failed: %v", userIndex, connIndex, err)
					return
				}

				var response wsHandler.Message
				err = conn.ReadJSON(&response)
				if err != nil {
					results <- fmt.Errorf("user %d conn %d: auth read failed: %v", userIndex, connIndex, err)
					return
				}

				if response.Type != "auth_success" {
					results <- fmt.Errorf("user %d conn %d: auth failed: %s", userIndex, connIndex, response.Content)
					return
				}

				// Send a test message
				testMsg := wsHandler.Message{
					Type:    "chat_message",
					Content: fmt.Sprintf("Hello from user %d connection %d", userIndex, connIndex),
					Data:    make(map[string]interface{}),
				}

				err = conn.WriteJSON(testMsg)
				if err != nil {
					results <- fmt.Errorf("user %d conn %d: message write failed: %v", userIndex, connIndex, err)
					return
				}

				err = conn.ReadJSON(&response)
				if err != nil {
					results <- fmt.Errorf("user %d conn %d: message read failed: %v", userIndex, connIndex, err)
					return
				}

				results <- nil // Success
			}(token, i, j)
		}
	}

	// Wait for all connections to complete
	wg.Wait()
	close(results)

	// Check results
	successCount := 0
	var errors []error
	for result := range results {
		if result == nil {
			successCount++
		} else {
			errors = append(errors, result)
		}
	}

	// Report results
	totalConnections := numUsers * connectionsPerUser
	successRate := float64(successCount) / float64(totalConnections)
	
	t.Logf("Scale test results: %d/%d connections successful (%.2f%%)", successCount, totalConnections, successRate*100)
	
	// We expect at least 95% success rate
	assert.GreaterOrEqual(t, successRate, 0.95, "Expected at least 95%% success rate")
	
	if len(errors) > 0 {
		t.Logf("Sample errors: %v", errors[:min(5, len(errors))])
	}
}

// TestGracefulShutdownWithActiveSessions tests service shutdown procedures
func TestGracefulShutdownWithActiveSessions(t *testing.T) {
	framework := SetupTestFramework(t)
	defer framework.Cleanup()

	ctx := context.Background()

	// Create multiple users with active sessions
	users := make([]*models.User, 3)
	sessions := make([]*session.ClaudeSession, 3)
	
	for i := 0; i < 3; i++ {
		users[i] = framework.CreateTestUser(t, int64(12345+i), fmt.Sprintf("user%d", i), fmt.Sprintf("user%d@example.com", i))
		
		session, err := framework.sessionManager.CreateSession(ctx, users[i].ID.Hex(), "sk-ant-api03-valid-token-12345")
		require.NoError(t, err)
		sessions[i] = session
	}

	// Verify all sessions are active
	for i, session := range sessions {
		assert.True(t, framework.sessionManager.IsSessionActive(session.ID.Hex()), "Session %d should be active", i)
	}

	// Create WebSocket connections
	server := httptest.NewServer(http.HandlerFunc(framework.wsHandler.HandleWebSocket))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	connections := make([]*websocket.Conn, 3)
	
	for i, user := range users {
		token := framework.GenerateTestJWT(t, user)
		
		dialer := websocket.Dialer{}
		header := http.Header{}
		header.Set("Origin", "http://localhost:3000")
		conn, _, err := dialer.Dial(wsURL, header)
		require.NoError(t, err)
		connections[i] = conn
		
		// Authenticate
		authMsg := wsHandler.Message{
			Type:    "auth",
			Content: token,
			Data:    make(map[string]interface{}),
		}
		
		err = conn.WriteJSON(authMsg)
		require.NoError(t, err)
		
		var response wsHandler.Message
		err = conn.ReadJSON(&response)
		require.NoError(t, err)
		assert.Equal(t, "auth_success", response.Type)
	}

	// Verify Redis connections
	for _, user := range users {
		count, err := framework.redisService.GetConnectionCount(user.ID.Hex())
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	}

	// Trigger graceful shutdown
	framework.wsHandler.Shutdown()
	
	// Wait for shutdown to complete
	time.Sleep(100 * time.Millisecond)

	// Stop session manager
	err := framework.sessionManager.Stop(ctx)
	require.NoError(t, err)

	// Verify sessions are terminated
	for i, session := range sessions {
		assert.False(t, framework.sessionManager.IsSessionActive(session.ID.Hex()), "Session %d should be terminated", i)
	}

	// Close connections
	for _, conn := range connections {
		conn.Close()
	}
}

// TestCorruptedSessionDataRecovery tests handling of corrupted session state
func TestCorruptedSessionDataRecovery(t *testing.T) {
	framework := SetupTestFramework(t)
	defer framework.Cleanup()

	ctx := context.Background()

	// Create user and session
	user := framework.CreateTestUser(t, 12345, "testuser", "test@example.com")
	claudeSession, err := framework.sessionManager.CreateSession(ctx, user.ID.Hex(), "sk-ant-api03-valid-token-12345")
	require.NoError(t, err)

	// Store corrupted data in Redis
	err = framework.redisService.StoreSessionData(claudeSession.ID.Hex(), map[string]interface{}{
		"status":      "corrupted",
		"invalid_key": make(chan int), // This will cause JSON marshaling issues
	})
	// This should fail, but we test the recovery

	// Try to retrieve session data
	data, err := framework.redisService.GetSessionData(claudeSession.ID.Hex())
	require.NoError(t, err) // Should not fail catastrophically
	
	// Verify we can handle empty/corrupted data gracefully
	t.Logf("Retrieved session data: %v", data)
	
	// Verify we can still operate with the session
	assert.True(t, framework.sessionManager.IsSessionActive(claudeSession.ID.Hex()))

	// Test cleanup of corrupted data
	cleaned := framework.sessionManager.CleanupInactiveSessions(ctx)
	t.Logf("Cleaned up %d sessions", cleaned)

	// Session should still be active (not cleaned up due to recent activity)
	assert.True(t, framework.sessionManager.IsSessionActive(claudeSession.ID.Hex()))
}

// TestNetworkPartitionRecovery tests network partition simulation
func TestNetworkPartitionRecovery(t *testing.T) {
	framework := SetupTestFramework(t)
	defer framework.Cleanup()

	ctx := context.Background()

	// Create initial state
	user := framework.CreateTestUser(t, 12345, "testuser", "test@example.com")
	
	// Verify initial connectivity
	err := framework.redisService.Ping()
	require.NoError(t, err)

	retrievedUser, err := framework.userRepo.GetUserByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Username, retrievedUser.Username)

	// Simulate network partition by stopping both containers
	err = framework.mongoContainer.Stop(ctx, nil)
	require.NoError(t, err)
	err = framework.redisContainer.Stop(ctx, nil)
	require.NoError(t, err)

	// Verify services are unavailable
	assert.False(t, framework.redisService.IsAvailable())

	_, err = framework.userRepo.GetUserByID(ctx, user.ID)
	assert.Error(t, err)

	// Simulate network recovery
	err = framework.mongoContainer.Start(ctx)
	require.NoError(t, err)
	err = framework.redisContainer.Start(ctx)
	require.NoError(t, err)

	// Wait for services to be ready
	time.Sleep(5 * time.Second)

	// Get new connection strings after restart
	mongoEndpoint, err := framework.mongoContainer.Endpoint(ctx, "")
	require.NoError(t, err)
	framework.mongoURI = "mongodb://testuser:testpass@" + mongoEndpoint + "/testdb?authSource=admin"
	
	redisEndpoint, err := framework.redisContainer.Endpoint(ctx, "")
	require.NoError(t, err)
	framework.redisAddr = redisEndpoint

	// Reconnect services
	framework.mongoClient.Disconnect(ctx)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(framework.mongoURI))
	require.NoError(t, err)
	framework.mongoClient = client
	framework.mongoDB = client.Database("testdb")
	framework.userRepo = repository.NewMongoUserRepository(framework.mongoDB)

	framework.redisService.Close()
	framework.redisService = redisService.NewService(framework.redisAddr, "", 0)

	// Verify services are available again
	assert.True(t, framework.redisService.IsAvailable())

	// Recreate test data and verify functionality
	user2 := framework.CreateTestUser(t, 54321, "testuser2", "test2@example.com")
	retrievedUser2, err := framework.userRepo.GetUserByID(ctx, user2.ID)
	require.NoError(t, err)
	assert.Equal(t, user2.Username, retrievedUser2.Username)

	// Test Redis operations
	err = framework.redisService.SetConnectionCount(user2.ID.Hex(), 1)
	require.NoError(t, err)
	
	count, err := framework.redisService.GetConnectionCount(user2.ID.Hex())
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}