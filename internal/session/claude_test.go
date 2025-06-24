package session

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Mock interfaces and types for testing
type MockClaudeAPIClient struct {
	mock.Mock
}

func (m *MockClaudeAPIClient) ValidateToken(ctx context.Context, token string) (*TokenValidationResponse, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TokenValidationResponse), args.Error(1)
}

type MockProcessManager struct {
	mock.Mock
}

func (m *MockProcessManager) StartProcess(ctx context.Context, config ProcessConfig) (*ProcessInfo, error) {
	args := m.Called(ctx, config)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ProcessInfo), args.Error(1)
}

func (m *MockProcessManager) StopProcess(processID int) error {
	args := m.Called(processID)
	return args.Error(0)
}

func (m *MockProcessManager) IsProcessRunning(processID int) bool {
	args := m.Called(processID)
	return args.Bool(0)
}

func (m *MockProcessManager) GetProcessMetrics(processID int) (*ProcessMetrics, error) {
	args := m.Called(processID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ProcessMetrics), args.Error(1)
}

type MockWorkspaceManager struct {
	mock.Mock
}

func (m *MockWorkspaceManager) CreateWorkspace(ctx context.Context, userID string) (*WorkspaceInfo, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*WorkspaceInfo), args.Error(1)
}

func (m *MockWorkspaceManager) DeleteWorkspace(ctx context.Context, workspacePath string) error {
	args := m.Called(ctx, workspacePath)
	return args.Error(0)
}

func (m *MockWorkspaceManager) GetWorkspaceUsage(workspacePath string) (*WorkspaceUsage, error) {
	args := m.Called(workspacePath)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*WorkspaceUsage), args.Error(1)
}

type MockEncryptionService struct {
	mock.Mock
}

func (m *MockEncryptionService) Encrypt(data string) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

func (m *MockEncryptionService) Decrypt(encryptedData string) (string, error) {
	args := m.Called(encryptedData)
	return args.String(0), args.Error(1)
}


// Test fixtures
func createTestSession(userID string) *ClaudeSession {
	sessionID := primitive.NewObjectID()
	return &ClaudeSession{
		ID:            sessionID,
		UserID:        userID,
		Status:        SessionStatusActive,
		CreatedAt:     time.Now(),
		LastActivity:  time.Now(),
		WorkspacePath: fmt.Sprintf("/tmp/workspace_%s", sessionID.Hex()),
		ProcessID:     12345,
		EncryptedToken: "encrypted_token_data",
	}
}

func createValidClaudeToken() string {
	return "sk-ant-api03-valid-token-12345"
}

func createInvalidClaudeToken() string {
	return "invalid-token-format"
}

func createTestEncryptionKey() []byte {
	key := make([]byte, 32) // AES-256 requires 32 bytes
	rand.Read(key)
	return key
}

// Test: Happy Path - Validate working Claude API token
func TestClaudeTokenValidation(t *testing.T) {
	// Setup
	mockClient := &MockClaudeAPIClient{}
	mockEncryption := &MockEncryptionService{}
	
	manager := &ClaudeSessionManager{
		apiClient:    mockClient,
		encryption:   mockEncryption,
		sessions:     make(map[string]*ClaudeSession),
		userSessions: make(map[string][]string),
		mutex:        sync.RWMutex{},
		userMutex:    sync.RWMutex{},
	}
	
	ctx := context.Background()
	validToken := createValidClaudeToken()
	
	// Mock expectations
	expectedResponse := &TokenValidationResponse{
		Valid:        true,
		Organization: "personal",
		RateLimit:    1000,
	}
	mockClient.On("ValidateToken", ctx, validToken).Return(expectedResponse, nil)
	
	// Execute
	response, err := manager.ValidateClaudeToken(ctx, validToken)
	
	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.True(t, response.Valid)
	assert.Equal(t, "personal", response.Organization)
	assert.Equal(t, 1000, response.RateLimit)
	
	mockClient.AssertExpectations(t)
}

// Test: Happy Path - Start Claude Code process successfully
func TestClaudeCodeProcessSpawn(t *testing.T) {
	// Setup
	mockProcessManager := &MockProcessManager{}
	mockWorkspaceManager := &MockWorkspaceManager{}
	mockEncryption := &MockEncryptionService{}
	
	manager := &ClaudeSessionManager{
		processManager:   mockProcessManager,
		workspaceManager: mockWorkspaceManager,
		encryption:       mockEncryption,
		sessions:         make(map[string]*ClaudeSession),
		userSessions:     make(map[string][]string),
		mutex:            sync.RWMutex{},
		userMutex:        sync.RWMutex{},
	}
	
	ctx := context.Background()
	userID := "user123"
	claudeToken := createValidClaudeToken()
	encryptedToken := "encrypted_token_data"
	workspacePath := "/tmp/workspace_test"
	
	// Mock expectations
	workspaceInfo := &WorkspaceInfo{
		Path:      workspacePath,
		UserID:    userID,
		CreatedAt: time.Now(),
	}
	mockWorkspaceManager.On("CreateWorkspace", ctx, userID).Return(workspaceInfo, nil)
	mockEncryption.On("Encrypt", claudeToken).Return(encryptedToken, nil)
	
	processInfo := &ProcessInfo{
		ProcessID:     12345,
		WorkspacePath: workspacePath,
		StartTime:     time.Now(),
		StdinPipe:     &mockWriteCloser{closed: false},
		StdoutPipe:    &mockReadCloser{data: []byte("Claude Code started"), closed: false},
	}
	mockProcessManager.On("StartProcess", ctx, mock.AnythingOfType("ProcessConfig")).Return(processInfo, nil)
	
	// Execute
	session, err := manager.CreateSession(ctx, userID, claudeToken)
	
	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, userID, session.UserID)
	assert.Equal(t, workspacePath, session.WorkspacePath)
	assert.Equal(t, 12345, session.ProcessID)
	assert.Equal(t, SessionStatusActive, session.Status)
	assert.Equal(t, encryptedToken, session.EncryptedToken)
	
	mockProcessManager.AssertExpectations(t)
	mockWorkspaceManager.AssertExpectations(t)
	mockEncryption.AssertExpectations(t)
}

// Test: Edge Case - Handle invalid API tokens
func TestClaudeTokenValidationWithInvalidToken(t *testing.T) {
	// Setup
	mockClient := &MockClaudeAPIClient{}
	
	manager := &ClaudeSessionManager{
		apiClient:    mockClient,
		sessions:     make(map[string]*ClaudeSession),
		userSessions: make(map[string][]string),
		mutex:        sync.RWMutex{},
		userMutex:    sync.RWMutex{},
	}
	
	ctx := context.Background()
	invalidToken := createInvalidClaudeToken()
	
	// Mock expectations - API returns invalid token response
	expectedResponse := &TokenValidationResponse{
		Valid: false,
	}
	mockClient.On("ValidateToken", ctx, invalidToken).Return(expectedResponse, nil)
	
	// Execute
	response, err := manager.ValidateClaudeToken(ctx, invalidToken)
	
	// Assert
	assert.NoError(t, err) // No HTTP error, but token is invalid
	assert.NotNil(t, response)
	assert.False(t, response.Valid)
	
	mockClient.AssertExpectations(t)
}

// Test: Edge Case - Handle Anthropic API unavailability
func TestClaudeTokenValidationWhenAPIDown(t *testing.T) {
	// Setup
	mockClient := &MockClaudeAPIClient{}
	
	manager := &ClaudeSessionManager{
		apiClient:    mockClient,
		sessions:     make(map[string]*ClaudeSession),
		userSessions: make(map[string][]string),
		mutex:        sync.RWMutex{},
		userMutex:    sync.RWMutex{},
	}
	
	ctx := context.Background()
	validToken := createValidClaudeToken()
	
	// Mock expectations - API is down
	apiError := errors.New("connection refused: anthropic API unavailable")
	mockClient.On("ValidateToken", ctx, validToken).Return(nil, apiError)
	
	// Execute
	response, err := manager.ValidateClaudeToken(ctx, validToken)
	
	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Contains(t, err.Error(), "anthropic API unavailable")
	
	mockClient.AssertExpectations(t)
}

// Test: Edge Case - Handle binary missing/permissions
func TestClaudeCodeProcessSpawnFailure(t *testing.T) {
	// Setup
	mockProcessManager := &MockProcessManager{}
	mockWorkspaceManager := &MockWorkspaceManager{}
	mockEncryption := &MockEncryptionService{}
	
	manager := &ClaudeSessionManager{
		processManager:   mockProcessManager,
		workspaceManager: mockWorkspaceManager,
		encryption:       mockEncryption,
		sessions:         make(map[string]*ClaudeSession),
		userSessions:     make(map[string][]string),
		mutex:            sync.RWMutex{},
		userMutex:        sync.RWMutex{},
	}
	
	ctx := context.Background()
	userID := "user123"
	claudeToken := createValidClaudeToken()
	encryptedToken := "encrypted_token_data"
	workspacePath := "/tmp/workspace_test"
	
	// Mock expectations
	workspaceInfo := &WorkspaceInfo{
		Path:      workspacePath,
		UserID:    userID,
		CreatedAt: time.Now(),
	}
	mockWorkspaceManager.On("CreateWorkspace", ctx, userID).Return(workspaceInfo, nil)
	mockEncryption.On("Encrypt", claudeToken).Return(encryptedToken, nil)
	
	// Process start fails due to missing binary or permissions
	processError := &exec.Error{
		Name: "claude-code",
		Err:  errors.New("executable file not found in $PATH"),
	}
	mockProcessManager.On("StartProcess", ctx, mock.AnythingOfType("ProcessConfig")).Return(nil, processError)
	
	// Cleanup should be called
	mockWorkspaceManager.On("DeleteWorkspace", ctx, workspacePath).Return(nil)
	
	// Execute
	session, err := manager.CreateSession(ctx, userID, claudeToken)
	
	// Assert
	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "executable file not found")
	
	mockProcessManager.AssertExpectations(t)
	mockWorkspaceManager.AssertExpectations(t)
	mockEncryption.AssertExpectations(t)
}

// Test: Edge Case - Handle process crashes mid-session
func TestClaudeCodeProcessCrashHandling(t *testing.T) {
	// Setup
	mockProcessManager := &MockProcessManager{}
	
	manager := &ClaudeSessionManager{
		processManager: mockProcessManager,
		sessions:       make(map[string]*ClaudeSession),
		userSessions:   make(map[string][]string),
		mutex:          sync.RWMutex{},
		userMutex:      sync.RWMutex{},
	}
	
	// Create a session with running process
	session := createTestSession("user123")
	manager.sessions[session.ID.Hex()] = session
	
	// Mock expectations - process is no longer running
	mockProcessManager.On("IsProcessRunning", session.ProcessID).Return(false)
	
	// Execute
	isRunning := manager.IsSessionActive(session.ID.Hex())
	
	// Assert
	assert.False(t, isRunning)
	
	// Verify session status is updated
	updatedSession := manager.GetSession(session.ID.Hex())
	assert.Equal(t, SessionStatusCrashed, updatedSession.Status)
	
	mockProcessManager.AssertExpectations(t)
}

// Test: Edge Case - Handle memory/CPU limits
func TestClaudeCodeProcessResourceExhaustion(t *testing.T) {
	// Setup
	mockProcessManager := &MockProcessManager{}
	
	manager := &ClaudeSessionManager{
		processManager: mockProcessManager,
		sessions:       make(map[string]*ClaudeSession),
		userSessions:   make(map[string][]string),
		mutex:          sync.RWMutex{},
		userMutex:      sync.RWMutex{},
	}
	
	// Create a session with running process
	session := createTestSession("user123")
	manager.sessions[session.ID.Hex()] = session
	
	// Mock expectations - process exceeds resource limits
	metrics := &ProcessMetrics{
		MemoryUsageMB: 1024, // Exceeds limit of 512MB
		CPUUsage:      150,  // Exceeds limit of 100%
		DiskUsageMB:   200,
		Uptime:        time.Hour,
	}
	mockProcessManager.On("GetProcessMetrics", session.ProcessID).Return(metrics, nil)
	mockProcessManager.On("StopProcess", session.ProcessID).Return(nil)
	
	// Execute
	err := manager.CheckResourceUsage(session.ID.Hex())
	
	// Assert
	assert.NoError(t, err)
	
	// Verify session was terminated due to resource exhaustion
	updatedSession := manager.GetSession(session.ID.Hex())
	assert.Equal(t, SessionStatusTerminated, updatedSession.Status)
	
	mockProcessManager.AssertExpectations(t)
}

// Test: Edge Case - Handle filesystem errors during workspace creation
func TestWorkspaceCreationWithInsufficientPermissions(t *testing.T) {
	// Setup
	mockWorkspaceManager := &MockWorkspaceManager{}
	mockEncryption := &MockEncryptionService{}
	
	manager := &ClaudeSessionManager{
		workspaceManager: mockWorkspaceManager,
		encryption:       mockEncryption,
		sessions:         make(map[string]*ClaudeSession),
		userSessions:     make(map[string][]string),
		mutex:            sync.RWMutex{},
		userMutex:        sync.RWMutex{},
	}
	
	ctx := context.Background()
	userID := "user123"
	claudeToken := createValidClaudeToken()
	encryptedToken := "encrypted_token_data"
	
	// Mock expectations
	mockEncryption.On("Encrypt", claudeToken).Return(encryptedToken, nil)
	
	// Mock expectations - filesystem permission error
	permissionError := &os.PathError{
		Op:   "mkdir",
		Path: "/restricted/workspace",
		Err:  errors.New("permission denied"),
	}
	mockWorkspaceManager.On("CreateWorkspace", ctx, userID).Return(nil, permissionError)
	
	// Execute
	session, err := manager.CreateSession(ctx, userID, claudeToken)
	
	// Assert
	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "permission denied")
	
	mockWorkspaceManager.AssertExpectations(t)
	mockEncryption.AssertExpectations(t)
}

// Test: Edge Case - Handle out-of-space errors
func TestWorkspaceCreationWithDiskSpaceFull(t *testing.T) {
	// Setup
	mockWorkspaceManager := &MockWorkspaceManager{}
	mockEncryption := &MockEncryptionService{}
	
	manager := &ClaudeSessionManager{
		workspaceManager: mockWorkspaceManager,
		encryption:       mockEncryption,
		sessions:         make(map[string]*ClaudeSession),
		userSessions:     make(map[string][]string),
		mutex:            sync.RWMutex{},
		userMutex:        sync.RWMutex{},
	}
	
	ctx := context.Background()
	userID := "user123"
	claudeToken := createValidClaudeToken()
	encryptedToken := "encrypted_token_data"
	
	// Mock expectations
	mockEncryption.On("Encrypt", claudeToken).Return(encryptedToken, nil)
	
	// Mock expectations - disk space full error
	diskFullError := &os.PathError{
		Op:   "write",
		Path: "/workspace",
		Err:  errors.New("no space left on device"),
	}
	mockWorkspaceManager.On("CreateWorkspace", ctx, userID).Return(nil, diskFullError)
	
	// Execute
	session, err := manager.CreateSession(ctx, userID, claudeToken)
	
	// Assert
	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "no space left on device")
	
	mockWorkspaceManager.AssertExpectations(t)
	mockEncryption.AssertExpectations(t)
}

// Test: Edge Case - Handle session conflicts
func TestConcurrentProcessSpawnForSameUser(t *testing.T) {
	// Setup
	mockProcessManager := &MockProcessManager{}
	mockWorkspaceManager := &MockWorkspaceManager{}
	mockEncryption := &MockEncryptionService{}
	
	manager := &ClaudeSessionManager{
		processManager:   mockProcessManager,
		workspaceManager: mockWorkspaceManager,
		encryption:       mockEncryption,
		sessions:         make(map[string]*ClaudeSession),
		mutex:            sync.RWMutex{},
		userSessions:     make(map[string][]string),
		userMutex:        sync.RWMutex{},
	}
	
	ctx := context.Background()
	userID := "user123"
	claudeToken := createValidClaudeToken()
	
	// Create existing session for the same user
	existingSession := createTestSession(userID)
	manager.sessions[existingSession.ID.Hex()] = existingSession
	manager.userSessions[userID] = []string{existingSession.ID.Hex()}
	
	// Mock expectations - existing session is still running
	mockProcessManager.On("IsProcessRunning", existingSession.ProcessID).Return(true)
	
	// Execute - try to create another session for the same user
	session, err := manager.CreateSession(ctx, userID, claudeToken)
	
	// Assert - should return error due to existing active session
	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "active session already exists")
	
	mockProcessManager.AssertExpectations(t)
}

// Test: Edge Case - Handle encryption key failures
func TestClaudeTokenEncryptionKeyMissing(t *testing.T) {
	// Setup
	mockEncryption := &MockEncryptionService{}
	
	manager := &ClaudeSessionManager{
		encryption:   mockEncryption,
		sessions:     make(map[string]*ClaudeSession),
		userSessions: make(map[string][]string),
		mutex:        sync.RWMutex{},
		userMutex:    sync.RWMutex{},
	}
	
	ctx := context.Background()
	userID := "user123"
	claudeToken := createValidClaudeToken()
	
	// Mock expectations - encryption fails due to missing key
	encryptionError := errors.New("encryption key not found or invalid")
	mockEncryption.On("Encrypt", claudeToken).Return("", encryptionError)
	
	// Execute
	session, err := manager.CreateSession(ctx, userID, claudeToken)
	
	// Assert
	assert.Error(t, err)
	assert.Nil(t, session)
	assert.Contains(t, err.Error(), "encryption key not found")
	
	mockEncryption.AssertExpectations(t)
}

// Additional test for complete coverage - Session cleanup and termination
func TestSessionCleanupAndTermination(t *testing.T) {
	// Setup
	mockProcessManager := &MockProcessManager{}
	mockWorkspaceManager := &MockWorkspaceManager{}
	mockEncryption := &MockEncryptionService{}
	
	manager := &ClaudeSessionManager{
		processManager:   mockProcessManager,
		workspaceManager: mockWorkspaceManager,
		encryption:       mockEncryption,
		sessions:         make(map[string]*ClaudeSession),
		mutex:            sync.RWMutex{},
		userSessions:     make(map[string][]string),
		userMutex:        sync.RWMutex{},
	}
	
	ctx := context.Background()
	
	// Create test session
	session := createTestSession("user123")
	manager.sessions[session.ID.Hex()] = session
	manager.userSessions[session.UserID] = []string{session.ID.Hex()}
	
	// Mock expectations
	mockProcessManager.On("StopProcess", session.ProcessID).Return(nil)
	mockWorkspaceManager.On("DeleteWorkspace", ctx, session.WorkspacePath).Return(nil)
	
	// Execute
	err := manager.TerminateSession(ctx, session.ID.Hex())
	
	// Assert
	assert.NoError(t, err)
	
	// Verify session is removed from manager
	terminatedSession := manager.GetSession(session.ID.Hex())
	assert.Nil(t, terminatedSession)
	
	// Verify user sessions are cleaned up
	userSessions := manager.GetUserSessions(session.UserID)
	assert.Empty(t, userSessions)
	
	mockProcessManager.AssertExpectations(t)
	mockWorkspaceManager.AssertExpectations(t)
}

// Test inactive session cleanup (30-minute timeout)
func TestInactiveSessionCleanup(t *testing.T) {
	// Setup
	mockProcessManager := &MockProcessManager{}
	mockWorkspaceManager := &MockWorkspaceManager{}
	
	manager := &ClaudeSessionManager{
		processManager:   mockProcessManager,
		workspaceManager: mockWorkspaceManager,
		sessions:         make(map[string]*ClaudeSession),
		mutex:            sync.RWMutex{},
	}
	
	ctx := context.Background()
	
	// Create inactive session (older than 30 minutes)
	session := createTestSession("user123")
	session.LastActivity = time.Now().Add(-31 * time.Minute)
	manager.sessions[session.ID.Hex()] = session
	
	// Mock expectations
	mockProcessManager.On("StopProcess", session.ProcessID).Return(nil)
	mockWorkspaceManager.On("DeleteWorkspace", ctx, session.WorkspacePath).Return(nil)
	
	// Execute
	cleaned := manager.CleanupInactiveSessions(ctx)
	
	// Assert
	assert.Equal(t, 1, cleaned)
	
	// Verify session is removed
	assert.Nil(t, manager.GetSession(session.ID.Hex()))
	
	mockProcessManager.AssertExpectations(t)
	mockWorkspaceManager.AssertExpectations(t)
}

// Mock implementations for test helpers
type mockWriteCloser struct {
	closed bool
}

func (m *mockWriteCloser) Write(p []byte) (n int, err error) {
	if m.closed {
		return 0, errors.New("write on closed pipe")
	}
	return len(p), nil
}

func (m *mockWriteCloser) Close() error {
	m.closed = true
	return nil
}

type mockReadCloser struct {
	data   []byte
	pos    int
	closed bool
}

func (m *mockReadCloser) Read(p []byte) (n int, err error) {
	if m.closed {
		return 0, errors.New("read on closed pipe")
	}
	if m.pos >= len(m.data) {
		return 0, io.EOF
	}
	n = copy(p, m.data[m.pos:])
	m.pos += n
	return n, nil
}

func (m *mockReadCloser) Close() error {
	m.closed = true
	return nil
}

// Test AES-256 encryption implementation
func TestAES256Encryption(t *testing.T) {
	// Test the actual encryption service implementation from claude.go
	encryptionKey := createTestEncryptionKey()
	encryptionService, err := NewAESGCMEncryptionService(encryptionKey)
	require.NoError(t, err)
	
	testData := "sk-ant-api03-test-token-12345"
	
	// Test encryption
	encrypted, err := encryptionService.Encrypt(testData)
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)
	require.NotEqual(t, testData, encrypted)
	
	// Test decryption
	decrypted, err := encryptionService.Decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, testData, decrypted)
}

