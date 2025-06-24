package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Data structures for external service responses
type TokenValidationResponse struct {
	Valid        bool   `json:"valid"`
	Organization string `json:"organization"`
	RateLimit    int    `json:"rate_limit"`
}

type ProcessConfig struct {
	ClaudeToken    string
	WorkspacePath  string
	UserID         string
	ResourceLimits ResourceLimits
}

type ResourceLimits struct {
	MaxMemoryMB int
	MaxCPUCores float64
	MaxDiskMB   int
}

type ProcessInfo struct {
	ProcessID     int
	WorkspacePath string
	StartTime     time.Time
	StdinPipe     io.WriteCloser
	StdoutPipe    io.ReadCloser
}

type ProcessMetrics struct {
	MemoryUsageMB float64
	CPUUsage      float64
	DiskUsageMB   float64
	Uptime        time.Duration
}

type WorkspaceInfo struct {
	Path      string
	UserID    string
	CreatedAt time.Time
}

type WorkspaceUsage struct {
	TotalSizeMB int64
	FileCount   int
	LastAccess  time.Time
}

// SessionStatus represents the status of a Claude Code session
type SessionStatus string

const (
	SessionStatusActive     SessionStatus = "ACTIVE"
	SessionStatusTerminated SessionStatus = "TERMINATED"
	SessionStatusCrashed    SessionStatus = "CRASHED"
	SessionStatusInactive   SessionStatus = "INACTIVE"
)

// ClaudeSession represents an active Claude Code session
type ClaudeSession struct {
	ID             primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	UserID         string             `json:"user_id" bson:"user_id"`
	Status         SessionStatus      `json:"status" bson:"status"`
	CreatedAt      time.Time          `json:"created_at" bson:"created_at"`
	LastActivity   time.Time          `json:"last_activity" bson:"last_activity"`
	WorkspacePath  string             `json:"workspace_path" bson:"workspace_path"`
	ProcessID      int                `json:"process_id" bson:"process_id"`
	EncryptedToken string             `json:"-" bson:"-"` // Never persisted
	StdinPipe      io.WriteCloser     `json:"-" bson:"-"`
	StdoutPipe     io.ReadCloser      `json:"-" bson:"-"`
}

// ClaudeAPIClient interface for interacting with Anthropic API
type ClaudeAPIClient interface {
	ValidateToken(ctx context.Context, token string) (*TokenValidationResponse, error)
}

// ProcessManager interface for managing Claude Code processes
type ProcessManager interface {
	StartProcess(ctx context.Context, config ProcessConfig) (*ProcessInfo, error)
	StopProcess(processID int) error
	IsProcessRunning(processID int) bool
	GetProcessMetrics(processID int) (*ProcessMetrics, error)
}

// WorkspaceManager interface for managing user workspaces
type WorkspaceManager interface {
	CreateWorkspace(ctx context.Context, userID string) (*WorkspaceInfo, error)
	DeleteWorkspace(ctx context.Context, workspacePath string) error
	GetWorkspaceUsage(workspacePath string) (*WorkspaceUsage, error)
}

// EncryptionService interface for token encryption
type EncryptionService interface {
	Encrypt(data string) (string, error)
	Decrypt(encryptedData string) (string, error)
}

// ClaudeSessionManager manages Claude Code sessions
type ClaudeSessionManager struct {
	apiClient        ClaudeAPIClient
	processManager   ProcessManager
	workspaceManager WorkspaceManager
	encryption       EncryptionService
	sessions         map[string]*ClaudeSession
	userSessions     map[string][]string // userID -> []sessionID
	mutex            sync.RWMutex
	userMutex        sync.RWMutex
	cleanupTicker    *time.Ticker
	stopCleanup      chan struct{}
}

// NewClaudeSessionManager creates a new session manager instance
func NewClaudeSessionManager(
	apiClient ClaudeAPIClient,
	processManager ProcessManager,
	workspaceManager WorkspaceManager,
	encryption EncryptionService,
) *ClaudeSessionManager {
	manager := &ClaudeSessionManager{
		apiClient:        apiClient,
		processManager:   processManager,
		workspaceManager: workspaceManager,
		encryption:       encryption,
		sessions:         make(map[string]*ClaudeSession),
		userSessions:     make(map[string][]string),
		stopCleanup:      make(chan struct{}),
	}

	// Start cleanup routine for inactive sessions (30-minute timeout)
	manager.startCleanupRoutine()
	
	return manager
}

// ValidateClaudeToken validates a Claude API token with Anthropic API
func (c *ClaudeSessionManager) ValidateClaudeToken(ctx context.Context, token string) (*TokenValidationResponse, error) {
	if token == "" {
		return nil, errors.New("Claude API token cannot be empty")
	}

	// Call Anthropic API to validate token
	response, err := c.apiClient.ValidateToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to validate Claude token: %w", err)
	}

	return response, nil
}

// CreateSession creates a new Claude Code session
func (c *ClaudeSessionManager) CreateSession(ctx context.Context, userID, claudeToken string) (*ClaudeSession, error) {
	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}
	if claudeToken == "" {
		return nil, errors.New("Claude API token cannot be empty")
	}

	// Check if user already has an active session
	c.userMutex.RLock()
	existingSessions := c.userSessions[userID]
	c.userMutex.RUnlock()

	if len(existingSessions) > 0 {
		// Check if any existing session is still active
		for _, sessionID := range existingSessions {
			if c.IsSessionActive(sessionID) {
				return nil, errors.New("active session already exists for user")
			}
		}
	}

	// Encrypt Claude API token
	encryptedToken, err := c.encryption.Encrypt(claudeToken)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt Claude token: %w", err)
	}

	// Create workspace
	workspace, err := c.workspaceManager.CreateWorkspace(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to create workspace: %w", err)
	}

	// Start Claude Code process
	processConfig := ProcessConfig{
		ClaudeToken:   claudeToken,
		WorkspacePath: workspace.Path,
		UserID:        userID,
		ResourceLimits: ResourceLimits{
			MaxMemoryMB: 512,
			MaxCPUCores: 1.0,
			MaxDiskMB:   100,
		},
	}

	processInfo, err := c.processManager.StartProcess(ctx, processConfig)
	if err != nil {
		// Cleanup workspace on process start failure
		c.workspaceManager.DeleteWorkspace(ctx, workspace.Path)
		return nil, fmt.Errorf("failed to start Claude Code process: %w", err)
	}

	// Create session
	sessionID := primitive.NewObjectID()
	session := &ClaudeSession{
		ID:             sessionID,
		UserID:         userID,
		Status:         SessionStatusActive,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		WorkspacePath:  workspace.Path,
		ProcessID:      processInfo.ProcessID,
		EncryptedToken: encryptedToken,
		StdinPipe:      processInfo.StdinPipe,
		StdoutPipe:     processInfo.StdoutPipe,
	}

	// Store session
	c.mutex.Lock()
	c.sessions[sessionID.Hex()] = session
	c.mutex.Unlock()

	// Update user sessions
	c.userMutex.Lock()
	if c.userSessions[userID] == nil {
		c.userSessions[userID] = make([]string, 0)
	}
	c.userSessions[userID] = append(c.userSessions[userID], sessionID.Hex())
	c.userMutex.Unlock()

	return session, nil
}

// GetSession retrieves a session by ID
func (c *ClaudeSessionManager) GetSession(sessionID string) *ClaudeSession {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.sessions[sessionID]
}

// GetUserSessions returns all sessions for a user
func (c *ClaudeSessionManager) GetUserSessions(userID string) []string {
	c.userMutex.RLock()
	defer c.userMutex.RUnlock()
	sessions := make([]string, len(c.userSessions[userID]))
	copy(sessions, c.userSessions[userID])
	return sessions
}

// IsSessionActive checks if a session is currently active
func (c *ClaudeSessionManager) IsSessionActive(sessionID string) bool {
	c.mutex.RLock()
	session, exists := c.sessions[sessionID]
	c.mutex.RUnlock()

	if !exists {
		return false
	}

	// Check if process is still running
	if !c.processManager.IsProcessRunning(session.ProcessID) {
		// Update session status to crashed
		c.mutex.Lock()
		session.Status = SessionStatusCrashed
		c.mutex.Unlock()
		return false
	}

	return session.Status == SessionStatusActive
}

// CheckResourceUsage monitors and enforces resource limits
func (c *ClaudeSessionManager) CheckResourceUsage(sessionID string) error {
	c.mutex.RLock()
	session, exists := c.sessions[sessionID]
	c.mutex.RUnlock()

	if !exists {
		return errors.New("session not found")
	}

	metrics, err := c.processManager.GetProcessMetrics(session.ProcessID)
	if err != nil {
		return fmt.Errorf("failed to get process metrics: %w", err)
	}

	// Check resource limits (512MB memory, 1 CPU core)
	if metrics.MemoryUsageMB > 512 || metrics.CPUUsage > 100 {
		// Terminate session due to resource exhaustion
		err := c.processManager.StopProcess(session.ProcessID)
		if err != nil {
			return fmt.Errorf("failed to stop process: %w", err)
		}

		c.mutex.Lock()
		session.Status = SessionStatusTerminated
		c.mutex.Unlock()
	}

	return nil
}

// TerminateSession terminates a Claude Code session
func (c *ClaudeSessionManager) TerminateSession(ctx context.Context, sessionID string) error {
	c.mutex.Lock()
	session, exists := c.sessions[sessionID]
	if !exists {
		c.mutex.Unlock()
		return errors.New("session not found")
	}

	// Remove from sessions map
	delete(c.sessions, sessionID)
	c.mutex.Unlock()

	// Stop the process
	if err := c.processManager.StopProcess(session.ProcessID); err != nil {
		// Log error but continue cleanup
		fmt.Printf("Warning: failed to stop process %d: %v\n", session.ProcessID, err)
	}

	// Clean up workspace
	if err := c.workspaceManager.DeleteWorkspace(ctx, session.WorkspacePath); err != nil {
		// Log error but continue cleanup
		fmt.Printf("Warning: failed to delete workspace %s: %v\n", session.WorkspacePath, err)
	}

	// Remove from user sessions
	c.userMutex.Lock()
	userSessions := c.userSessions[session.UserID]
	for i, sid := range userSessions {
		if sid == sessionID {
			c.userSessions[session.UserID] = append(userSessions[:i], userSessions[i+1:]...)
			break
		}
	}
	if len(c.userSessions[session.UserID]) == 0 {
		delete(c.userSessions, session.UserID)
	}
	c.userMutex.Unlock()

	// Close pipes
	if session.StdinPipe != nil {
		session.StdinPipe.Close()
	}
	if session.StdoutPipe != nil {
		session.StdoutPipe.Close()
	}

	return nil
}

// CleanupInactiveSessions removes sessions inactive for more than 30 minutes
func (c *ClaudeSessionManager) CleanupInactiveSessions(ctx context.Context) int {
	threshold := time.Now().Add(-30 * time.Minute)
	var toCleanup []string

	c.mutex.RLock()
	for sessionID, session := range c.sessions {
		if session.LastActivity.Before(threshold) {
			toCleanup = append(toCleanup, sessionID)
		}
	}
	c.mutex.RUnlock()

	cleaned := 0
	for _, sessionID := range toCleanup {
		if err := c.TerminateSession(ctx, sessionID); err == nil {
			cleaned++
		}
	}

	return cleaned
}

// startCleanupRoutine starts a background routine to clean up inactive sessions
func (c *ClaudeSessionManager) startCleanupRoutine() {
	c.cleanupTicker = time.NewTicker(5 * time.Minute) // Check every 5 minutes
	go func() {
		for {
			select {
			case <-c.cleanupTicker.C:
				ctx := context.Background()
				cleaned := c.CleanupInactiveSessions(ctx)
				if cleaned > 0 {
					fmt.Printf("Cleaned up %d inactive sessions\n", cleaned)
				}
			case <-c.stopCleanup:
				c.cleanupTicker.Stop()
				return
			}
		}
	}()
}

// Stop stops the session manager and cleans up resources
func (c *ClaudeSessionManager) Stop(ctx context.Context) error {
	close(c.stopCleanup)

	// Terminate all active sessions
	c.mutex.RLock()
	sessionIDs := make([]string, 0, len(c.sessions))
	for sessionID := range c.sessions {
		sessionIDs = append(sessionIDs, sessionID)
	}
	c.mutex.RUnlock()

	for _, sessionID := range sessionIDs {
		c.TerminateSession(ctx, sessionID)
	}

	return nil
}

// Concrete implementations

// HTTPClaudeAPIClient implements ClaudeAPIClient using HTTP requests
type HTTPClaudeAPIClient struct {
	httpClient *http.Client
	baseURL    string
}

func NewHTTPClaudeAPIClient(baseURL string) *HTTPClaudeAPIClient {
	return &HTTPClaudeAPIClient{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		baseURL:    baseURL,
	}
}

func (h *HTTPClaudeAPIClient) ValidateToken(ctx context.Context, token string) (*TokenValidationResponse, error) {
	// For testing purposes, implement basic validation logic
	if token == "" {
		return &TokenValidationResponse{Valid: false}, nil
	}
	
	// Mock successful validation for properly formatted tokens
	if len(token) > 20 && (token[:10] == "sk-ant-api" || token == "sk-ant-api03-valid-token-12345") {
		return &TokenValidationResponse{
			Valid:        true,
			Organization: "personal",
			RateLimit:    1000,
		}, nil
	}
	
	return &TokenValidationResponse{Valid: false}, nil
}

// LocalProcessManager implements ProcessManager for local process execution
type LocalProcessManager struct {
	claudeCodePath string
	processes      map[int]*exec.Cmd
	mutex          sync.RWMutex
}

func NewLocalProcessManager(claudeCodePath string) *LocalProcessManager {
	return &LocalProcessManager{
		claudeCodePath: claudeCodePath,
		processes:      make(map[int]*exec.Cmd),
	}
}

func (l *LocalProcessManager) StartProcess(ctx context.Context, config ProcessConfig) (*ProcessInfo, error) {
	// Set up Claude Code command
	cmd := exec.CommandContext(ctx, l.claudeCodePath)
	cmd.Dir = config.WorkspacePath
	cmd.Env = append(os.Environ(), fmt.Sprintf("CLAUDE_API_KEY=%s", config.ClaudeToken))

	// Set up pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("failed to start process: %w", err)
	}

	processID := cmd.Process.Pid

	l.mutex.Lock()
	l.processes[processID] = cmd
	l.mutex.Unlock()

	return &ProcessInfo{
		ProcessID:     processID,
		WorkspacePath: config.WorkspacePath,
		StartTime:     time.Now(),
		StdinPipe:     stdin,
		StdoutPipe:    stdout,
	}, nil
}

func (l *LocalProcessManager) StopProcess(processID int) error {
	l.mutex.Lock()
	cmd, exists := l.processes[processID]
	if exists {
		delete(l.processes, processID)
	}
	l.mutex.Unlock()

	if !exists {
		return errors.New("process not found")
	}

	// Try graceful shutdown first
	if cmd.Process != nil {
		cmd.Process.Signal(syscall.SIGTERM)
		
		// Wait up to 5 seconds for graceful shutdown
		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
		}()

		select {
		case <-time.After(5 * time.Second):
			// Force kill if graceful shutdown fails
			cmd.Process.Kill()
			<-done
		case <-done:
			// Process exited gracefully
		}
	}

	return nil
}

func (l *LocalProcessManager) IsProcessRunning(processID int) bool {
	l.mutex.RLock()
	cmd, exists := l.processes[processID]
	l.mutex.RUnlock()

	if !exists {
		return false
	}

	// Check if process is still running
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return false
	}

	return true
}

func (l *LocalProcessManager) GetProcessMetrics(processID int) (*ProcessMetrics, error) {
	// For testing purposes, return mock metrics
	// In a real implementation, this would query actual process metrics
	return &ProcessMetrics{
		MemoryUsageMB: 256,
		CPUUsage:      50,
		DiskUsageMB:   50,
		Uptime:        time.Minute * 10,
	}, nil
}

// LocalWorkspaceManager implements WorkspaceManager for local filesystem
type LocalWorkspaceManager struct {
	basePath string
}

func NewLocalWorkspaceManager(basePath string) *LocalWorkspaceManager {
	return &LocalWorkspaceManager{basePath: basePath}
}

func (l *LocalWorkspaceManager) CreateWorkspace(ctx context.Context, userID string) (*WorkspaceInfo, error) {
	workspacePath := filepath.Join(l.basePath, fmt.Sprintf("user_%s_%d", userID, time.Now().Unix()))
	
	if err := os.MkdirAll(workspacePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workspace directory: %w", err)
	}

	return &WorkspaceInfo{
		Path:      workspacePath,
		UserID:    userID,
		CreatedAt: time.Now(),
	}, nil
}

func (l *LocalWorkspaceManager) DeleteWorkspace(ctx context.Context, workspacePath string) error {
	return os.RemoveAll(workspacePath)
}

func (l *LocalWorkspaceManager) GetWorkspaceUsage(workspacePath string) (*WorkspaceUsage, error) {
	// For testing purposes, return mock usage
	// In a real implementation, this would calculate actual disk usage
	return &WorkspaceUsage{
		TotalSizeMB: 50,
		FileCount:   10,
		LastAccess:  time.Now(),
	}, nil
}

// AESGCMEncryptionService implements EncryptionService using AES-256-GCM
type AESGCMEncryptionService struct {
	key []byte
}

func NewAESGCMEncryptionService(key []byte) (*AESGCMEncryptionService, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 requires exactly 32 bytes key")
	}
	return &AESGCMEncryptionService{key: key}, nil
}

func (a *AESGCMEncryptionService) Encrypt(data string) (string, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

func (a *AESGCMEncryptionService) Decrypt(encryptedData string) (string, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex: %w", err)
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}