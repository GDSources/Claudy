package websocket

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"claudy/internal/auth"
	"claudy/internal/files"
	"claudy/internal/session"
)

// Message represents the WebSocket message protocol
type Message struct {
	Type      string                 `json:"type"`
	Content   string                 `json:"content"`
	Timestamp string                 `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// JWTService interface for JWT token validation
type JWTService interface {
	ValidateToken(tokenString string) (*auth.UserClaims, error)
}

// RedisService interface for connection management
type RedisService interface {
	IncrementConnectionCount(userID string) (int, error)
	DecrementConnectionCount(userID string) (int, error)
	GetConnectionCount(userID string) (int, error)
	SetConnectionCount(userID string, count int) error
	IsAvailable() bool
}

// FileManager interface for file operations
type FileManagerInterface interface {
	UploadFile(ctx context.Context, workspacePath, filename, content, encoding string) (*files.UploadResult, error)
	ListFiles(ctx context.Context, workspacePath string) ([]files.FileInfo, error)
	CleanupWorkspace(ctx context.Context, workspacePath string) error
	GetWorkspaceSize(ctx context.Context, workspacePath string) (int64, error)
}

// SessionManager interface for session management
type SessionManagerInterface interface {
	GetSession(sessionID string) *session.ClaudeSession
	GetUserSessions(userID string) []string
}


// Config holds WebSocket handler configuration
type Config struct {
	MaxConnectionsPerUser int
	AllowedOrigins        []string
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	PingInterval          time.Duration
}

// Connection represents an active WebSocket connection
type Connection struct {
	conn          *websocket.Conn
	userID        string
	authenticated bool
	send          chan Message
	handler       *Handler
	mutex         sync.RWMutex
}

// Handler manages WebSocket connections
type Handler struct {
	jwtService     JWTService
	redisService   RedisService
	fileManager    FileManagerInterface
	sessionManager SessionManagerInterface
	config         Config
	connections    map[string][]*Connection
	upgrader       websocket.Upgrader
	mutex          sync.RWMutex
	shutdown       chan struct{}
	shutdownOnce   sync.Once
}

// NewHandler creates a new WebSocket handler
func NewHandler(jwtService JWTService, redisService RedisService, fileManager FileManagerInterface, sessionManager SessionManagerInterface, config Config) *Handler {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return false
			}
			
			for _, allowedOrigin := range config.AllowedOrigins {
				if origin == allowedOrigin {
					return true
				}
			}
			return false
		},
	}

	return &Handler{
		jwtService:     jwtService,
		redisService:   redisService,
		fileManager:    fileManager,
		sessionManager: sessionManager,
		config:         config,
		connections:    make(map[string][]*Connection),
		upgrader:       upgrader,
		shutdown:       make(chan struct{}),
	}
}

// HandleWebSocket handles WebSocket connection requests
func (h *Handler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP connection to WebSocket
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	// Create connection wrapper
	wsConn := &Connection{
		conn:          conn,
		authenticated: false,
		send:          make(chan Message, 256),
		handler:       h,
	}

	// Set connection timeouts
	conn.SetReadDeadline(time.Now().Add(h.config.ReadTimeout))
	conn.SetWriteDeadline(time.Now().Add(h.config.WriteTimeout))

	// Start connection handlers
	go wsConn.readPump()
	go wsConn.writePump()
}

// readPump handles incoming messages from the WebSocket connection
func (c *Connection) readPump() {
	defer func() {
		c.cleanup()
		c.conn.Close()
	}()

	// Set read deadline and pong handler
	c.conn.SetReadDeadline(time.Now().Add(c.handler.config.ReadTimeout))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(c.handler.config.ReadTimeout))
		return nil
	})

	for {
		select {
		case <-c.handler.shutdown:
			return
		default:
			var msg Message
			err := c.conn.ReadJSON(&msg)
			if err != nil {
				// Check if it's a JSON parse error
				if strings.Contains(err.Error(), "invalid character") || strings.Contains(err.Error(), "unexpected end") {
					c.sendError("invalid message format: malformed JSON")
					continue
				}
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("WebSocket error: %v", err)
				}
				return
			}

			c.handleMessage(msg)
		}
	}
}

// writePump handles outgoing messages to the WebSocket connection
func (c *Connection) writePump() {
	ticker := time.NewTicker(c.handler.config.PingInterval)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case <-c.handler.shutdown:
			return
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(c.handler.config.WriteTimeout))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteJSON(message); err != nil {
				log.Printf("WebSocket write error: %v", err)
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(c.handler.config.WriteTimeout))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleMessage processes incoming WebSocket messages
func (c *Connection) handleMessage(msg Message) {
	// Validate message format
	if msg.Type == "" {
		c.sendError("invalid message format: missing type")
		return
	}

	// Handle authentication first
	if !c.authenticated {
		if msg.Type != "auth" {
			c.sendError("authentication required: please send auth message first")
			return
		}
		c.handleAuthentication(msg)
		return
	}

	// Handle authenticated messages
	switch msg.Type {
	case "chat_message":
		c.handleChatMessage(msg)
	case "file_upload":
		c.handleFileUpload(msg)
	case "file_list":
		c.handleFileList(msg)
	case "workspace_info":
		c.handleWorkspaceInfo(msg)
	default:
		c.sendError("unknown message type: " + msg.Type)
	}
}

// handleAuthentication processes authentication messages
func (c *Connection) handleAuthentication(msg Message) {
	if msg.Content == "" {
		c.sendError("authentication failed: missing token")
		return
	}

	// Validate JWT token
	claims, err := c.handler.jwtService.ValidateToken(msg.Content)
	if err != nil {
		c.sendError("authentication failed: invalid token")
		return
	}

	// Check Redis service availability
	if !c.handler.redisService.IsAvailable() {
		c.sendError("service temporarily unavailable: please try again later")
		return
	}

	// Check connection limits
	count, err := c.handler.redisService.IncrementConnectionCount(claims.UserID)
	if err != nil {
		c.sendError("service temporarily unavailable: please try again later")
		return
	}

	if count > c.handler.config.MaxConnectionsPerUser {
		// Decrement back since we exceeded the limit
		c.handler.redisService.DecrementConnectionCount(claims.UserID)
		c.sendError("connection limit exceeded: maximum 3 connections per user")
		return
	}

	// Authentication successful - set userID and authenticated flag together
	c.mutex.Lock()
	c.userID = claims.UserID
	c.authenticated = true
	c.mutex.Unlock()

	// Add to handler's connection tracking
	c.handler.addConnection(claims.UserID, c)

	// Send success response
	c.sendMessage(Message{
		Type:      "auth_success",
		Content:   "successfully authenticated",
		Timestamp: time.Now().Format(time.RFC3339),
		Data: map[string]interface{}{
			"user_id":  claims.UserID,
			"username": claims.Username,
		},
	})

	log.Printf("WebSocket: User %s authenticated successfully", claims.UserID)
}

// handleChatMessage processes chat messages
func (c *Connection) handleChatMessage(msg Message) {
	// Echo the message back for now (placeholder implementation)
	response := Message{
		Type:      "claude_response",
		Content:   "Echo: " + msg.Content,
		Timestamp: time.Now().Format(time.RFC3339),
		Data:      map[string]interface{}{},
	}
	c.sendMessage(response)
}

// handleFileUpload processes file upload messages
func (c *Connection) handleFileUpload(msg Message) {
	c.mutex.RLock()
	userID := c.userID
	c.mutex.RUnlock()

	// Parse file upload data
	var fileData files.FileUploadMessage
	if dataBytes, err := json.Marshal(msg.Data); err != nil {
		c.sendError("invalid file upload data format")
		return
	} else if err := json.Unmarshal(dataBytes, &fileData); err != nil {
		c.sendError("failed to parse file upload data")
		return
	}

	// Get user's active session to find workspace
	sessionIDs := c.handler.sessionManager.GetUserSessions(userID)
	if len(sessionIDs) == 0 {
		c.sendError("no active session found - please start a Claude Code session first")
		return
	}

	// Use the first active session (in a real implementation, you might want to specify which session)
	session := c.handler.sessionManager.GetSession(sessionIDs[0])
	if session == nil {
		c.sendError("session not found")
		return
	}

	// Upload file to workspace
	ctx := context.Background()
	result, err := c.handler.fileManager.UploadFile(ctx, session.WorkspacePath, fileData.Filename, fileData.Content, fileData.Encoding)
	if err != nil {
		c.sendError("file upload failed: " + err.Error())
		return
	}

	// Send success response
	response := Message{
		Type:      "file_uploaded",
		Content:   "file uploaded successfully",
		Timestamp: time.Now().Format(time.RFC3339),
		Data: map[string]interface{}{
			"filename": result.Filename,
			"size":     result.Size,
			"path":     result.Path,
		},
	}
	c.sendMessage(response)

	log.Printf("File uploaded: %s (%d bytes) to workspace %s", result.Filename, result.Size, session.WorkspacePath)
}

// handleFileList processes file listing requests
func (c *Connection) handleFileList(msg Message) {
	c.mutex.RLock()
	userID := c.userID
	c.mutex.RUnlock()

	// Get user's active session to find workspace
	sessionIDs := c.handler.sessionManager.GetUserSessions(userID)
	if len(sessionIDs) == 0 {
		c.sendError("no active session found")
		return
	}

	session := c.handler.sessionManager.GetSession(sessionIDs[0])
	if session == nil {
		c.sendError("session not found")
		return
	}

	// List files in workspace
	ctx := context.Background()
	fileList, err := c.handler.fileManager.ListFiles(ctx, session.WorkspacePath)
	if err != nil {
		c.sendError("failed to list files: " + err.Error())
		return
	}

	// Send file list response
	response := Message{
		Type:      "file_list",
		Content:   "file list retrieved successfully",
		Timestamp: time.Now().Format(time.RFC3339),
		Data: map[string]interface{}{
			"files":          fileList,
			"workspace_path": session.WorkspacePath,
		},
	}
	c.sendMessage(response)
}

// handleWorkspaceInfo processes workspace information requests
func (c *Connection) handleWorkspaceInfo(msg Message) {
	c.mutex.RLock()
	userID := c.userID
	c.mutex.RUnlock()

	// Get user's active session to find workspace
	sessionIDs := c.handler.sessionManager.GetUserSessions(userID)
	if len(sessionIDs) == 0 {
		c.sendError("no active session found")
		return
	}

	session := c.handler.sessionManager.GetSession(sessionIDs[0])
	if session == nil {
		c.sendError("session not found")
		return
	}

	// Get workspace size
	ctx := context.Background()
	workspaceSize, err := c.handler.fileManager.GetWorkspaceSize(ctx, session.WorkspacePath)
	if err != nil {
		c.sendError("failed to get workspace info: " + err.Error())
		return
	}

	// Send workspace info response
	response := Message{
		Type:      "workspace_info",
		Content:   "workspace info retrieved successfully",
		Timestamp: time.Now().Format(time.RFC3339),
		Data: map[string]interface{}{
			"workspace_path": session.WorkspacePath,
			"size_bytes":     workspaceSize,
			"size_mb":        float64(workspaceSize) / (1024 * 1024),
			"max_size_mb":    float64(files.MaxWorkspaceSize) / (1024 * 1024),
		},
	}
	c.sendMessage(response)
}

// sendMessage sends a message to the WebSocket connection
func (c *Connection) sendMessage(msg Message) {
	select {
	case c.send <- msg:
	default:
		// Channel is full, close connection
		c.cleanup()
	}
}

// sendError sends an error message to the WebSocket connection
func (c *Connection) sendError(errorMsg string) {
	msg := Message{
		Type:      "error",
		Content:   errorMsg,
		Timestamp: time.Now().Format(time.RFC3339),
		Data:      map[string]interface{}{},
	}
	c.sendMessage(msg)
	log.Printf("WebSocket error sent: %s", errorMsg)
}

// cleanup handles connection cleanup
func (c *Connection) cleanup() {
	c.mutex.RLock()
	userID := c.userID
	authenticated := c.authenticated
	c.mutex.RUnlock()

	if authenticated && userID != "" {
		// Decrement connection count in Redis
		if _, err := c.handler.redisService.DecrementConnectionCount(userID); err != nil {
			log.Printf("Failed to decrement connection count for user %s: %v", userID, err)
		}

		// Remove from handler's connection tracking
		c.handler.removeConnection(userID, c)
	}

	// Close send channel
	close(c.send)
}

// addConnection adds a connection to the handler's tracking
func (h *Handler) addConnection(userID string, conn *Connection) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	
	if h.connections[userID] == nil {
		h.connections[userID] = make([]*Connection, 0)
	}
	h.connections[userID] = append(h.connections[userID], conn)
}

// removeConnection removes a connection from the handler's tracking
func (h *Handler) removeConnection(userID string, conn *Connection) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	
	connections := h.connections[userID]
	for i, c := range connections {
		if c == conn {
			// Remove connection from slice
			h.connections[userID] = append(connections[:i], connections[i+1:]...)
			break
		}
	}
	
	// Clean up empty slice
	if len(h.connections[userID]) == 0 {
		delete(h.connections, userID)
	}
}

// Shutdown gracefully shuts down the WebSocket handler
func (h *Handler) Shutdown() {
	h.shutdownOnce.Do(func() {
		close(h.shutdown)
		
		// Close all active connections
		h.mutex.Lock()
		for userID, connections := range h.connections {
			for _, conn := range connections {
				conn.conn.Close()
			}
			delete(h.connections, userID)
		}
		h.mutex.Unlock()
		
		log.Println("WebSocket handler shut down gracefully")
	})
}

// UpdateRedisService updates the Redis service reference (useful for testing scenarios)
func (h *Handler) UpdateRedisService(redisService RedisService) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.redisService = redisService
}