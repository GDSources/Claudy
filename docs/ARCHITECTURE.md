# System Architecture Documentation

This document describes the technical architecture of the Claudy backend service - a secure, scalable Go-based system that enables remote access to Claude Code sessions through WebSocket interfaces with comprehensive authentication and session management.

## System Overview

Claudy is a production-ready backend service that provides:
- **Remote Claude Code Access**: WebSocket-based interface to Claude Code sessions
- **Secure Authentication**: GitHub OAuth2 + JWT token management
- **Session Management**: Isolated Claude Code processes with workspace management
- **File Management**: Secure file upload/download with validation
- **Real-time Communication**: WebSocket connections with Redis state management

## High-Level Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   Web Client    │    │   Load Balancer  │    │   Claudy Backend    │
│                 │────│                  │────│                     │
│ - Browser UI    │    │ - TLS Term       │    │ - JWT Auth          │
│ - WebSocket     │    │ - Rate Limiting  │    │ - WebSocket Handler │
│ - File Upload   │    │ - Health Checks  │    │ - Session Manager   │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
                                                         │
                       ┌─────────────────────────────────┼─────────────────────────────────┐
                       │                                 │                                 │
             ┌─────────▼──────────┐              ┌─────▼─────────┐              ┌─────▼──────────┐
             │     MongoDB        │              │     Redis     │              │ Claude Code    │
             │                    │              │               │              │   Processes    │
             │ - User Profiles    │              │ - Session     │              │                │
             │ - Session History  │              │   State       │              │ - Isolated     │
             │ - Persistent Data  │              │ - WebSocket   │              │   Workspaces   │
             │                    │              │   Connections │              │ - User API     │
             │                    │              │ - Cache       │              │   Tokens       │
             └────────────────────┘              └───────────────┘              └────────────────┘
```

## Component Architecture

### 1. Authentication Service (`internal/auth/`)

**Purpose**: Secure user authentication and JWT token management

**Components:**
- **JWT Service** (`jwt.go`): RS256 token generation, validation, and refresh
- **User Claims**: Structured user information in JWT tokens
- **Key Management**: RSA key pair handling for token signing

**Key Features:**
- RS256 signing algorithm (security requirement)
- Configurable token expiration (15 minutes access, 7 days refresh)
- Concurrent token generation safety
- Comprehensive validation and error handling

**Integration Points:**
- WebSocket authentication
- HTTP middleware for protected endpoints
- User repository for profile data

### 2. User Management (`internal/models/`)

**Purpose**: User profile management and GitHub integration

**Components:**
- **User Model** (`user.go`): Complete user data structure
- **Repository Interface**: Abstract data access layer
- **GitHub Integration**: OAuth2 profile data handling

**Data Model:**
```go
type User struct {
    ID          primitive.ObjectID         `bson:"_id,omitempty"`
    GitHubID    int64                     `bson:"github_id"`
    Username    string                    `bson:"username"`
    Email       string                    `bson:"email"`
    AvatarURL   string                    `bson:"avatar_url"`
    CreatedAt   time.Time                 `bson:"created_at"`
    LastLogin   time.Time                 `bson:"last_login"`
    IsActive    bool                      `bson:"is_active"`
    Preferences map[string]interface{}    `bson:"preferences"`
    Metadata    map[string]interface{}    `bson:"metadata"`
}
```

**Integration Points:**
- MongoDB repository implementation
- JWT token generation
- Session association

### 3. WebSocket Gateway (`internal/websocket/`)

**Purpose**: Real-time communication and connection management

**Components:**
- **Connection Handler** (`handler.go`): WebSocket lifecycle management
- **Message Router**: Protocol-aware message handling
- **Authentication Middleware**: JWT validation for WebSocket connections
- **Connection Pool**: Concurrent connection management

**Message Protocol:**
```json
{
  "type": "auth|chat_message|file_upload|claude_response|session_status|error",
  "content": "message content",
  "timestamp": "2025-06-23T10:30:00Z",
  "data": {}
}
```

**Key Features:**
- JWT authentication during handshake
- Connection limits per user (max 3)
- Origin validation for CORS security
- Redis state management
- Graceful connection cleanup
- Message queuing for disconnected users

**Integration Points:**
- Redis service for connection state
- JWT service for authentication
- File manager for upload handling
- Claude session manager for process communication

### 4. Claude Code Session Manager (`internal/session/`)

**Purpose**: Claude Code process lifecycle and token management

**Components:**
- **Session Manager** (`claude.go`): Process orchestration and lifecycle
- **Token Encryption**: AES-256-GCM for Claude API tokens
- **Workspace Manager**: Isolated user workspace creation
- **Process Monitor**: Health checking and resource management

**Key Features:**
- Secure AES-256-GCM token encryption (memory-only)
- Process isolation with resource limits (512MB RAM, 1 CPU core)
- Automatic session cleanup (30-minute timeout)
- Workspace isolation and cleanup
- Claude API token validation with Anthropic API
- Bidirectional process communication via stdin/stdout

**Security Implementation:**
```go
type ClaudeSessionManager struct {
    encryptionService EncryptionService
    processManager    ProcessManager
    workspaceManager  WorkspaceManager
    apiClient         ClaudeAPIClient
    sessions          map[string]*Session
    mutex             sync.RWMutex
}
```

**Integration Points:**
- Anthropic API for token validation
- File system for workspace management
- WebSocket for real-time communication
- MongoDB for session persistence

### 5. File Management (`internal/files/`)

**Purpose**: Secure file upload and workspace management

**Components:**
- **File Manager** (`manager.go`): File operations and validation
- **Security Scanner**: Malicious content detection
- **Workspace Service**: Directory management and cleanup
- **Upload Handler**: WebSocket file upload protocol

**Security Features:**
- File size validation (10MB per file, 100MB per workspace)
- Malicious content detection (scripts, executables, suspicious patterns)
- UTF-8 encoding validation
- Path traversal prevention
- Binary file rejection

**File Operations:**
```go
type FileManager struct {
    workspaceBasePath string
    maxFileSize       int64
    maxWorkspaceSize  int64
    mutex             sync.RWMutex
}
```

**Integration Points:**
- WebSocket for file upload protocol
- Workspace manager for directory operations
- Claude Code sessions for file access

### 6. Database Integration

#### MongoDB Repository (`internal/repository/`)
**Purpose**: Persistent data storage and user management

**Collections:**
- **Users**: Profile data, preferences, metadata
- **Sessions**: Session history, metadata, file information
- **Message History**: Optional message persistence

**Features:**
- Proper indexing for performance
- Connection pooling and health checks
- Error handling and retry logic
- CRUD operations with validation

#### Redis Service (`internal/redis/`)
**Purpose**: Session state and connection management

**Data Structures:**
- **WebSocket Connections**: Active connection tracking
- **Session State**: Real-time session information
- **Message Queues**: Temporary message storage
- **Cache**: Frequently accessed data

**Features:**
- Connection failover and retry
- Pub/sub for real-time notifications
- TTL for automatic cleanup
- Performance monitoring

## Security Architecture

### Authentication Flow
```
1. GitHub OAuth2 → Authorization Code
2. Backend Exchange → GitHub Access Token
3. Profile Retrieval → User Information
4. JWT Generation → Access + Refresh Tokens
5. WebSocket Auth → Token Validation
6. Session Creation → Encrypted Claude Token
```

### Security Layers

#### 1. Network Security
- TLS 1.3 for all communications
- CORS validation for WebSocket origins
- Rate limiting (100 requests/minute per IP)
- Load balancer with DDoS protection

#### 2. Application Security
- JWT tokens with RS256 signing
- Token expiration and refresh mechanisms
- Input validation and sanitization
- SQL injection prevention (NoSQL databases)

#### 3. Process Security
- Isolated Claude Code processes
- Resource limits enforcement
- User privilege separation
- Workspace directory isolation

#### 4. Data Security
- AES-256-GCM encryption for Claude API tokens
- No sensitive data logging
- Automatic token cleanup
- Encrypted data at rest

## Performance Architecture

### Concurrency Model
```go
// WebSocket connections handled concurrently
go func() {
    for {
        select {
        case msg := <-connectionChannel:
            go handleMessage(msg)
        case <-ctx.Done():
            return
        }
    }
}()

// Claude Code processes managed with goroutines
go monitorProcess(session)
go handleProcessOutput(session)
```

### Resource Management
- **Memory Limits**: 512MB per Claude Code session
- **CPU Limits**: 1 core per Claude Code process
- **Connection Limits**: 3 WebSocket connections per user
- **File Limits**: 10MB per file, 100MB per workspace

### Performance Metrics
- **WebSocket Message Delivery**: <200ms (95th percentile)
- **Authentication Response**: <500ms (95th percentile)
- **Claude Code Process Startup**: <5 seconds
- **File Upload Processing**: <1 second for files <1MB
- **Concurrent Sessions**: 100+ per VM

## Deployment Architecture

### Container Strategy
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o claudy-backend ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates curl
WORKDIR /root/
COPY --from=builder /app/claudy-backend .
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1
EXPOSE 8080
CMD ["./claudy-backend"]
```

### Infrastructure Components
- **Load Balancer**: HAProxy or nginx for traffic distribution
- **Application Servers**: Multiple Claudy backend instances
- **Database Cluster**: MongoDB replica set with automatic failover
- **Cache Cluster**: Redis cluster with persistence
- **Monitoring**: Prometheus + Grafana for metrics and alerting

## Technology Stack

### Backend Framework
- **Language**: Go 1.21+ (performance and concurrency)
- **Web Framework**: Gin HTTP framework
- **WebSocket**: Gorilla WebSocket library
- **Authentication**: golang-jwt for JWT handling
- **HTTP Client**: Native net/http for external APIs

### Database & Storage
- **Primary Database**: MongoDB 7.0 (user data, session history)
- **Session Store**: Redis 7.0 (connection state, real-time data)
- **File Storage**: Local filesystem with proper permissions
- **Caching**: In-memory caching with sync.Map

### Security & Encryption
- **JWT Signing**: RS256 with RSA key pairs
- **Token Encryption**: AES-256-GCM for Claude API tokens
- **TLS**: TLS 1.3 for all external communications
- **Hashing**: bcrypt for password hashing (if applicable)

### Development & Testing
- **Testing**: testify for assertions and mocking
- **Integration**: testcontainers-go for real database testing
- **Benchmarking**: Go built-in benchmark tools
- **Linting**: golangci-lint for code quality
- **Documentation**: Built-in Go documentation tools

## Scalability Considerations

### Horizontal Scaling
- **Stateless Design**: All state in Redis/MongoDB
- **Load Balancing**: Multiple backend instances
- **Database Sharding**: User-based partitioning
- **Cache Distribution**: Redis cluster mode

### Vertical Scaling
- **Resource Tuning**: Optimize memory and CPU usage
- **Connection Pooling**: Efficient database connections
- **Garbage Collection**: Tuned Go GC parameters
- **Process Limits**: Configurable resource constraints

### Performance Monitoring
- **Metrics Collection**: Prometheus integration
- **Health Checks**: Comprehensive service monitoring
- **Log Aggregation**: Structured logging with centralized collection
- **Alerting**: Automated alerts for service degradation

This architecture successfully delivers a production-ready system capable of handling 100+ concurrent Claude Code sessions with comprehensive security, monitoring, and scalability features.