# Development Setup Guide

This guide provides comprehensive instructions for setting up the Claudy development environment, building the project, running tests, and contributing to the codebase.

## Prerequisites

### System Requirements
- **Go**: Version 1.21 or higher
- **Docker**: For test containers and optional local services
- **Git**: For version control
- **Make**: For build automation (optional)

### Development Tools (Recommended)
- **VS Code** with Go extension
- **GoLand** or other Go IDE
- **Postman** or similar for API testing
- **MongoDB Compass** for database inspection
- **Redis CLI** for cache inspection

## Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/GDSources/Claudy.git
cd Claudy
```

### 2. Install Dependencies
```bash
go mod download
go mod verify
```

### 3. Run Tests
```bash
# Run all unit tests
go test ./...

# Run with verbose output
go test -v ./...

# Run integration tests (requires Docker)
go test -v ./tests/integration/...
```

### 4. Build Application
```bash
# Build for current platform
go build -o bin/claudy-backend ./cmd/server

# Build for Linux (deployment)
GOOS=linux GOARCH=amd64 go build -o bin/claudy-backend-linux ./cmd/server
```

## Project Structure

```
claudy/
├── cmd/
│   └── server/             # Application entry point
│       └── main.go         # Main application file
├── internal/               # Private application code
│   ├── auth/               # JWT authentication
│   │   ├── jwt.go          # JWT service implementation
│   │   └── jwt_test.go     # JWT service tests
│   ├── models/             # Data models and repositories
│   │   ├── user.go         # User model and interfaces
│   │   └── user_test.go    # User model tests
│   ├── websocket/          # WebSocket handling
│   │   ├── handler.go      # WebSocket connection handler
│   │   └── handler_test.go # WebSocket handler tests
│   ├── session/            # Claude Code session management
│   │   ├── claude.go       # Session manager implementation
│   │   └── claude_test.go  # Session manager tests
│   ├── files/              # File management
│   │   ├── manager.go      # File manager implementation
│   │   └── manager_test.go # File manager tests
│   ├── redis/              # Redis service integration
│   │   └── service.go      # Redis service implementation
│   └── repository/         # Database repositories
│       └── mongodb.go      # MongoDB repository implementation
├── tests/
│   └── integration/        # Integration tests with test containers
│       ├── integration_test.go       # Main integration test suite
│       ├── mock_process_manager.go   # Mock process manager
│       └── README.md                 # Integration test documentation
├── docs/                   # Documentation
│   ├── ARCHITECTURE.md     # System architecture
│   ├── GITFLOW.md          # Git workflow
│   ├── TDD_METHODOLOGY.md  # Testing methodology
│   ├── DEVELOPMENT_SETUP.md # This file
│   └── SUBAGENT_PATTERNS.md # Subagent delegation patterns
├── go.mod                  # Go module definition
├── go.sum                  # Go module checksums
├── CLAUDE.md               # Claude Code guidance
├── PRD.md                  # Product requirements
└── README.md               # Project overview
```

## Development Environment Setup

### Environment Variables
Create a `.env` file in the project root:

```bash
# Server Configuration
PORT=8080
ENV=development

# GitHub OAuth2 (for integration testing)
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# Security
JWT_PRIVATE_KEY_PATH=./keys/jwt_private_key.pem
JWT_PUBLIC_KEY_PATH=./keys/jwt_public_key.pem
ENCRYPTION_KEY=your_32_byte_encryption_key_here

# MongoDB (for integration testing)
MONGO_URI=mongodb://localhost:27017
MONGO_DB=claudy_dev

# Redis (for integration testing)
REDIS_ADDR=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0

# Claude Code
CLAUDE_CODE_PATH=claude-code
WORKSPACE_BASE_PATH=/tmp/claudy-workspaces
MAX_SESSION_DURATION=1800

# Rate Limiting
RATE_LIMIT=100
RATE_LIMIT_BURST=10
```

### Generate JWT Keys
```bash
# Create keys directory
mkdir -p keys

# Generate RSA private key
openssl genrsa -out keys/jwt_private_key.pem 2048

# Generate RSA public key
openssl rsa -in keys/jwt_private_key.pem -pubout -out keys/jwt_public_key.pem

# Set proper permissions
chmod 600 keys/jwt_private_key.pem
chmod 644 keys/jwt_public_key.pem
```

## Running Tests

### Unit Tests
```bash
# Run all unit tests
go test ./internal/...

# Run specific package tests
go test ./internal/auth/
go test ./internal/models/
go test ./internal/websocket/
go test ./internal/session/
go test ./internal/files/

# Run with coverage
go test -cover ./internal/...

# Generate coverage report
go test -coverprofile=coverage.out ./internal/...
go tool cover -html=coverage.out -o coverage.html
```

### Integration Tests
```bash
# Prerequisites: Docker must be running
docker --version

# Run integration tests (will start test containers)
go test -v ./tests/integration/

# Run specific integration test
go test -v ./tests/integration/ -run TestFullUserAuthenticationFlow

# Run integration tests with cleanup
go test -v ./tests/integration/ -cleanup
```

### Benchmark Tests
```bash
# Run benchmarks
go test -bench=. ./internal/...

# Run specific benchmarks
go test -bench=BenchmarkJWTTokenGeneration ./internal/auth/
go test -bench=BenchmarkFileUpload ./internal/files/

# Profile memory usage
go test -bench=. -memprofile=mem.prof ./internal/auth/
go tool pprof mem.prof
```

## Building and Running

### Local Development
```bash
# Build and run development server
go run ./cmd/server

# Build binary
go build -o bin/claudy-backend ./cmd/server

# Run with environment variables
PORT=8080 ENV=development ./bin/claudy-backend
```

### Production Build
```bash
# Build optimized binary
go build -ldflags="-s -w" -o bin/claudy-backend ./cmd/server

# Build for different platforms
GOOS=linux GOARCH=amd64 go build -o bin/claudy-backend-linux ./cmd/server
GOOS=darwin GOARCH=amd64 go build -o bin/claudy-backend-macos ./cmd/server
GOOS=windows GOARCH=amd64 go build -o bin/claudy-backend.exe ./cmd/server
```

### Docker Build
```bash
# Build Docker image
docker build -t claudy-backend .

# Run with Docker
docker run -p 8080:8080 claudy-backend

# Run with environment variables
docker run -p 8080:8080 -e PORT=8080 -e ENV=production claudy-backend
```

## Database Setup

### MongoDB (for integration testing)
```bash
# Run MongoDB container
docker run -d --name mongodb \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=password \
  mongo:7.0

# Connect to MongoDB
mongosh mongodb://admin:password@localhost:27017/
```

### Redis (for integration testing)
```bash
# Run Redis container
docker run -d --name redis \
  -p 6379:6379 \
  redis:7.0-alpine

# Connect to Redis
redis-cli -h localhost -p 6379
```

## Development Workflow

### 1. Feature Development
```bash
# Create feature branch
git checkout -b feature/new-component

# Follow TDD approach
# 1. Write failing tests
# 2. Implement minimal code to pass
# 3. Refactor and improve

# Run tests frequently
go test ./...

# Commit when tests pass
git add -A
git commit -m "Implement feature: description"
```

### 2. Code Quality
```bash
# Format code
go fmt ./...

# Lint code (requires golangci-lint)
golangci-lint run

# Vet code
go vet ./...

# Check for race conditions
go test -race ./...

# Check for memory leaks
go test -msan ./...
```

### 3. Pre-commit Checklist
- [ ] All tests pass: `go test ./...`
- [ ] Code formatted: `go fmt ./...`
- [ ] No lint errors: `golangci-lint run`
- [ ] No vet warnings: `go vet ./...`
- [ ] Integration tests pass: `go test ./tests/integration/`
- [ ] Documentation updated
- [ ] Commit message follows convention

## Debugging

### Debug Server
```bash
# Install Delve debugger
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug server
dlv debug ./cmd/server -- --port=8080

# Debug tests
dlv test ./internal/auth/
```

### Logging
```bash
# Enable debug logging
export LOG_LEVEL=debug
go run ./cmd/server

# Structured logging output
export LOG_FORMAT=json
go run ./cmd/server
```

### Profiling
```bash
# CPU profiling
go test -cpuprofile=cpu.prof ./internal/auth/
go tool pprof cpu.prof

# Memory profiling
go test -memprofile=mem.prof ./internal/auth/
go tool pprof mem.prof

# HTTP profiling (add to server)
import _ "net/http/pprof"
```

## Common Development Tasks

### Adding New Package
```bash
# Create package directory
mkdir -p internal/newpackage

# Create implementation file
touch internal/newpackage/service.go

# Create test file
touch internal/newpackage/service_test.go

# Follow TDD methodology (see docs/TDD_METHODOLOGY.md)
```

### Adding Dependencies
```bash
# Add new dependency
go get github.com/example/package

# Update dependencies
go get -u ./...

# Clean unused dependencies
go mod tidy
```

### Database Migrations
```bash
# MongoDB index creation (add to repository)
db.users.createIndex({"github_id": 1}, {"unique": true})
db.users.createIndex({"username": 1})
db.users.createIndex({"email": 1})

# Redis configuration
CONFIG SET maxmemory-policy allkeys-lru
CONFIG SET maxmemory 256mb
```

## Performance Optimization

### Profiling Setup
```bash
# Add profiling to main.go
import _ "net/http/pprof"

# Access profiling endpoint
go tool pprof http://localhost:8080/debug/pprof/profile
```

### Memory Management
```bash
# Check memory usage
go test -memprofile=mem.prof ./...
go tool pprof mem.prof

# Check for memory leaks
go test -run=TestLongRunning -timeout=30m ./...
```

### Concurrency Testing
```bash
# Race condition detection
go test -race ./...

# Deadlock detection
go test -run=TestConcurrent -timeout=10s ./...
```

## Troubleshooting

### Common Issues

#### "Go module not found"
```bash
# Solution: Initialize module
go mod init claudy
go mod tidy
```

#### "Test containers fail to start"
```bash
# Solution: Check Docker daemon
docker version
docker ps

# Clean up containers
docker container prune
docker volume prune
```

#### "Permission denied for workspace"
```bash
# Solution: Fix permissions
sudo chown -R $USER:$USER /tmp/claudy-workspaces
chmod 755 /tmp/claudy-workspaces
```

#### "JWT key not found"
```bash
# Solution: Generate keys
mkdir -p keys
openssl genrsa -out keys/jwt_private_key.pem 2048
openssl rsa -in keys/jwt_private_key.pem -pubout -out keys/jwt_public_key.pem
```

### Getting Help

1. **Check Documentation**: Review `docs/` directory
2. **Run Tests**: Ensure development environment is working
3. **Check Issues**: Look for similar problems in GitHub issues
4. **Debug Logs**: Enable debug logging for detailed output
5. **Community**: Ask questions in project discussions

This development setup ensures a productive environment for contributing to the Claudy project with comprehensive testing, debugging, and quality assurance tools.