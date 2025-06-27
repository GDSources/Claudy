# Claudy Backend Server

A production-ready HTTP server with comprehensive middleware, dependency injection, and graceful shutdown.

## Features

- **Gin HTTP Framework** with optimized middleware stack
- **Dependency Injection Container** with lifecycle management
- **Comprehensive Middleware**:
  - CORS with origin validation
  - Rate limiting with burst support
  - Security headers (CSP, HSTS, XSS protection)
- **Graceful Shutdown** with signal handling
- **Health Monitoring** with service status reporting
- **Environment Configuration** with validation

## Quick Start

```bash
# Set environment variables (optional)
export PORT=8080
export ENV=development
export MONGO_URI=mongodb://localhost:27017
export REDIS_ADDR=localhost:6379

# Run the server
go run ./cmd/server

# Or build and run
go build -o claudy-server ./cmd/server
./claudy-server
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `ENV` | `development` | Environment mode (`development`, `production`, `test`) |
| `MONGO_URI` | `mongodb://localhost:27017` | MongoDB connection URI |
| `MONGO_DB` | `claudy` | MongoDB database name |
| `REDIS_ADDR` | `localhost:6379` | Redis server address |
| `REDIS_PASSWORD` | `` | Redis password (if required) |

## API Endpoints

### Health Check
```bash
GET /health
```
Returns server health status and dependency information.

### API Status
```bash
GET /api/v1/status
```
Returns service information and configuration details.

## Testing

### Unit Tests
```bash
go test ./cmd/server -v -run TestServerUnitTests
```

### Integration Tests (requires Docker)
```bash
go test ./cmd/server -v -run TestServerWithRealDatabases
```

### Skip Integration Tests
```bash
SKIP_INTEGRATION=true go test ./cmd/server -v
```

## Production Deployment

1. Set `ENV=production` for optimized performance
2. Configure proper MongoDB and Redis instances
3. Set appropriate resource limits
4. Use process manager (systemd, Docker, etc.)
5. Configure reverse proxy (nginx, etc.)

## Signal Handling

The server gracefully handles:
- `SIGINT` (Ctrl+C)
- `SIGTERM` (kill command)

Graceful shutdown includes:
- Stop accepting new requests
- Complete active requests (30s timeout)
- Clean up database connections
- Release resources

## Architecture

```
cmd/server/
├── main.go              # Server implementation
├── main_test.go         # Unit tests
├── integration_test.go  # Integration tests with test containers
└── README.md           # This file
```

The server integrates:
- `internal/config/` - Configuration management
- `internal/container/` - Dependency injection
- `internal/middleware/` - HTTP middleware stack
- All other `internal/` packages for business logic