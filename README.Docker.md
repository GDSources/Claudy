# Claudy Docker Development Environment

This document provides comprehensive instructions for using Docker in the Claudy development workflow.

## Quick Start

1. **Prerequisites**: Ensure Docker and Docker Compose are installed
2. **Start Development Environment**:
   ```bash
   ./scripts/docker-dev.sh start
   ```
3. **Access Services**:
   - **Application**: http://localhost:8080
   - **MongoDB Express**: http://localhost:8081 (admin/admin)
   - **Redis Commander**: http://localhost:8082 (admin/admin)
   - **Documentation**: http://localhost:8083
   - **MailHog**: http://localhost:8025

## Development Workflow

### Starting Development

```bash
# Start all services with hot reload
./scripts/docker-dev.sh start

# View application logs
./scripts/docker-dev.sh logs

# View specific service logs
./scripts/docker-dev.sh logs mongo
./scripts/docker-dev.sh logs redis
```

### Code Development

The development environment includes:
- **Hot Reload**: Code changes automatically restart the application
- **Live Editing**: Source code is mounted as a volume
- **Debugging**: Delve debugger available on port 2345

```bash
# Open shell in development container
./scripts/docker-dev.sh exec

# Run specific commands
./scripts/docker-dev.sh exec go test ./...
./scripts/docker-dev.sh exec go mod tidy
./scripts/docker-dev.sh exec go run ./cmd/server
```

### Testing

```bash
# Run unit tests
./scripts/docker-dev.sh test

# Run integration tests with test containers
./scripts/docker-dev.sh test-integration

# Run specific test packages
./scripts/docker-dev.sh exec go test ./internal/auth -v
```

### Debugging

1. **Start Debug Session**:
   ```bash
   ./scripts/docker-dev.sh debug
   ```

2. **Connect Debugger**: Connect your IDE debugger to `localhost:2345`

3. **VS Code Configuration** (`.vscode/launch.json`):
   ```json
   {
     "version": "0.2.0",
     "configurations": [
       {
         "name": "Connect to Docker",
         "type": "go",
         "request": "attach",
         "mode": "remote",
         "remotePath": "/app",
         "port": 2345,
         "host": "127.0.0.1"
       }
     ]
   }
   ```

## Service Architecture

### Application Services

- **app**: Claudy backend with hot reload (Air)
- **mongo**: MongoDB 7.0 with development data
- **redis**: Redis 7.0 with persistence
- **mongo-express**: Web UI for MongoDB
- **redis-commander**: Web UI for Redis

### Development Tools

- **mailhog**: Email testing server
- **docs**: Documentation server (Nginx)

### Test Services (Profile: testing)

- **mongo-test**: Isolated MongoDB for integration tests
- **redis-test**: Isolated Redis for integration tests

## Configuration

### Environment Variables

Create `.env` file from template:
```bash
cp .env.docker .env
```

Key configuration options:

| Variable | Default | Description |
|----------|---------|-------------|
| `ENV` | `development` | Application environment |
| `PORT` | `8080` | HTTP server port |
| `MONGO_URI` | `mongodb://mongo:27017/claudy_dev` | MongoDB connection |
| `REDIS_ADDR` | `redis:6379` | Redis connection |
| `DEBUG` | `true` | Enable debug logging |

### Docker Compose Files

- **docker-compose.yml**: Main service definitions
- **docker-compose.override.yml**: Development-specific overrides
- **Profiles**: Use `--profile testing` for test services

## Data Persistence

### Volumes

- **mongo-data**: MongoDB data persistence
- **redis-data**: Redis data persistence
- **workspace-data**: Claude Code workspaces
- **go-mod-cache**: Go module cache for faster builds

### Database Initialization

MongoDB is automatically initialized with:
- Development user: `claudy_dev/devpassword`
- Test user: `claudy_test/testpassword`
- Optimized indexes for performance
- Sample development data

## Performance Optimization

### Development

- **Layer Caching**: Optimized Dockerfile layers
- **Module Cache**: Persistent Go module cache
- **Hot Reload**: Air for fast restart cycles
- **Resource Limits**: Controlled memory/CPU usage

### Build Optimization

```bash
# Build production image
./scripts/docker-dev.sh build-prod

# Multi-stage build with minimal runtime
docker build --target production -t claudy:prod .
```

## Troubleshooting

### Common Issues

1. **Services Not Starting**:
   ```bash
   # Check service status
   ./scripts/docker-dev.sh status
   
   # View detailed logs
   docker-compose logs
   ```

2. **Port Conflicts**:
   ```bash
   # Stop all services
   ./scripts/docker-dev.sh stop
   
   # Check port usage
   lsof -i :8080
   ```

3. **Database Connection Issues**:
   ```bash
   # Restart database services
   docker-compose restart mongo redis
   
   # Check connectivity
   ./scripts/docker-dev.sh exec nc -zv mongo 27017
   ```

4. **Hot Reload Not Working**:
   ```bash
   # Check Air process
   ./scripts/docker-dev.sh exec ps aux | grep air
   
   # Restart application service
   docker-compose restart app
   ```

### Cleanup

```bash
# Stop all services and remove volumes
./scripts/docker-dev.sh clean

# Remove all Docker resources
docker system prune -a --volumes
```

## Production Deployment

### Build Production Image

```bash
# Build optimized production image
docker build --target production -t claudy-backend:latest .

# Run production container
docker run -d \
  -p 8080:8080 \
  -e ENV=production \
  -e MONGO_URI=mongodb://mongo:27017/claudy \
  -e REDIS_ADDR=redis:6379 \
  claudy-backend:latest
```

### Docker Compose Production

Create `docker-compose.prod.yml`:
```yaml
version: '3.8'
services:
  app:
    image: claudy-backend:latest
    environment:
      - ENV=production
      - DEBUG=false
    # Add production configurations
```

## Best Practices

### Development

1. **Use the helper script**: `./scripts/docker-dev.sh` for all operations
2. **Keep .env updated**: Sync with team for consistent configuration
3. **Regular cleanup**: Use `clean` command to free disk space
4. **Monitor resources**: Use `status` command to check usage

### Testing

1. **Isolated environments**: Use test profiles for integration tests
2. **Clean state**: Tests start with fresh database containers
3. **Parallel execution**: Run tests concurrently when possible

### Security

1. **Development only**: This setup is for development environments
2. **Credential management**: Never commit real credentials
3. **Network isolation**: Services communicate via Docker network
4. **Non-root execution**: Application runs as non-root user

## Advanced Usage

### Custom Commands

```bash
# Custom Go commands
./scripts/docker-dev.sh exec go generate ./...
./scripts/docker-dev.sh exec go vet ./...
./scripts/docker-dev.sh exec golangci-lint run

# Database operations
./scripts/docker-dev.sh exec mongosh mongodb://mongo:27017/claudy_dev
./scripts/docker-dev.sh exec redis-cli -h redis
```

### Development with IDEs

#### VS Code
- Use Dev Containers extension
- Configure remote debugging
- Mount workspace for full IDE features

#### GoLand
- Configure remote Go interpreter
- Set up remote debugging configuration
- Use Docker integration features

## Support

For issues with the Docker development environment:

1. Check this documentation
2. Review service logs: `./scripts/docker-dev.sh logs`
3. Check service status: `./scripts/docker-dev.sh status`
4. Clean and restart: `./scripts/docker-dev.sh clean && ./scripts/docker-dev.sh start`