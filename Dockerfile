# Multi-stage Dockerfile for Claudy backend
# Stage 1: Development base with hot reload capabilities
FROM golang:1.24-alpine AS development

# Install development tools
RUN apk add --no-cache \
    git \
    make \
    curl \
    bash \
    tzdata \
    ca-certificates

# Install Air for hot reload (development only)
RUN go install github.com/air-verse/air@latest

# Install Delve for debugging
RUN go install github.com/go-delve/delve/cmd/dlv@latest

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Create non-root user for security
RUN adduser -D -s /bin/sh claudy

# Create necessary directories and set permissions
RUN mkdir -p /tmp/claudy-workspaces && \
    mkdir -p /app/test_keys && \
    chown -R claudy:claudy /app /tmp/claudy-workspaces

# Expose ports
EXPOSE 8080 2345

# Default command for development (with hot reload)
CMD ["air", "-c", ".air.toml"]

# Stage 2: Builder for production
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o claudy-backend \
    ./cmd/server

# Stage 3: Production runtime
FROM alpine:latest AS production

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN adduser -D -s /bin/sh claudy

# Set working directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/claudy-backend .

# Copy necessary config files and keys
COPY --from=builder /app/test_keys ./test_keys/

# Create workspace directory
RUN mkdir -p /tmp/claudy-workspaces && \
    chown -R claudy:claudy /app /tmp/claudy-workspaces

# Switch to non-root user
USER claudy

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["./claudy-backend"]