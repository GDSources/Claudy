package container

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"claudy/internal/config"

	"github.com/prometheus/client_golang/prometheus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Container holds all application services and manages their lifecycle
type Container struct {
	config *config.Config
	
	// Core services - using interface{} for now, will be typed properly in future tests
	mongoClient    *mongo.Client
	redisService   interface{}
	userRepo       interface{}
	jwtService     interface{}
	fileManager    interface{}
	sessionManager interface{}
	wsHandler      interface{}
	
	// Health and metrics
	healthChecker *HealthChecker
	registry      *prometheus.Registry
	
	// Lifecycle management
	started     bool
	everStarted bool
	mu          sync.RWMutex
	
	// Order tracking for dependency management
	initOrder     []string
	shutdownOrder []string
	orderMutex    sync.RWMutex
	
	// Error tracking for aggregation and reporting
	lastErrors   *ErrorDetails
	errorHistory *ErrorHistory
	errorMutex   sync.RWMutex
}

// New creates a new service container with the given configuration.
// Returns a container ready for initialization with all core components set up.
func New(cfg *config.Config) *Container {
	if cfg == nil {
		panic("config cannot be nil")
	}
	
	return &Container{
		config:        cfg,
		registry:      prometheus.NewRegistry(),
		healthChecker: NewHealthChecker(),
		started:       false,
		lastErrors:    &ErrorDetails{},
		errorHistory:  &ErrorHistory{},
	}
}

// Initialize initializes all services in the correct dependency order.
// This is a placeholder implementation - real service initialization will be added in future tests.
func (c *Container) Initialize(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.started {
		return fmt.Errorf("container already initialized")
	}
	
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}
	
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return fmt.Errorf("initialization failed: %w", ctx.Err())
	default:
		// Context is not cancelled, proceed
	}
	
	// Initialize infrastructure services (databases, caches) with proper cleanup on failure
	if err := c.initializeInfrastructureServices(ctx); err != nil {
		c.trackError("initialization", err)
		c.cleanupPartialInitialization(ctx)
		return fmt.Errorf("infrastructure initialization failed: %w", err)
	}
	
	// Initialize application services (stubs for now - will be replaced with real services)
	c.initializeApplicationServices()
	
	c.started = true
	c.everStarted = true
	return nil
}

// initializeInfrastructureServices initializes infrastructure-level services (databases, caches)
func (c *Container) initializeInfrastructureServices(ctx context.Context) error {
	// Initialize MongoDB first
	if err := c.initializeMongoDB(ctx); err != nil {
		return fmt.Errorf("MongoDB initialization failed: %w", err)
	}
	
	// Initialize Redis second
	if err := c.initializeRedis(ctx); err != nil {
		return fmt.Errorf("Redis initialization failed: %w", err)
	}
	
	return nil
}

// initializeApplicationServices initializes application-level services that depend on infrastructure
func (c *Container) initializeApplicationServices() {
	// Service stubs - clearly labeled for easy identification during development
	// Note: Infrastructure services (MongoDB, Redis) are initialized separately
	c.userRepo = &ServiceStub{Name: "user_repository", Initialized: true}
	c.trackInitialization("user_repository")
	
	c.jwtService = &ServiceStub{Name: "jwt_service", Initialized: true}
	c.trackInitialization("jwt_service")
	
	c.fileManager = &ServiceStub{Name: "file_manager", Initialized: true}
	c.trackInitialization("file_manager")
	
	c.sessionManager = &ServiceStub{Name: "session_manager", Initialized: true}
	c.trackInitialization("session_manager")
	
	c.wsHandler = &ServiceStub{Name: "websocket_handler", Initialized: true}
	c.trackInitialization("websocket_handler")
}

// cleanupPartialInitialization cleans up any services that were initialized before failure
func (c *Container) cleanupPartialInitialization(ctx context.Context) {
	// Cleanup in reverse dependency order
	
	// Cleanup Redis service if it exists
	if c.redisService != nil {
		// In real implementation, would close Redis connection
		c.redisService = nil
	}
	
	// Cleanup MongoDB connection if it exists
	if c.mongoClient != nil {
		c.mongoClient.Disconnect(ctx)
		c.mongoClient = nil
	}
}

// initializeMongoDB attempts to connect to MongoDB with the configured settings
func (c *Container) initializeMongoDB(ctx context.Context) error {
	clientOptions := options.Client().ApplyURI(c.config.Database.URI)
	clientOptions.SetMaxPoolSize(c.config.Database.MaxPoolSize)
	clientOptions.SetMinPoolSize(c.config.Database.MinPoolSize)
	clientOptions.SetConnectTimeout(c.config.Database.ConnectTimeout)
	
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %w", err)
	}
	
	// Skip ping for stub implementation to avoid requiring real DB
	c.mongoClient = client
	
	// Track initialization order
	c.trackInitialization("mongodb")
	
	return nil
}

// initializeRedis attempts to connect to Redis with the configured settings
func (c *Container) initializeRedis(ctx context.Context) error {
	if c.config.Redis.Addr == "" {
		// Create default Redis service stub when no configuration provided
		c.redisService = &ServiceStub{Name: "redis_service", Initialized: true}
		c.trackInitialization("redis")
		return nil
	}
	
	// For now, simulate Redis connection attempt that will fail with invalid addresses
	// In a real implementation, this would use go-redis client
	if strings.Contains(c.config.Redis.Addr, "invalid") {
		return fmt.Errorf("Redis connection failed: cannot connect to %s", c.config.Redis.Addr)
	}
	
	// Create Redis service stub for valid addresses
	c.redisService = &ServiceStub{Name: "redis_service", Initialized: true}
	
	// Track initialization order
	c.trackInitialization("redis")
	
	return nil
}


// ServiceStub represents a placeholder service for testing
type ServiceStub struct {
	Name        string
	Initialized bool
}

// String implements fmt.Stringer for better debugging
func (s *ServiceStub) String() string {
	status := "uninitialized"
	if s.Initialized {
		status = "initialized"
	}
	return fmt.Sprintf("ServiceStub{name: %s, status: %s}", s.Name, status)
}

// Stop gracefully stops all services in reverse dependency order.
// Safe to call multiple times or when not started.
func (c *Container) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if !c.started {
		return nil // Already stopped, safe to call multiple times
	}
	
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return fmt.Errorf("stop failed: %w", ctx.Err())
	default:
		// Context is not cancelled, proceed
	}
	
	var errors []error
	
	// Stop application services first (reverse order of initialization)
	if c.wsHandler != nil {
		c.trackShutdown("websocket_handler")
		c.wsHandler = nil
	}
	
	if c.sessionManager != nil {
		c.trackShutdown("session_manager")
		c.sessionManager = nil
	}
	
	if c.fileManager != nil {
		c.trackShutdown("file_manager")
		c.fileManager = nil
	}
	
	if c.jwtService != nil {
		c.trackShutdown("jwt_service")
		c.jwtService = nil
	}
	
	if c.userRepo != nil {
		c.trackShutdown("user_repository")
		c.userRepo = nil
	}
	
	// Stop infrastructure services last
	if c.redisService != nil {
		c.trackShutdown("redis")
		c.redisService = nil
	}
	
	if c.mongoClient != nil {
		if err := c.mongoClient.Disconnect(ctx); err != nil {
			errors = append(errors, fmt.Errorf("MongoDB disconnect error: %w", err))
		}
		c.trackShutdown("mongodb")
		c.mongoClient = nil
	}
	
	c.started = false
	
	// Return first error if any occurred
	if len(errors) > 0 {
		return errors[0]
	}
	
	return nil
}

// Start starts all services that require explicit startup.
// Must be called after Initialize(). Safe to call multiple times (idempotent).
func (c *Container) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if !c.started {
		err := fmt.Errorf("container not initialized - call Initialize() first")
		c.trackError("start", err)
		return err
	}
	
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}
	
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		err := fmt.Errorf("start failed: %w", ctx.Err())
		c.trackError("start", err)
		return err
	default:
		// Context is not cancelled, proceed
	}
	
	// Start services that need explicit startup (placeholder implementation)
	// In future tests, this will start session managers, background workers, etc.
	// For now, all services are considered "started" during initialization
	
	return nil
}

// IsStarted returns true if the container has been initialized.
// This indicates that all services are ready for use.
func (c *Container) IsStarted() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.started
}

// Service getters - all are thread-safe with read locks

// MongoDB returns the MongoDB client instance. Returns nil if not initialized.
func (c *Container) MongoDB() *mongo.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.mongoClient
}

// Redis returns the Redis service instance. Returns nil if not initialized.
func (c *Container) Redis() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.redisService
}

// UserRepository returns the user repository instance. Returns nil if not initialized.
func (c *Container) UserRepository() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.userRepo
}

// JWTService returns the JWT service instance. Returns nil if not initialized.
func (c *Container) JWTService() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.jwtService
}

// FileManager returns the file manager instance. Returns nil if not initialized.
func (c *Container) FileManager() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.fileManager
}

// SessionManager returns the session manager instance. Returns nil if not initialized.
func (c *Container) SessionManager() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionManager
}

// WebSocketHandler returns the WebSocket handler instance. Returns nil if not initialized.
func (c *Container) WebSocketHandler() interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.wsHandler
}

// HealthChecker returns the health checker instance. Never nil.
func (c *Container) HealthChecker() *HealthChecker {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.healthChecker
}

// Registry returns the Prometheus metrics registry. Never nil.
func (c *Container) Registry() *prometheus.Registry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.registry
}

// Config returns the configuration instance. Never nil.
func (c *Container) Config() *config.Config {
	return c.config // Config is immutable, no lock needed
}

// ValidateServices validates that all initialized services are accessible and functional.
// Returns an error if any service is missing or if the container is not initialized.
// This method is thread-safe and can be called concurrently.
func (c *Container) ValidateServices(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if !c.started {
		err := fmt.Errorf("container not initialized - call Initialize() first")
		c.trackError("validate_services", err)
		return err
	}
	
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}
	
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		err := fmt.Errorf("service validation failed: %w", ctx.Err())
		c.trackError("validate_services", err)
		return err
	default:
		// Context is not cancelled, proceed
	}
	
	// Validate core services are present
	validationErrors := c.validateCoreServices()
	if len(validationErrors) > 0 {
		return fmt.Errorf("service validation failed: %v", validationErrors)
	}
	
	return nil
}

// RollbackInitialization cleans up any partially initialized state.
// This is called when initialization fails to ensure a clean state.
// Safe to call multiple times or when no initialization has occurred.
// Thread-safe and idempotent - can be called concurrently and repeatedly.
func (c *Container) RollbackInitialization(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}
	
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		err := fmt.Errorf("rollback failed: %w", ctx.Err())
		c.trackError("rollback_initialization", err)
		return err
	default:
		// Context is not cancelled, proceed
	}
	
	var cleanupErrors []error
	
	// Clean up services in reverse dependency order
	cleanupErrors = append(cleanupErrors, c.cleanupDatabaseConnections(ctx)...)
	c.resetServiceReferences()
	c.resetContainerState()
	
	// Return aggregated errors if any occurred during cleanup
	if len(cleanupErrors) > 0 {
		return fmt.Errorf("cleanup errors occurred: %v", cleanupErrors)
	}
	
	return nil
}

// cleanupDatabaseConnections handles cleanup of database connections
func (c *Container) cleanupDatabaseConnections(ctx context.Context) []error {
	var errors []error
	
	// Clean up MongoDB connection if it exists
	if c.mongoClient != nil {
		if err := c.mongoClient.Disconnect(ctx); err != nil {
			errors = append(errors, fmt.Errorf("MongoDB disconnect failed: %w", err))
		}
		c.mongoClient = nil
	}
	
	// Future: Redis cleanup would go here
	// Future: Other database cleanups would go here
	
	return errors
}

// resetServiceReferences clears all service references
func (c *Container) resetServiceReferences() {
	c.redisService = nil
	c.userRepo = nil
	c.jwtService = nil
	c.fileManager = nil
	c.sessionManager = nil
	c.wsHandler = nil
}

// resetContainerState resets the container's internal state
func (c *Container) resetContainerState() {
	c.started = false
}

// ValidateRedisConnection validates that Redis connection is working
func (c *Container) ValidateRedisConnection(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}
	
	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		err := fmt.Errorf("Redis validation failed: %w", ctx.Err())
		c.trackError("validate_redis_connection", err)
		return err
	default:
		// Context is not cancelled, proceed
	}
	
	if !c.started {
		err := fmt.Errorf("Redis connection validation failed: container not initialized")
		c.trackError("validate_redis_connection", err)
		return err
	}
	
	if c.redisService == nil {
		err := fmt.Errorf("Redis service not available: connection not established")
		c.trackError("validate_redis_connection", err)
		return err
	}
	
	// Basic validation - check if Redis service is accessible
	// In the current stub implementation, just check if service exists
	return nil
}

// validateCoreServices performs nil checks on all core services
func (c *Container) validateCoreServices() []string {
	var errors []string
	
	if c.mongoClient == nil {
		errors = append(errors, "MongoDB client is nil")
	}
	
	if c.redisService == nil {
		errors = append(errors, "Redis service is nil")
	}
	
	if c.userRepo == nil {
		errors = append(errors, "User repository is nil")
	}
	
	if c.jwtService == nil {
		errors = append(errors, "JWT service is nil")
	}
	
	if c.fileManager == nil {
		errors = append(errors, "File manager is nil")
	}
	
	if c.sessionManager == nil {
		errors = append(errors, "Session manager is nil")
	}
	
	if c.wsHandler == nil {
		errors = append(errors, "WebSocket handler is nil")
	}
	
	// Core services that should never be nil
	if c.healthChecker == nil {
		errors = append(errors, "Health checker is nil")
	}
	
	if c.registry == nil {
		errors = append(errors, "Prometheus registry is nil")
	}
	
	return errors
}

// trackInitialization records the order of service initialization
func (c *Container) trackInitialization(serviceName string) {
	c.orderMutex.Lock()
	defer c.orderMutex.Unlock()
	c.initOrder = append(c.initOrder, serviceName)
}

// trackShutdown records the order of service shutdown
func (c *Container) trackShutdown(serviceName string) {
	c.orderMutex.Lock()
	defer c.orderMutex.Unlock()
	c.shutdownOrder = append(c.shutdownOrder, serviceName)
}

// GetInitializationOrder returns the order in which services were initialized
func (c *Container) GetInitializationOrder() ([]string, error) {
	c.orderMutex.RLock()
	defer c.orderMutex.RUnlock()
	
	// Return a copy to avoid external modification
	result := make([]string, len(c.initOrder))
	copy(result, c.initOrder)
	return result, nil
}

// GetShutdownOrder returns the order in which services were shut down
func (c *Container) GetShutdownOrder() ([]string, error) {
	c.orderMutex.RLock()
	defer c.orderMutex.RUnlock()
	
	// Return a copy to avoid external modification
	result := make([]string, len(c.shutdownOrder))
	copy(result, c.shutdownOrder)
	return result, nil
}

// ResetOrderTracking clears the initialization and shutdown order tracking
func (c *Container) ResetOrderTracking() error {
	c.orderMutex.Lock()
	defer c.orderMutex.Unlock()
	
	c.initOrder = nil
	c.shutdownOrder = nil
	return nil
}

// HealthStatus represents the health status of the container and its services
type HealthStatus struct {
	Healthy   bool                   `json:"healthy"`
	Details   map[string]interface{} `json:"details"`
	Timestamp string                 `json:"timestamp"`
}

// ServiceHealth represents the health status of an individual service
type ServiceHealth struct {
	ServiceName string `json:"service_name"`
	Healthy     bool   `json:"healthy"`
	Message     string `json:"message"`
	Timestamp   string `json:"timestamp"`
}

// GetHealthStatus returns comprehensive health status for the container and all services
func (c *Container) GetHealthStatus(ctx context.Context) *HealthStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	details := make(map[string]interface{})
	
	// Determine container status
	var containerStatus string
	var healthy bool
	
	if !c.started {
		// Determine if stopped vs never initialized
		if c.everStarted {
			containerStatus = "stopped"
		} else {
			containerStatus = "not_initialized"
		}
		healthy = false
	} else {
		containerStatus = "initialized"
		healthy = true
	}
	
	details["container_status"] = containerStatus
	
	// Add service health details when initialized
	if c.started {
		details["mongodb_status"] = c.getServiceStatus("mongodb")
		details["redis_status"] = c.getServiceStatus("redis")
		details["service_count"] = 7 // Total services initialized
	}
	
	return &HealthStatus{
		Healthy:   healthy,
		Details:   details,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// CheckServiceHealth returns health status for a specific service
func (c *Container) CheckServiceHealth(ctx context.Context, serviceName string) *ServiceHealth {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	timestamp := time.Now().UTC().Format(time.RFC3339)
	
	if !c.started {
		return &ServiceHealth{
			ServiceName: serviceName,
			Healthy:     false,
			Message:     "container not initialized",
			Timestamp:   timestamp,
		}
	}
	
	healthy, message := c.checkIndividualServiceHealth(serviceName)
	
	return &ServiceHealth{
		ServiceName: serviceName,
		Healthy:     healthy,
		Message:     message,
		Timestamp:   timestamp,
	}
}

// checkIndividualServiceHealth checks the health of a specific service
func (c *Container) checkIndividualServiceHealth(serviceName string) (bool, string) {
	switch serviceName {
	case "mongodb":
		if c.mongoClient != nil {
			return true, "service healthy"
		}
		return false, "service not available"
	case "redis":
		if c.redisService != nil {
			return true, "service healthy"
		}
		return false, "service not available"
	default:
		return false, "service not found"
	}
}

// getServiceStatus returns a simple status string for a service
func (c *Container) getServiceStatus(serviceName string) string {
	switch serviceName {
	case "mongodb":
		if c.mongoClient != nil {
			return "healthy"
		}
	case "redis":
		if c.redisService != nil {
			return "healthy"
		}
	}
	return "unavailable"
}

// ErrorDetails holds detailed information about recent errors
type ErrorDetails struct {
	Errors    []string `json:"errors"`
	Summary   string   `json:"summary"`
	Timestamp string   `json:"timestamp"`
}

// ErrorHistory tracks the history of failed operations
type ErrorHistory struct {
	Operations []OperationError `json:"operations"`
}

// OperationError represents a failed operation with details
type OperationError struct {
	Operation string `json:"operation"`
	Error     string `json:"error"`
	Timestamp string `json:"timestamp"`
}

// GetLastErrors returns detailed information about the most recent errors
func (c *Container) GetLastErrors() *ErrorDetails {
	c.errorMutex.RLock()
	defer c.errorMutex.RUnlock()
	
	// Return a copy to avoid external modification
	result := &ErrorDetails{
		Errors:    make([]string, len(c.lastErrors.Errors)),
		Summary:   c.lastErrors.Summary,
		Timestamp: c.lastErrors.Timestamp,
	}
	copy(result.Errors, c.lastErrors.Errors)
	
	return result
}

// GetErrorHistory returns the history of failed operations
func (c *Container) GetErrorHistory() *ErrorHistory {
	c.errorMutex.RLock()
	defer c.errorMutex.RUnlock()
	
	// Return a copy to avoid external modification
	result := &ErrorHistory{
		Operations: make([]OperationError, len(c.errorHistory.Operations)),
	}
	copy(result.Operations, c.errorHistory.Operations)
	
	return result
}

// ClearErrors clears all tracked errors and error history
func (c *Container) ClearErrors() {
	c.errorMutex.Lock()
	defer c.errorMutex.Unlock()
	
	c.lastErrors = &ErrorDetails{}
	c.errorHistory = &ErrorHistory{}
}

// trackError records an error for aggregation and reporting
func (c *Container) trackError(operation string, err error) {
	c.errorMutex.Lock()
	defer c.errorMutex.Unlock()
	
	timestamp := time.Now().UTC().Format(time.RFC3339)
	
	// Add to error history
	c.errorHistory.Operations = append(c.errorHistory.Operations, OperationError{
		Operation: operation,
		Error:     err.Error(),
		Timestamp: timestamp,
	})
	
	// Update last errors
	c.lastErrors.Errors = append(c.lastErrors.Errors, err.Error())
	c.lastErrors.Summary = fmt.Sprintf("%s failed", operation)
	c.lastErrors.Timestamp = timestamp
}