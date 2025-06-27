package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"claudy/internal/config"
	"claudy/internal/container"
	"claudy/internal/middleware"

	"github.com/gin-gonic/gin"
)

// Server represents the HTTP server with all its dependencies
type Server struct {
	httpServer  *http.Server
	router      *gin.Engine
	container   *container.Container
	config      *config.Config
	port        string
	environment string
	started     bool
	mu          sync.RWMutex
}

// NewServer creates a new server instance with all dependencies configured
func NewServer() *Server {
	// Load configuration
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			URI:            getEnvOrDefault("MONGO_URI", "mongodb://localhost:27017"),
			Database:       getEnvOrDefault("MONGO_DB", "claudy"),
			ConnectTimeout: 30 * time.Second,
			QueryTimeout:   10 * time.Second,
			MaxPoolSize:    100,
			MinPoolSize:    10,
		},
		Redis: config.RedisConfig{
			Addr:         getEnvOrDefault("REDIS_ADDR", "localhost:6379"),
			Password:     getEnvOrDefault("REDIS_PASSWORD", ""),
			DB:           0,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			PoolSize:     10,
			MinIdleConns: 5,
		},
	}

	// Create dependency injection container
	cont := container.New(cfg)

	// Configure Gin
	env := getEnvOrDefault("ENV", "development")
	if env == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else if env == "test" {
		gin.SetMode(gin.TestMode)
	}

	// Create router
	router := gin.New()
	
	// Add middleware
	middlewareConfig := middleware.DefaultMiddlewareConfig()
	middleware.ApplyMiddleware(router, middlewareConfig)

	// Get port
	port := getEnvOrDefault("PORT", "8080")
	if !isValidPort(port) {
		port = "8080" // Default to 8080 if invalid
	}

	server := &Server{
		router:      router,
		container:   cont,
		config:      cfg,
		port:        port,
		environment: env,
	}

	// Setup routes
	server.setupRoutes()

	return server
}

// GetPort returns the configured port
func (s *Server) GetPort() string {
	return s.port
}

// GetEnvironment returns the configured environment
func (s *Server) GetEnvironment() string {
	return s.environment
}

// GetRouter returns the Gin router
func (s *Server) GetRouter() *gin.Engine {
	return s.router
}

// GetContainer returns the dependency injection container
func (s *Server) GetContainer() *container.Container {
	return s.container
}

// Start starts the HTTP server
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return fmt.Errorf("server already started")
	}

	// Initialize container
	ctx := context.Background()
	if err := s.container.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize container: %w", err)
	}

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:    ":" + s.port,
		Handler: s.router,
	}

	s.started = true

	// Start listening
	log.Printf("Server starting on port %s in %s mode", s.port, s.environment)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.started = false
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started || s.httpServer == nil {
		return nil // Already shutdown or never started
	}

	log.Println("Server shutting down gracefully...")

	// Shutdown HTTP server
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown HTTP server: %w", err)
	}

	// Shutdown container
	if err := s.container.Stop(ctx); err != nil {
		log.Printf("Warning: failed to shutdown container cleanly: %v", err)
	}

	s.started = false
	log.Println("Server shutdown complete")
	return nil
}

// Run starts the server and handles graceful shutdown on signals
func (s *Server) Run() error {
	// Channel to listen for interrupt signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		if err := s.Start(); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	// Wait for signal
	<-quit
	log.Println("Received shutdown signal")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return s.Shutdown(ctx)
}

// setupRoutes configures all application routes
func (s *Server) setupRoutes() {
	// Health endpoint
	s.router.GET("/health", func(c *gin.Context) {
		healthStatus := s.container.GetHealthStatus(c.Request.Context())
		if healthStatus.Healthy {
			c.JSON(http.StatusOK, gin.H{
				"status":    "healthy",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"version":   "1.0.0",
			})
		} else {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":    "unhealthy",
				"details":   healthStatus.Details,
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})
		}
	})

	// Slow endpoint for testing graceful shutdown
	s.router.GET("/api/slow", func(c *gin.Context) {
		time.Sleep(2 * time.Second)
		c.JSON(http.StatusOK, gin.H{
			"message": "slow response completed",
		})
	})

	// API routes group
	api := s.router.Group("/api/v1")
	{
		api.GET("/status", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"service":     "claudy-backend",
				"version":     "1.0.0",
				"environment": s.environment,
				"port":        s.port,
			})
		})
	}
}

// getEnvOrDefault gets environment variable or returns default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// isValidPort checks if the port string is a valid port number
func isValidPort(port string) bool {
	if portNum, err := strconv.Atoi(port); err == nil {
		return portNum > 0 && portNum <= 65535
	}
	return false
}

func main() {
	server := NewServer()
	if err := server.Run(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}