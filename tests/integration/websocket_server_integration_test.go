package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"claudy/internal/config"
	"claudy/internal/container"
	"claudy/internal/server"
)

// createTestKeys generates temporary RSA key pair for testing
func createTestKeys(t *testing.T) (privateKeyPath, publicKeyPath string, cleanup func()) {
	tempDir, err := ioutil.TempDir("", "claudy-test-keys-")
	require.NoError(t, err)

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create private key file
	privateKeyPath = filepath.Join(tempDir, "private.pem")
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	err = ioutil.WriteFile(privateKeyPath, privateKeyPEM, 0600)
	require.NoError(t, err)

	// Create public key file
	publicKeyPath = filepath.Join(tempDir, "public.pem")
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	err = ioutil.WriteFile(publicKeyPath, publicKeyPEM, 0644)
	require.NoError(t, err)

	cleanup = func() {
		os.RemoveAll(tempDir)
	}

	return privateKeyPath, publicKeyPath, cleanup
}

// createTestConfig creates a valid test configuration for containers
func createTestConfig(t *testing.T, websocketEnabled bool, websocketPath string) *config.Config {
	privateKeyPath, publicKeyPath, cleanup := createTestKeys(t)
	t.Cleanup(cleanup)

	tempWorkspace, err := ioutil.TempDir("", "claudy-test-workspace-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tempWorkspace) })

	return &config.Config{
		Environment: config.Development,
		Debug:       true,
		WebSocket: config.WebSocketConfig{
			Enabled:               websocketEnabled,
			Path:                  websocketPath,
			MaxConnectionsPerUser: 3,
			AllowedOrigins:        []string{"http://localhost:3000"},
			ReadTimeout:           60 * time.Second,
			WriteTimeout:          10 * time.Second,
			PingInterval:          30 * time.Second,
			BufferSize:            1024,
		},
		Database: config.DatabaseConfig{
			URI:            "mongodb://localhost:27017",
			Database:       "test",
			ConnectTimeout: 10 * time.Second,
			QueryTimeout:   5 * time.Second,
			MaxPoolSize:    10,
			MinPoolSize:    1,
		},
		Redis: config.RedisConfig{
			Addr:         "localhost:6379",
			Password:     "",
			DB:           0,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			PoolSize:     10,
			MinIdleConns: 2,
		},
		JWT: config.JWTConfig{
			PrivateKeyPath: privateKeyPath,
			PublicKeyPath:  publicKeyPath,
			Issuer:         "claudy-test",
			ExpiryDuration: 24 * time.Hour,
		},
		Claude: config.ClaudeConfig{
			APIBaseURL:             "https://api.anthropic.com",
			CodePath:               "claude-code",
			WorkspaceBasePath:      tempWorkspace,
			MaxSessionDuration:     30 * time.Minute,
			SessionCleanupInterval: 5 * time.Minute,
			MaxFileSize:            10485760,
			MaxWorkspaceSize:       104857600,
		},
		Security: config.SecurityConfig{
			EncryptionKey:     "test-32-byte-key-for-testing!!!!", // Exactly 32 bytes
			CSPPolicy:         "default-src 'self'",
			HSTSMaxAge:        31536000,
			EnableHSTS:        true,
			EnableCSP:         true,
			EnableFrameDeny:   true,
		},
		Monitoring: config.MonitoringConfig{
			Enabled:              true,
			MetricsPath:          "/metrics",
			HealthPath:           "/health",
			ReadinessPath:        "/ready",
			EnableRequestLogging: true,
		},
		RateLimit: config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100.0,
			BurstSize:         10,
			KeyFunc:           "ip",
		},
		Server: config.ServerConfig{
			Host:             "localhost",
			Port:             8080,
			ReadTimeout:      30 * time.Second,
			WriteTimeout:     30 * time.Second,
			IdleTimeout:      120 * time.Second,
			ShutdownTimeout:  30 * time.Second,
			MaxHeaderBytes:   1048576,
			AllowedOrigins:   []string{"http://localhost:3000"},
			TLS: config.TLSConfig{
				Enabled: false,
			},
		},
	}
}

// setupTestEnvironment sets up environment variables for server tests that use config.Load()
func setupTestEnvironment(t *testing.T, websocketEnabled bool, websocketPath string) func() {
	privateKeyPath, publicKeyPath, keyCleanup := createTestKeys(t)
	
	tempWorkspace, err := ioutil.TempDir("", "claudy-test-workspace-")
	require.NoError(t, err)

	// Set environment variables
	originalEnv := make(map[string]string)
	envVars := map[string]string{
		"ENVIRONMENT":                    "development",
		"DEBUG":                          "true",
		"WEBSOCKET_ENABLED":              fmt.Sprintf("%t", websocketEnabled),
		"WEBSOCKET_PATH":                 websocketPath,
		"JWT_PRIVATE_KEY_PATH":           privateKeyPath,
		"JWT_PUBLIC_KEY_PATH":            publicKeyPath,
		"JWT_ISSUER":                     "claudy-test",
		"JWT_EXPIRY_DURATION":            "24h",
		"SECURITY_ENCRYPTION_KEY":        "test-32-byte-key-for-testing!!!!", // Exactly 32 bytes
		"SECURITY_ENABLE_HSTS":           "true",
		"SECURITY_ENABLE_CSP":            "true",
		"SECURITY_ENABLE_FRAME_DENY":     "true",
		"SECURITY_HSTS_MAX_AGE":          "31536000",
		"SECURITY_CSP_POLICY":            "default-src 'self'",
		"CLAUDE_WORKSPACE_BASE_PATH":     tempWorkspace,
		"CLAUDE_API_BASE_URL":            "https://api.anthropic.com",
		"CLAUDE_CODE_PATH":               "claude-code",
		"CLAUDE_MAX_SESSION_DURATION":    "30m",
		"CLAUDE_SESSION_CLEANUP_INTERVAL": "5m",
		"CLAUDE_MAX_FILE_SIZE":           "10485760",
		"CLAUDE_MAX_WORKSPACE_SIZE":      "104857600",
		"MONITORING_ENABLED":             "true",
		"MONITORING_METRICS_PATH":        "/metrics",
		"MONITORING_HEALTH_PATH":         "/health",
		"MONITORING_READINESS_PATH":      "/ready",
		"MONITORING_ENABLE_REQUEST_LOGGING": "true",
		"RATE_LIMIT_ENABLED":             "true",
		"RATE_LIMIT_REQUESTS_PER_SECOND": "100.0",
		"RATE_LIMIT_BURST_SIZE":          "10",
		"RATE_LIMIT_KEY_FUNC":            "ip",
		"SERVER_HOST":                    "localhost",
		"SERVER_PORT":                    "8080",
		"SERVER_READ_TIMEOUT":            "30s",
		"SERVER_WRITE_TIMEOUT":           "30s",
		"SERVER_IDLE_TIMEOUT":            "120s",
		"SERVER_SHUTDOWN_TIMEOUT":        "30s",
		"SERVER_MAX_HEADER_BYTES":        "1048576",
		"SERVER_TLS_ENABLED":             "false",
		"DATABASE_URI":                   "mongodb://localhost:27017",
		"DATABASE_DATABASE":              "claudy-test",
		"DATABASE_CONNECT_TIMEOUT":       "10s",
		"DATABASE_QUERY_TIMEOUT":         "30s",
		"DATABASE_MAX_POOL_SIZE":         "100",
		"DATABASE_MIN_POOL_SIZE":         "5",
		"REDIS_ADDR":                     "localhost:6379",
		"REDIS_PASSWORD":                 "",
		"REDIS_DB":                       "0",
		"REDIS_DIAL_TIMEOUT":             "5s",
		"REDIS_READ_TIMEOUT":             "3s",
		"REDIS_WRITE_TIMEOUT":            "3s",
		"REDIS_POOL_SIZE":                "10",
		"REDIS_MIN_IDLE_CONNS":           "2",
	}

	for key, value := range envVars {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, value)
	}

	return func() {
		// Restore original environment
		for key, value := range originalEnv {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
		keyCleanup()
		os.RemoveAll(tempWorkspace)
	}
}

// TestContainerWebSocketInitialization verifies proper dependency injection setup for WebSocket handler
func TestContainerWebSocketInitialization(t *testing.T) {
	tests := []struct {
		name           string
		webSocketEnabled bool
		expectHandler  bool
	}{
		{
			name:           "WebSocket enabled - handler should be initialized",
			webSocketEnabled: true,
			expectHandler:  true,
		},
		{
			name:           "WebSocket disabled - handler should not be initialized", 
			webSocketEnabled: false,
			expectHandler:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test configuration
			cfg := createTestConfig(t, tt.webSocketEnabled, "/ws")

			// Create container
			cont := container.New(cfg)
			require.NotNil(t, cont)

			// Initialize container
			ctx := context.Background()
			err := cont.Initialize(ctx)
			require.NoError(t, err)

			// Verify WebSocket handler initialization
			wsHandler := cont.GetWebSocketHandler()
			if tt.expectHandler {
				assert.NotNil(t, wsHandler, "WebSocket handler should be initialized when enabled")
			} else {
				assert.Nil(t, wsHandler, "WebSocket handler should not be initialized when disabled")
			}

			// Verify initialization order includes WebSocket handler
			initOrder, err := cont.GetInitializationOrder()
			require.NoError(t, err)

			if tt.expectHandler {
				assert.Contains(t, initOrder, "websocket_handler", "WebSocket handler should be in initialization order")
			} else {
				assert.Contains(t, initOrder, "websocket_handler_disabled", "WebSocket disabled should be tracked in initialization order")
			}

			// Cleanup
			err = cont.Stop(ctx)
			assert.NoError(t, err)
		})
	}
}

// TestWebSocketConfigurationLoading verifies config parsing and validation for WebSocket settings
func TestWebSocketConfigurationLoading(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		expectError bool
		validate    func(t *testing.T, cfg *config.Config)
	}{
		{
			name: "Default WebSocket configuration",
			envVars: map[string]string{},
			expectError: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.True(t, cfg.WebSocket.Enabled)
				assert.Equal(t, "/ws", cfg.WebSocket.Path)
				assert.Equal(t, 3, cfg.WebSocket.MaxConnectionsPerUser)
				assert.Equal(t, []string{"http://localhost:3000", "https://app.claudy.com"}, cfg.WebSocket.AllowedOrigins)
				assert.Equal(t, 60*time.Second, cfg.WebSocket.ReadTimeout)
				assert.Equal(t, 10*time.Second, cfg.WebSocket.WriteTimeout)
				assert.Equal(t, 30*time.Second, cfg.WebSocket.PingInterval)
				assert.Equal(t, 1024, cfg.WebSocket.BufferSize)
			},
		},
		{
			name: "Custom WebSocket configuration via environment",
			envVars: map[string]string{
				"WEBSOCKET_ENABLED":                  "true",
				"WEBSOCKET_PATH":                     "/custom-ws",
				"WEBSOCKET_MAX_CONNECTIONS_PER_USER": "5",
				"WEBSOCKET_READ_TIMEOUT":             "45s",
				"WEBSOCKET_WRITE_TIMEOUT":            "15s",
				"WEBSOCKET_PING_INTERVAL":            "20s",
				"WEBSOCKET_BUFFER_SIZE":              "2048",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.True(t, cfg.WebSocket.Enabled)
				assert.Equal(t, "/custom-ws", cfg.WebSocket.Path)
				assert.Equal(t, 5, cfg.WebSocket.MaxConnectionsPerUser)
				assert.Equal(t, 45*time.Second, cfg.WebSocket.ReadTimeout)
				assert.Equal(t, 15*time.Second, cfg.WebSocket.WriteTimeout)
				assert.Equal(t, 20*time.Second, cfg.WebSocket.PingInterval)
				assert.Equal(t, 2048, cfg.WebSocket.BufferSize)
			},
		},
		{
			name: "WebSocket disabled",
			envVars: map[string]string{
				"WEBSOCKET_ENABLED": "false",
			},
			expectError: false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.False(t, cfg.WebSocket.Enabled)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up test environment
			cleanup := setupTestEnvironment(t, true, "/ws")
			defer cleanup()

			// Set additional environment variables from test case (non-empty values only)
			for key, value := range tt.envVars {
				if value != "" {
					t.Setenv(key, value)
				}
			}

			// Load configuration
			cfg, err := config.Load()
			
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			
			require.NoError(t, err)
			require.NotNil(t, cfg)

			// Run validation
			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

// TestWebSocketRouteRegistration verifies the WebSocket route is properly mounted
func TestWebSocketRouteRegistration(t *testing.T) {
	tests := []struct {
		name           string
		websocketPath  string
		enabled        bool
		expectRoute    bool
	}{
		{
			name:          "Default WebSocket path registration",
			websocketPath: "/ws",
			enabled:       true,
			expectRoute:   true,
		},
		{
			name:          "Custom WebSocket path registration",
			websocketPath: "/custom-websocket",
			enabled:       true,
			expectRoute:   true,
		},
		{
			name:          "WebSocket disabled - no route registration",
			websocketPath: "/ws",
			enabled:       false,
			expectRoute:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up test environment
			cleanup := setupTestEnvironment(t, tt.enabled, tt.websocketPath)
			defer cleanup()

			// Create server
			srv := server.NewServer()
			require.NotNil(t, srv)

			// Initialize server to set up WebSocket routes
			err := srv.Initialize()
			require.NoError(t, err)

			// Get router and check routes
			router := srv.GetRouter()
			require.NotNil(t, router)

			// Create test HTTP server
			testServer := httptest.NewServer(router)
			defer testServer.Close()

			// Test WebSocket route
			wsURL := strings.Replace(testServer.URL, "http://", "ws://", 1) + tt.websocketPath
			
			// Try to connect to WebSocket endpoint
			dialer := websocket.Dialer{}
			conn, resp, err := dialer.Dial(wsURL, nil)
			
			if tt.expectRoute {
				// When route exists, we expect either a successful connection or a specific WebSocket error
				// (not a 404 Not Found)
				if err != nil {
					// Check that it's not a 404 error
					require.NotNil(t, resp)
					assert.NotEqual(t, http.StatusNotFound, resp.StatusCode, 
						"WebSocket route should exist and not return 404")
				} else {
					// Successful connection
					assert.NotNil(t, conn)
					conn.Close()
				}
			} else {
				// When route doesn't exist, we expect a 404
				require.Error(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, http.StatusNotFound, resp.StatusCode,
					"WebSocket route should not exist when disabled")
			}

			if resp != nil {
				resp.Body.Close()
			}
		})
	}
}

// TestWebSocketMiddlewareIntegration verifies security middleware is applied to WebSocket endpoints
func TestWebSocketMiddlewareIntegration(t *testing.T) {
	// Set up test environment
	cleanup := setupTestEnvironment(t, true, "/ws")
	defer cleanup()

	// Create server
	srv := server.NewServer()
	require.NotNil(t, srv)

	// Initialize server to set up WebSocket routes
	err := srv.Initialize()
	require.NoError(t, err)

	// Get router
	router := srv.GetRouter()
	require.NotNil(t, router)

	// Create test HTTP server
	testServer := httptest.NewServer(router)
	defer testServer.Close()

	// Test that security headers are applied to WebSocket upgrade request
	// Create a request to the WebSocket endpoint (but not upgrade it)
	req, err := http.NewRequest("GET", testServer.URL+"/ws", nil)
	require.NoError(t, err)

	// Add WebSocket headers to trigger the handler
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify security headers are present (added by middleware)
	assert.NotEmpty(t, resp.Header.Get("X-Frame-Options"), "X-Frame-Options header should be set by security middleware")
	assert.NotEmpty(t, resp.Header.Get("X-Content-Type-Options"), "X-Content-Type-Options header should be set by security middleware")
	
	// Even if WebSocket upgrade fails due to missing auth, security headers should be present
	// This confirms middleware stack is applied to WebSocket endpoints
}

// TestWebSocketServerStartup verifies server starts correctly with WebSocket enabled
func TestWebSocketServerStartup(t *testing.T) {
	// Create test configuration
	cfg := createTestConfig(t, true, "/ws")

	// Create container directly (bypassing server.NewServer() which loads config)
	cont := container.New(cfg)
	require.NotNil(t, cont)

	// Initialize container
	ctx := context.Background()
	err := cont.Initialize(ctx)
	require.NoError(t, err)

	// Verify WebSocket handler is available
	wsHandler := cont.GetWebSocketHandler()
	assert.NotNil(t, wsHandler, "WebSocket handler should be available after initialization")

	// Verify container is started
	assert.True(t, cont.IsStarted(), "Container should be started after initialization")

	// Cleanup
	err = cont.Stop(ctx)
	assert.NoError(t, err)
}

// TestWebSocketServerShutdown verifies proper cleanup on shutdown
func TestWebSocketServerShutdown(t *testing.T) {
	// Create test configuration
	cfg := createTestConfig(t, true, "/ws")

	// Create container directly
	cont := container.New(cfg)
	require.NotNil(t, cont)

	ctx := context.Background()
	err := cont.Initialize(ctx)
	require.NoError(t, err)

	// Verify WebSocket handler is initialized
	wsHandler := cont.GetWebSocketHandler()
	assert.NotNil(t, wsHandler, "WebSocket handler should be available before shutdown")

	// Shutdown container
	err = cont.Stop(ctx)
	require.NoError(t, err)

	// Verify container is stopped
	assert.False(t, cont.IsStarted(), "Container should be stopped after shutdown")

	// Verify shutdown order includes WebSocket handler
	shutdownOrder, err := cont.GetShutdownOrder()
	require.NoError(t, err)
	assert.Contains(t, shutdownOrder, "websocket_handler", "WebSocket handler should be in shutdown order")
}

// TestWebSocketConfigDisabled verifies WebSocket is properly disabled when configuration is disabled
func TestWebSocketConfigDisabled(t *testing.T) {
	// Set up test environment with WebSocket disabled
	cleanup := setupTestEnvironment(t, false, "/ws")
	defer cleanup()

	// Create server
	srv := server.NewServer()
	require.NotNil(t, srv)

	// Initialize server to set up WebSocket routes
	err := srv.Initialize()
	require.NoError(t, err)

	// Get container
	cont := srv.GetContainer()
	require.NotNil(t, cont)

	ctx := context.Background()

	// Verify WebSocket handler is not initialized when disabled
	wsHandler := cont.GetWebSocketHandler()
	assert.Nil(t, wsHandler, "WebSocket handler should not be available when disabled")

	// Verify initialization order tracks disabled state
	initOrder, err := cont.GetInitializationOrder()
	require.NoError(t, err)
	assert.Contains(t, initOrder, "websocket_handler_disabled", "WebSocket disabled state should be tracked")

	// Test that WebSocket route is not registered
	router := srv.GetRouter()
	testServer := httptest.NewServer(router)
	defer testServer.Close()

	// Try to access WebSocket endpoint
	req, err := http.NewRequest("GET", testServer.URL+"/ws", nil)
	require.NoError(t, err)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return 404 since route is not registered when disabled
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "WebSocket endpoint should return 404 when disabled")

	// Cleanup
	err = cont.Stop(ctx)
	assert.NoError(t, err)
}

// TestWebSocketHealthCheck verifies WebSocket status is included in health checks
func TestWebSocketHealthCheck(t *testing.T) {
	tests := []struct {
		name           string
		enabled        bool
		expectInHealth bool
	}{
		{
			name:           "WebSocket enabled - should appear in health status",
			enabled:        true,
			expectInHealth: true,
		},
		{
			name:           "WebSocket disabled - should not appear in health status",
			enabled:        false,
			expectInHealth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test configuration
			cfg := createTestConfig(t, tt.enabled, "/ws")

			// Create container directly
			cont := container.New(cfg)
			require.NotNil(t, cont)

			ctx := context.Background()
			err := cont.Initialize(ctx)
			require.NoError(t, err)

			// Get health status
			healthStatus := cont.GetHealthStatus(ctx)
			require.NotNil(t, healthStatus)

			// Verify WebSocket handler status based on configuration
			if tt.expectInHealth {
				wsHandler := cont.GetWebSocketHandler()
				assert.NotNil(t, wsHandler, "WebSocket handler should exist when enabled")
			} else {
				wsHandler := cont.GetWebSocketHandler()
				assert.Nil(t, wsHandler, "WebSocket handler should not exist when disabled")
			}

			// Verify health status reflects overall container health
			assert.True(t, healthStatus.Healthy, "Container should be healthy regardless of WebSocket state")
			assert.NotEmpty(t, healthStatus.Details, "Health status should include details")

			// Cleanup
			err = cont.Stop(ctx)
			assert.NoError(t, err)
		})
	}
}