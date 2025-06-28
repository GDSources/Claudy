package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"claudy/internal/config"
	"claudy/internal/container"
)

// createTestKeysForHealthCheck generates temporary RSA key pair for health check testing
func createTestKeysForHealthCheck(t *testing.T) (privateKeyPath, publicKeyPath string, cleanup func()) {
	tempDir, err := ioutil.TempDir("", "claudy-health-test-keys-")
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

// createTestConfigForHealthCheck creates a valid test configuration for health check testing
func createTestConfigForHealthCheck(t *testing.T, websocketEnabled bool) *config.Config {
	privateKeyPath, publicKeyPath, cleanup := createTestKeysForHealthCheck(t)
	t.Cleanup(cleanup)

	tempWorkspace, err := ioutil.TempDir("", "claudy-health-test-workspace-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tempWorkspace) })

	return &config.Config{
		Environment: config.Development,
		Debug:       true,
		WebSocket: config.WebSocketConfig{
			Enabled:               websocketEnabled,
			Path:                  "/ws",
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

// TestWebSocketHealthCheckIntegration verifies WebSocket status is included in health checks
func TestWebSocketHealthCheckIntegration(t *testing.T) {
	tests := []struct {
		name             string
		websocketEnabled bool
		expectedStatus   string
	}{
		{
			name:             "WebSocket enabled - should show healthy status",
			websocketEnabled: true,
			expectedStatus:   "healthy",
		},
		{
			name:             "WebSocket disabled - should show disabled status",
			websocketEnabled: false,
			expectedStatus:   "disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test configuration
			cfg := createTestConfigForHealthCheck(t, tt.websocketEnabled)

			// Create container
			cont := container.New(cfg)
			require.NotNil(t, cont)

			// Initialize container
			ctx := context.Background()
			err := cont.Initialize(ctx)
			require.NoError(t, err)

			// Get health status
			healthStatus := cont.GetHealthStatus(ctx)
			require.NotNil(t, healthStatus)

			// Verify overall health
			assert.True(t, healthStatus.Healthy, "Container should be healthy")
			assert.NotEmpty(t, healthStatus.Details, "Health status should include details")

			// Verify WebSocket status is included
			wsStatus, exists := healthStatus.Details["websocket_status"]
			assert.True(t, exists, "WebSocket status should be included in health details")
			assert.Equal(t, tt.expectedStatus, wsStatus, "WebSocket status should match expected value")

			// Cleanup
			err = cont.Stop(ctx)
			assert.NoError(t, err)
		})
	}
}

// TestWebSocketSpecificHealthCheck verifies individual WebSocket service health check
func TestWebSocketSpecificHealthCheck(t *testing.T) {
	tests := []struct {
		name             string
		websocketEnabled bool
		expectedHealthy  bool
		expectedMessage  string
	}{
		{
			name:             "WebSocket enabled and initialized - should be healthy",
			websocketEnabled: true,
			expectedHealthy:  true,
			expectedMessage:  "service healthy",
		},
		{
			name:             "WebSocket disabled - should be healthy but disabled",
			websocketEnabled: false,
			expectedHealthy:  true,
			expectedMessage:  "service disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test configuration
			cfg := createTestConfigForHealthCheck(t, tt.websocketEnabled)

			// Create container
			cont := container.New(cfg)
			require.NotNil(t, cont)

			// Initialize container
			ctx := context.Background()
			err := cont.Initialize(ctx)
			require.NoError(t, err)

			// Get specific WebSocket service health
			wsHealth := cont.CheckServiceHealth(ctx, "websocket")
			require.NotNil(t, wsHealth)

			// Verify WebSocket service health
			assert.Equal(t, "websocket", wsHealth.ServiceName, "Service name should be websocket")
			assert.Equal(t, tt.expectedHealthy, wsHealth.Healthy, "WebSocket health should match expected")
			assert.Equal(t, tt.expectedMessage, wsHealth.Message, "WebSocket message should match expected")
			assert.NotEmpty(t, wsHealth.Timestamp, "Health check should include timestamp")

			// Cleanup
			err = cont.Stop(ctx)
			assert.NoError(t, err)
		})
	}
}

// TestWebSocketHealthCheckBeforeInitialization verifies health check before container initialization
func TestWebSocketHealthCheckBeforeInitialization(t *testing.T) {
	// Create test configuration
	cfg := createTestConfigForHealthCheck(t, true)

	// Create container but don't initialize
	cont := container.New(cfg)
	require.NotNil(t, cont)

	ctx := context.Background()

	// Get health status before initialization
	healthStatus := cont.GetHealthStatus(ctx)
	require.NotNil(t, healthStatus)

	// Should be unhealthy before initialization
	assert.False(t, healthStatus.Healthy, "Container should be unhealthy before initialization")
	
	// WebSocket status should not be included before initialization
	_, exists := healthStatus.Details["websocket_status"]
	assert.False(t, exists, "WebSocket status should not be included before initialization")

	// Check specific WebSocket service health before initialization
	wsHealth := cont.CheckServiceHealth(ctx, "websocket")
	require.NotNil(t, wsHealth)

	assert.False(t, wsHealth.Healthy, "WebSocket should be unhealthy before initialization")
	assert.Equal(t, "container not initialized", wsHealth.Message, "Should indicate container not initialized")
}