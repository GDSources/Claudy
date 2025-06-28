package server

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerUnit(t *testing.T) {
	t.Run("server_creation", func(t *testing.T) {
		// Set test environment
		os.Setenv("ENV", "test")
		os.Setenv("PORT", "8082")
		defer func() {
			os.Unsetenv("ENV")
			os.Unsetenv("PORT")
		}()

		server := NewServer()
		require.NotNil(t, server, "Server should be created")
		
		assert.Equal(t, "8082", server.GetPort(), "Should use configured port")
		assert.Equal(t, "test", server.GetEnvironment(), "Should use test environment")
		assert.NotNil(t, server.GetRouter(), "Should have router")
		assert.NotNil(t, server.GetContainer(), "Should have container")
	})

	t.Run("port_validation", func(t *testing.T) {
		tests := []struct {
			port     string
			expected bool
		}{
			{"8080", true},
			{"3000", true},
			{"65535", true},
			{"0", false},
			{"65536", false},
			{"invalid", false},
			{"", false},
		}

		for _, tt := range tests {
			t.Run(tt.port, func(t *testing.T) {
				result := isValidPort(tt.port)
				assert.Equal(t, tt.expected, result, "Port validation should match expected")
			})
		}
	})

	t.Run("environment_helper", func(t *testing.T) {
		os.Setenv("TEST_VAR", "test_value")
		defer os.Unsetenv("TEST_VAR")

		assert.Equal(t, "test_value", getEnvOrDefault("TEST_VAR", "default"), "Should return env value")
		assert.Equal(t, "default", getEnvOrDefault("NON_EXISTENT", "default"), "Should return default")
	})

	t.Run("shutdown_without_start", func(t *testing.T) {
		server := NewServer()
		
		ctx := context.Background()
		err := server.Shutdown(ctx)
		assert.NoError(t, err, "Should handle shutdown of non-started server")
	})

	t.Run("router_routes_configuration", func(t *testing.T) {
		server := NewServer()
		router := server.GetRouter()
		
		routes := router.Routes()
		assert.NotEmpty(t, routes, "Should have routes configured")
		
		// Check for health endpoint
		var hasHealthRoute bool
		for _, route := range routes {
			if route.Path == "/health" && route.Method == "GET" {
				hasHealthRoute = true
				break
			}
		}
		assert.True(t, hasHealthRoute, "Should have health endpoint")
	})

	t.Run("invalid_port_defaults_to_8080", func(t *testing.T) {
		os.Setenv("PORT", "99999") // Invalid port
		os.Setenv("ENV", "test")
		defer func() {
			os.Unsetenv("PORT")
			os.Unsetenv("ENV")
		}()

		server := NewServer()
		assert.Equal(t, "8080", server.GetPort(), "Should default to 8080 for invalid port")
	})
}

func TestServerLifecycle(t *testing.T) {
	// This test verifies the server can start and stop without external dependencies
	// It uses mocked/default configurations to avoid needing real databases
	
	t.Run("server_startup_and_shutdown", func(t *testing.T) {
		// Use test environment with minimal config
		os.Setenv("ENV", "test")
		os.Setenv("PORT", "8083")
		os.Setenv("MONGO_URI", "mongodb://localhost:27017") // Will fail to connect, but that's ok for this test
		os.Setenv("REDIS_ADDR", "localhost:6379")           // Will fail to connect, but that's ok for this test
		defer func() {
			os.Unsetenv("ENV")
			os.Unsetenv("PORT")
			os.Unsetenv("MONGO_URI")
			os.Unsetenv("REDIS_ADDR")
		}()

		server := NewServer()
		require.NotNil(t, server, "Server should be created")

		// Test that we can create a server instance successfully
		// We won't actually start it since that would require real databases
		// But we can verify the configuration is correct
		assert.Equal(t, "8083", server.GetPort(), "Should use configured port")
		assert.Equal(t, "test", server.GetEnvironment(), "Should use test environment")
		
		// Test graceful shutdown of non-started server
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		err := server.Shutdown(ctx)
		assert.NoError(t, err, "Should shutdown gracefully even when not started")
	})

	t.Run("multiple_shutdown_calls", func(t *testing.T) {
		server := NewServer()
		
		ctx := context.Background()
		err1 := server.Shutdown(ctx)
		err2 := server.Shutdown(ctx)
		
		assert.NoError(t, err1, "First shutdown should succeed")
		assert.NoError(t, err2, "Second shutdown should also succeed")
	})
}