package main

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerUnitTests(t *testing.T) {
	// Unit tests for server configuration and basic functionality

	t.Run("server_initialization", func(t *testing.T) {
		// Set test environment variables
		os.Setenv("PORT", "8081")
		os.Setenv("ENV", "test")
		defer func() {
			os.Unsetenv("PORT")
			os.Unsetenv("ENV")
		}()

		server := NewServer()
		require.NotNil(t, server, "Server should be created successfully")
		
		// Verify server configuration
		assert.Equal(t, "8081", server.GetPort(), "Should use configured port")
		assert.Equal(t, "test", server.GetEnvironment(), "Should use configured environment")
		assert.NotNil(t, server.GetRouter(), "Should have router configured")
		assert.NotNil(t, server.GetContainer(), "Should have dependency container")
	})

	t.Run("configuration_validation", func(t *testing.T) {
		// Test configuration validation
		os.Setenv("PORT", "invalid")
		defer os.Unsetenv("PORT")

		server := NewServer()
		
		// Should handle invalid configuration gracefully
		assert.NotNil(t, server, "Should create server even with invalid config")
		
		// Should use default port when invalid port is provided
		defaultPort := server.GetPort()
		assert.NotEqual(t, "invalid", defaultPort, "Should not use invalid port")
		assert.Regexp(t, `^\d+$`, defaultPort, "Should use numeric port")
	})

	t.Run("port_validation", func(t *testing.T) {
		// Test port validation function
		assert.True(t, isValidPort("8080"), "8080 should be valid")
		assert.True(t, isValidPort("3000"), "3000 should be valid")
		assert.True(t, isValidPort("65535"), "65535 should be valid")
		assert.False(t, isValidPort("0"), "0 should be invalid")
		assert.False(t, isValidPort("65536"), "65536 should be invalid")
		assert.False(t, isValidPort("invalid"), "non-numeric should be invalid")
		assert.False(t, isValidPort(""), "empty should be invalid")
	})

	t.Run("environment_configuration", func(t *testing.T) {
		tests := []struct {
			env      string
			expected string
		}{
			{"production", "production"},
			{"development", "development"},
			{"test", "test"},
			{"", "development"}, // default
		}

		for _, tt := range tests {
			t.Run(tt.env, func(t *testing.T) {
				os.Setenv("ENV", tt.env)
				defer os.Unsetenv("ENV")

				server := NewServer()
				assert.Equal(t, tt.expected, server.GetEnvironment(), "Should use correct environment")
			})
		}
	})

	t.Run("multiple_shutdown_calls", func(t *testing.T) {
		// Test that multiple shutdown calls are handled gracefully
		server := NewServer()
		require.NotNil(t, server, "Server should be created")

		// Call shutdown on non-started server (should be safe)
		ctx := context.Background()
		err1 := server.Shutdown(ctx)
		err2 := server.Shutdown(ctx)
		
		assert.NoError(t, err1, "First shutdown should succeed")
		assert.NoError(t, err2, "Second shutdown should also succeed (no-op)")
	})

	t.Run("router_configuration", func(t *testing.T) {
		// Test that router is properly configured with routes
		server := NewServer()
		require.NotNil(t, server, "Server should be created")
		
		router := server.GetRouter()
		require.NotNil(t, router, "Router should be configured")

		// Check that routes are configured (basic verification)
		routes := router.Routes()
		assert.NotEmpty(t, routes, "Router should have routes configured")
		
		// Check for health endpoint
		var hasHealthRoute bool
		for _, route := range routes {
			if route.Path == "/health" && route.Method == "GET" {
				hasHealthRoute = true
				break
			}
		}
		assert.True(t, hasHealthRoute, "Should have health endpoint configured")
	})

	t.Run("env_helper_function", func(t *testing.T) {
		// Test getEnvOrDefault helper function
		os.Setenv("TEST_VAR", "test_value")
		defer os.Unsetenv("TEST_VAR")

		assert.Equal(t, "test_value", getEnvOrDefault("TEST_VAR", "default"), "Should return env value")
		assert.Equal(t, "default", getEnvOrDefault("NON_EXISTENT", "default"), "Should return default")
		assert.Equal(t, "", getEnvOrDefault("NON_EXISTENT", ""), "Should return empty default")
	})
}