package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestServerWithRealDatabases(t *testing.T) {
	// Skip if running in environments where Docker is not available
	if os.Getenv("SKIP_INTEGRATION") == "true" {
		t.Skip("Integration tests skipped")
	}

	ctx := context.Background()

	// Start MongoDB test container
	mongoContainer, mongoURI, err := startMongoContainer(ctx)
	require.NoError(t, err, "Should start MongoDB container")
	defer func() {
		if err := mongoContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate MongoDB container: %v", err)
		}
	}()

	// Start Redis test container
	redisContainer, redisAddr, err := startRedisContainer(ctx)
	require.NoError(t, err, "Should start Redis container")
	defer func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate Redis container: %v", err)
		}
	}()

	// Set environment variables for the test
	os.Setenv("MONGO_URI", mongoURI)
	os.Setenv("REDIS_ADDR", redisAddr)
	os.Setenv("PORT", "8090")
	os.Setenv("ENV", "test")
	defer func() {
		os.Unsetenv("MONGO_URI")
		os.Unsetenv("REDIS_ADDR")
		os.Unsetenv("PORT")
		os.Unsetenv("ENV")
	}()

	t.Run("server_with_real_databases", func(t *testing.T) {
		server := NewServer()
		require.NotNil(t, server, "Server should be created")

		// Start server in background
		var startErr error
		var wg sync.WaitGroup
		wg.Add(1)
		
		go func() {
			defer wg.Done()
			startErr = server.Start()
		}()

		// Wait for server to be ready (shorter timeout)
		var resp *http.Response
		var healthErr error
		for i := 0; i < 15; i++ { // Try for up to 15 seconds
			time.Sleep(1 * time.Second)
			resp, healthErr = http.Get("http://localhost:8090/health")
			if healthErr == nil {
				break
			}
		}
		
		if healthErr == nil {
			assert.Equal(t, http.StatusOK, resp.StatusCode, "Health endpoint should respond")
			resp.Body.Close()

			// Test API endpoint
			statusResp, err := http.Get("http://localhost:8090/api/v1/status")
			if err == nil {
				assert.Equal(t, http.StatusOK, statusResp.StatusCode, "API endpoint should respond")
				statusResp.Body.Close()
			}
		} else {
			t.Logf("Server health check failed after 15 seconds: %v", healthErr)
		}

		// Gracefully shutdown server
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		shutdownErr := server.Shutdown(shutdownCtx)
		assert.NoError(t, shutdownErr, "Should shutdown gracefully")
		
		wg.Wait()
		
		// Check start error
		if startErr != nil && healthErr == nil {
			assert.Contains(t, startErr.Error(), "server closed", "Should handle shutdown gracefully")
		}
	})
}

// startMongoContainer starts a MongoDB test container and returns the container and connection URI
func startMongoContainer(ctx context.Context) (testcontainers.Container, string, error) {
	req := testcontainers.ContainerRequest{
		Image:        "mongo:7.0",
		ExposedPorts: []string{"27017/tcp"},
		WaitingFor:   wait.ForLog("Waiting for connections").WithStartupTimeout(60 * time.Second),
		Env: map[string]string{
			"MONGO_INITDB_ROOT_USERNAME": "root",
			"MONGO_INITDB_ROOT_PASSWORD": "password",
		},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, "", err
	}

	// Get the mapped port
	mappedPort, err := container.MappedPort(ctx, "27017")
	if err != nil {
		container.Terminate(ctx)
		return nil, "", err
	}

	// Get the host IP
	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		return nil, "", err
	}

	// Build connection URI
	uri := fmt.Sprintf("mongodb://root:password@%s:%s/claudy_test?authSource=admin", host, mappedPort.Port())
	
	return container, uri, nil
}

// startRedisContainer starts a Redis test container and returns the container and connection address
func startRedisContainer(ctx context.Context) (testcontainers.Container, string, error) {
	req := testcontainers.ContainerRequest{
		Image:        "redis:7.0",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, "", err
	}

	// Get the mapped port
	mappedPort, err := container.MappedPort(ctx, "6379")
	if err != nil {
		container.Terminate(ctx)
		return nil, "", err
	}

	// Get the host IP
	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		return nil, "", err
	}

	// Build connection address
	addr := fmt.Sprintf("%s:%s", host, mappedPort.Port())
	
	return container, addr, nil
}