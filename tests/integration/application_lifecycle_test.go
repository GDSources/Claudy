package integration

import (
	"context"
	"encoding/json"
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

	"claudy/internal/server"
)

// TestApplicationLifecycle tests the complete application lifecycle from startup to shutdown
func TestApplicationLifecycle(t *testing.T) {
	// Skip if running in environments where Docker is not available
	if os.Getenv("SKIP_INTEGRATION") == "true" {
		t.Skip("Integration tests skipped")
	}

	ctx := context.Background()

	// Setup test containers
	containers, config, err := setupTestInfrastructure(ctx)
	require.NoError(t, err, "Should setup test infrastructure")
	defer cleanupTestInfrastructure(ctx, containers)

	// Set environment variables for the test application
	setTestEnvironment(config)
	defer cleanupTestEnvironment()

	t.Run("complete_application_lifecycle", func(t *testing.T) {
		// Create server instance
		app := server.NewServer()
		require.NotNil(t, app, "Application should be created")

		// Test 1: Application startup
		var startupErr error
		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			defer wg.Done()
			startupErr = app.Start()
		}()

		// Wait for application to be ready
		baseURL := fmt.Sprintf("http://localhost:%s", config.Port)
		ready := waitForApplicationReady(baseURL, 30*time.Second)
		require.True(t, ready, "Application should start and be ready")

		// Test 2: Health endpoint validation
		healthResp, err := http.Get(baseURL + "/health")
		require.NoError(t, err, "Health endpoint should be accessible")
		assert.Equal(t, http.StatusOK, healthResp.StatusCode, "Health endpoint should return OK")

		var healthData map[string]interface{}
		json.NewDecoder(healthResp.Body).Decode(&healthData)
		healthResp.Body.Close()

		assert.Equal(t, "healthy", healthData["status"], "Application should be healthy")
		assert.NotEmpty(t, healthData["timestamp"], "Health response should include timestamp")
		assert.Equal(t, "1.0.0", healthData["version"], "Health response should include version")

		// Test 3: API endpoint validation
		statusResp, err := http.Get(baseURL + "/api/v1/status")
		require.NoError(t, err, "Status endpoint should be accessible")
		assert.Equal(t, http.StatusOK, statusResp.StatusCode, "Status endpoint should return OK")

		var statusData map[string]interface{}
		json.NewDecoder(statusResp.Body).Decode(&statusData)
		statusResp.Body.Close()

		assert.Equal(t, "claudy-backend", statusData["service"], "Should return correct service name")
		assert.Equal(t, "1.0.0", statusData["version"], "Should return correct version")
		assert.Equal(t, "test", statusData["environment"], "Should return test environment")

		// Test 4: CORS middleware functionality
		corsReq, _ := http.NewRequest("OPTIONS", baseURL+"/api/v1/status", nil)
		corsReq.Header.Set("Origin", "https://app.claudy.dev")
		corsReq.Header.Set("Access-Control-Request-Method", "GET")

		client := &http.Client{}
		corsResp, err := client.Do(corsReq)
		require.NoError(t, err, "CORS preflight should work")
		assert.Equal(t, http.StatusNoContent, corsResp.StatusCode, "CORS preflight should return 204")
		assert.NotEmpty(t, corsResp.Header.Get("Access-Control-Allow-Origin"), "Should set CORS headers")
		corsResp.Body.Close()

		// Test 5: Rate limiting middleware functionality
		rateLimitTests := []struct {
			name     string
			requests int
			expect   int
		}{
			{"within_limit", 3, http.StatusOK},
			{"exceeds_burst", 25, http.StatusTooManyRequests},
		}

		for _, tt := range rateLimitTests {
			t.Run(tt.name, func(t *testing.T) {
				var lastStatus int
				for i := 0; i < tt.requests; i++ {
					resp, err := http.Get(baseURL + "/api/v1/status")
					if err == nil {
						lastStatus = resp.StatusCode
						resp.Body.Close()
					}
				}
				if tt.expect == http.StatusTooManyRequests {
					assert.Equal(t, tt.expect, lastStatus, "Should be rate limited after many requests")
				} else {
					assert.Equal(t, tt.expect, lastStatus, "Should allow requests within limit")
				}
			})
		}

		// Test 6: Security headers validation
		securityResp, err := http.Get(baseURL + "/api/v1/status")
		require.NoError(t, err, "Should be able to make request for security headers")
		assert.NotEmpty(t, securityResp.Header.Get("Content-Security-Policy"), "Should set CSP header")
		assert.NotEmpty(t, securityResp.Header.Get("X-Frame-Options"), "Should set X-Frame-Options")
		assert.NotEmpty(t, securityResp.Header.Get("X-Content-Type-Options"), "Should set X-Content-Type-Options")
		securityResp.Body.Close()

		// Test 7: Database connectivity through health endpoint
		// The health endpoint should reflect database connection status
		time.Sleep(1 * time.Second) // Allow time for health checks to run
		dbHealthResp, err := http.Get(baseURL + "/health")
		require.NoError(t, err, "Should be able to check database health")
		
		var dbHealthData map[string]interface{}
		json.NewDecoder(dbHealthResp.Body).Decode(&dbHealthData)
		dbHealthResp.Body.Close()
		
		assert.Equal(t, "healthy", dbHealthData["status"], "Application with databases should be healthy")

		// Test 8: Load testing with concurrent requests
		t.Run("concurrent_load_test", func(t *testing.T) {
			const numGoroutines = 50
			const requestsPerGoroutine = 5
			var loadWg sync.WaitGroup
			results := make(chan int, numGoroutines*requestsPerGoroutine)

			for i := 0; i < numGoroutines; i++ {
				loadWg.Add(1)
				go func() {
					defer loadWg.Done()
					for j := 0; j < requestsPerGoroutine; j++ {
						resp, err := http.Get(baseURL + "/health")
						if err == nil {
							results <- resp.StatusCode
							resp.Body.Close()
						} else {
							results <- 0 // Error case
						}
					}
				}()
			}

			loadWg.Wait()
			close(results)

			successCount := 0
			totalRequests := 0
			for status := range results {
				totalRequests++
				if status == http.StatusOK {
					successCount++
				}
			}

			successRate := float64(successCount) / float64(totalRequests)
			assert.Greater(t, successRate, 0.9, "Should handle concurrent load with >90% success rate")
			assert.Equal(t, numGoroutines*requestsPerGoroutine, totalRequests, "Should process all requests")
		})

		// Test 9: Graceful shutdown testing
		t.Run("graceful_shutdown", func(t *testing.T) {
			// Start a slow request before shutdown
			slowDone := make(chan bool, 1)
			go func() {
				resp, err := http.Get(baseURL + "/api/slow")
				if err == nil {
					resp.Body.Close()
				}
				slowDone <- true
			}()

			// Give slow request time to start
			time.Sleep(500 * time.Millisecond)

			// Initiate graceful shutdown
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			shutdownStart := time.Now()
			shutdownErr := app.Shutdown(shutdownCtx)
			shutdownDuration := time.Since(shutdownStart)

			assert.NoError(t, shutdownErr, "Should shutdown gracefully")
			assert.Less(t, shutdownDuration, 10*time.Second, "Should shutdown within timeout")

			// Wait for slow request to complete
			select {
			case <-slowDone:
				// Good - slow request completed
			case <-time.After(5 * time.Second):
				t.Log("Slow request didn't complete within timeout - may be expected during shutdown")
			}

			// Verify server is no longer accepting connections
			time.Sleep(100 * time.Millisecond)
			_, err := http.Get(baseURL + "/health")
			assert.Error(t, err, "Server should no longer accept connections after shutdown")
		})

		// Wait for startup goroutine to complete
		wg.Wait()

		// Check startup error
		if startupErr != nil {
			assert.Contains(t, startupErr.Error(), "server closed", "Startup should end with server closed")
		}
	})
}

// TestApplicationErrorScenarios tests error handling in various failure scenarios
func TestApplicationErrorScenarios(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION") == "true" {
		t.Skip("Integration tests skipped")
	}

	t.Run("invalid_configuration", func(t *testing.T) {
		// Test with invalid port configuration
		os.Setenv("PORT", "99999")
		os.Setenv("ENV", "test")
		defer func() {
			os.Unsetenv("PORT")
			os.Unsetenv("ENV")
		}()

		app := server.NewServer()
		require.NotNil(t, app, "Should create app even with invalid config")

		// Should use default port instead of invalid one
		assert.NotEqual(t, "99999", app.GetPort(), "Should not use invalid port")
	})

	t.Run("database_connection_failure", func(t *testing.T) {
		// Test with invalid database configuration
		os.Setenv("MONGO_URI", "mongodb://invalid-host:27017")
		os.Setenv("REDIS_ADDR", "invalid-host:6379")
		os.Setenv("PORT", "8095")
		os.Setenv("ENV", "test")
		defer func() {
			os.Unsetenv("MONGO_URI")
			os.Unsetenv("REDIS_ADDR")
			os.Unsetenv("PORT")
			os.Unsetenv("ENV")
		}()

		app := server.NewServer()
		require.NotNil(t, app, "Should create app even with invalid DB config")

		// Starting should fail due to database connection issues
		err := app.Start()
		assert.Error(t, err, "Should fail to start with invalid database configuration")
		assert.Contains(t, err.Error(), "initialize", "Error should mention initialization failure")
	})
}

// Helper functions

type TestConfig struct {
	Port      string
	MongoURI  string
	RedisAddr string
}

type TestContainers struct {
	MongoDB testcontainers.Container
	Redis   testcontainers.Container
}

func setupTestInfrastructure(ctx context.Context) (*TestContainers, *TestConfig, error) {
	// Start MongoDB container
	mongoContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "mongo:7.0",
			ExposedPorts: []string{"27017/tcp"},
			WaitingFor:   wait.ForLog("Waiting for connections").WithStartupTimeout(60 * time.Second),
			Env: map[string]string{
				"MONGO_INITDB_ROOT_USERNAME": "root",
				"MONGO_INITDB_ROOT_PASSWORD": "password",
			},
		},
		Started: true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start MongoDB container: %w", err)
	}

	// Start Redis container
	redisContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "redis:7.0",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		mongoContainer.Terminate(ctx)
		return nil, nil, fmt.Errorf("failed to start Redis container: %w", err)
	}

	// Get connection details
	mongoHost, _ := mongoContainer.Host(ctx)
	mongoPort, _ := mongoContainer.MappedPort(ctx, "27017")
	mongoURI := fmt.Sprintf("mongodb://root:password@%s:%s/claudy_test?authSource=admin", mongoHost, mongoPort.Port())

	redisHost, _ := redisContainer.Host(ctx)
	redisPort, _ := redisContainer.MappedPort(ctx, "6379")
	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort.Port())

	containers := &TestContainers{
		MongoDB: mongoContainer,
		Redis:   redisContainer,
	}

	config := &TestConfig{
		Port:      "8091",
		MongoURI:  mongoURI,
		RedisAddr: redisAddr,
	}

	return containers, config, nil
}

func cleanupTestInfrastructure(ctx context.Context, containers *TestContainers) {
	if containers.MongoDB != nil {
		containers.MongoDB.Terminate(ctx)
	}
	if containers.Redis != nil {
		containers.Redis.Terminate(ctx)
	}
}

func setTestEnvironment(config *TestConfig) {
	os.Setenv("PORT", config.Port)
	os.Setenv("ENV", "test")
	os.Setenv("MONGO_URI", config.MongoURI)
	os.Setenv("REDIS_ADDR", config.RedisAddr)
}

func cleanupTestEnvironment() {
	os.Unsetenv("PORT")
	os.Unsetenv("ENV")
	os.Unsetenv("MONGO_URI")
	os.Unsetenv("REDIS_ADDR")
}

func waitForApplicationReady(baseURL string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return true
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}