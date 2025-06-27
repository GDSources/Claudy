package container

import (
	"context"
	"sync"
)

// HealthChecker manages health checks for all services
type HealthChecker struct {
	checks map[string]HealthCheckFunc
	mu     sync.RWMutex
}

// HealthCheckFunc is a function that performs a health check.
// Should return nil if healthy, error if unhealthy.
type HealthCheckFunc func(ctx context.Context) error

// NewHealthChecker creates a new health checker with empty registry.
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		checks: make(map[string]HealthCheckFunc),
	}
}

// RegisterCheck registers a health check for a service.
// Will replace existing check if name already exists.
func (h *HealthChecker) RegisterCheck(name string, checkFunc HealthCheckFunc) {
	if name == "" {
		panic("health check name cannot be empty")
	}
	if checkFunc == nil {
		panic("health check function cannot be nil")
	}
	
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[name] = checkFunc
}