package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Service provides Redis operations for the application
type Service struct {
	client *redis.Client
	ctx    context.Context
}

// NewService creates a new Redis service instance
func NewService(addr, password string, db int) *Service {
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           db,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     10,
		MinIdleConns: 2,
	})

	return &Service{
		client: rdb,
		ctx:    context.Background(),
	}
}

// IsAvailable checks if Redis service is available
func (s *Service) IsAvailable() bool {
	_, err := s.client.Ping(s.ctx).Result()
	return err == nil
}

// IncrementConnectionCount increments the connection count for a user
func (s *Service) IncrementConnectionCount(userID string) (int, error) {
	key := fmt.Sprintf("connections:%s", userID)
	
	// Use transaction to increment and get the new value
	txf := func(tx *redis.Tx) error {
		return nil
	}

	// Watch the key and execute transaction
	for i := 0; i < 3; i++ { // Retry up to 3 times
		err := s.client.Watch(s.ctx, txf, key)
		if err != nil {
			if err == redis.TxFailedErr {
				continue // Retry on transaction failure
			}
			return 0, fmt.Errorf("failed to watch key: %w", err)
		}

		// Get current value
		current, err := s.client.Get(s.ctx, key).Int()
		if err != nil && err != redis.Nil {
			return 0, fmt.Errorf("failed to get current count: %w", err)
		}
		if err == redis.Nil {
			current = 0
		}

		// Increment
		newVal := current + 1
		
		// Set new value with expiration (1 hour)
		err = s.client.Set(s.ctx, key, newVal, time.Hour).Err()
		if err != nil {
			return 0, fmt.Errorf("failed to set new count: %w", err)
		}

		return newVal, nil
	}

	return 0, fmt.Errorf("failed to increment after retries")
}

// DecrementConnectionCount decrements the connection count for a user
func (s *Service) DecrementConnectionCount(userID string) (int, error) {
	key := fmt.Sprintf("connections:%s", userID)
	
	// Get current value
	current, err := s.client.Get(s.ctx, key).Int()
	if err != nil {
		if err == redis.Nil {
			return 0, nil // Already at 0
		}
		return 0, fmt.Errorf("failed to get current count: %w", err)
	}

	newVal := current - 1
	if newVal <= 0 {
		// Delete the key if count reaches 0
		err = s.client.Del(s.ctx, key).Err()
		if err != nil {
			return 0, fmt.Errorf("failed to delete key: %w", err)
		}
		return 0, nil
	}

	// Set new value with expiration (1 hour)
	err = s.client.Set(s.ctx, key, newVal, time.Hour).Err()
	if err != nil {
		return 0, fmt.Errorf("failed to set new count: %w", err)
	}

	return newVal, nil
}

// GetConnectionCount gets the current connection count for a user
func (s *Service) GetConnectionCount(userID string) (int, error) {
	key := fmt.Sprintf("connections:%s", userID)
	
	count, err := s.client.Get(s.ctx, key).Int()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to get connection count: %w", err)
	}

	return count, nil
}

// SetConnectionCount sets the connection count for a user
func (s *Service) SetConnectionCount(userID string, count int) error {
	key := fmt.Sprintf("connections:%s", userID)
	
	if count <= 0 {
		return s.client.Del(s.ctx, key).Err()
	}

	return s.client.Set(s.ctx, key, count, time.Hour).Err()
}

// StoreSessionData stores session data in Redis
func (s *Service) StoreSessionData(sessionID string, data map[string]interface{}) error {
	key := fmt.Sprintf("session:%s", sessionID)
	
	return s.client.HMSet(s.ctx, key, data).Err()
}

// GetSessionData retrieves session data from Redis
func (s *Service) GetSessionData(sessionID string) (map[string]string, error) {
	key := fmt.Sprintf("session:%s", sessionID)
	
	data, err := s.client.HGetAll(s.ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get session data: %w", err)
	}

	return data, nil
}

// DeleteSessionData removes session data from Redis
func (s *Service) DeleteSessionData(sessionID string) error {
	key := fmt.Sprintf("session:%s", sessionID)
	
	return s.client.Del(s.ctx, key).Err()
}

// SetSessionExpiry sets expiration time for session data
func (s *Service) SetSessionExpiry(sessionID string, expiry time.Duration) error {
	key := fmt.Sprintf("session:%s", sessionID)
	
	return s.client.Expire(s.ctx, key, expiry).Err()
}

// Close closes the Redis connection
func (s *Service) Close() error {
	return s.client.Close()
}

// GetClient returns the underlying Redis client for advanced operations
func (s *Service) GetClient() *redis.Client {
	return s.client
}

// FlushAll clears all data in the Redis database (for testing only)
func (s *Service) FlushAll() error {
	return s.client.FlushAll(s.ctx).Err()
}

// Ping tests connectivity to Redis
func (s *Service) Ping() error {
	return s.client.Ping(s.ctx).Err()
}