package websocket

import (
	"net/http"
	"time"

	"claudy/internal/auth"
)

// ExampleRedisService provides a simple example of the Redis service interface
type ExampleRedisService struct {
	connectionCounts map[string]int
}

func NewExampleRedisService() *ExampleRedisService {
	return &ExampleRedisService{
		connectionCounts: make(map[string]int),
	}
}

func (r *ExampleRedisService) IncrementConnectionCount(userID string) (int, error) {
	r.connectionCounts[userID]++
	return r.connectionCounts[userID], nil
}

func (r *ExampleRedisService) DecrementConnectionCount(userID string) (int, error) {
	if r.connectionCounts[userID] > 0 {
		r.connectionCounts[userID]--
	}
	return r.connectionCounts[userID], nil
}

func (r *ExampleRedisService) GetConnectionCount(userID string) (int, error) {
	return r.connectionCounts[userID], nil
}

func (r *ExampleRedisService) SetConnectionCount(userID string, count int) error {
	r.connectionCounts[userID] = count
	return nil
}

func (r *ExampleRedisService) IsAvailable() bool {
	return true
}

// ExampleUsage demonstrates how to set up and use the WebSocket handler
func ExampleUsage(jwtService *auth.JWTService) *Handler {
	// Create Redis service (in production, use real Redis)
	redisService := NewExampleRedisService()

	// Configure WebSocket handler
	config := Config{
		MaxConnectionsPerUser: 3,
		AllowedOrigins:       []string{"http://localhost:3000", "https://yourapp.com"},
		ReadTimeout:          30 * time.Second,
		WriteTimeout:         30 * time.Second,
		PingInterval:         54 * time.Second,
	}

	// Create handler
	handler := NewHandler(jwtService, redisService, config)

	// In your HTTP server setup:
	// http.HandleFunc("/ws", handler.HandleWebSocket)

	return handler
}

// ExampleHTTPServer shows how to integrate the WebSocket handler into an HTTP server
func ExampleHTTPServer(jwtService *auth.JWTService) {
	handler := ExampleUsage(jwtService)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", handler.HandleWebSocket)

	// Start server
	// server := &http.Server{
	//     Addr:    ":8080",
	//     Handler: mux,
	// }
	// log.Fatal(server.ListenAndServe())
}