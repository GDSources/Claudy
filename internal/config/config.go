package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

// Environment represents the application environment
type Environment string

const (
	Development Environment = "development"
	Staging     Environment = "staging"
	Production  Environment = "production"
)

// Config holds all configuration for the Claudy application
type Config struct {
	// Environment and basic settings
	Environment Environment `mapstructure:"environment"`
	Debug       bool        `mapstructure:"debug"`
	
	// Server configuration
	Server ServerConfig `mapstructure:"server"`
	
	// Database configuration
	Database DatabaseConfig `mapstructure:"database"`
	
	// Redis configuration
	Redis RedisConfig `mapstructure:"redis"`
	
	// JWT configuration
	JWT JWTConfig `mapstructure:"jwt"`
	
	// Claude Code configuration
	Claude ClaudeConfig `mapstructure:"claude"`
	
	// Security configuration
	Security SecurityConfig `mapstructure:"security"`
	
	// Monitoring configuration
	Monitoring MonitoringConfig `mapstructure:"monitoring"`
	
	// Rate limiting configuration
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
	
	// WebSocket configuration
	WebSocket WebSocketConfig `mapstructure:"websocket"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Host              string        `mapstructure:"host"`
	Port              int           `mapstructure:"port"`
	ReadTimeout       time.Duration `mapstructure:"read_timeout"`
	WriteTimeout      time.Duration `mapstructure:"write_timeout"`
	IdleTimeout       time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout   time.Duration `mapstructure:"shutdown_timeout"`
	MaxHeaderBytes    int           `mapstructure:"max_header_bytes"`
	TLS               TLSConfig     `mapstructure:"tls"`
	AllowedOrigins    []string      `mapstructure:"allowed_origins"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// DatabaseConfig holds MongoDB configuration
type DatabaseConfig struct {
	URI             string        `mapstructure:"uri"`
	Database        string        `mapstructure:"database"`
	ConnectTimeout  time.Duration `mapstructure:"connect_timeout"`
	QueryTimeout    time.Duration `mapstructure:"query_timeout"`
	MaxPoolSize     uint64        `mapstructure:"max_pool_size"`
	MinPoolSize     uint64        `mapstructure:"min_pool_size"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Addr         string        `mapstructure:"addr"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	PrivateKeyPath string        `mapstructure:"private_key_path"`
	PublicKeyPath  string        `mapstructure:"public_key_path"`
	Issuer         string        `mapstructure:"issuer"`
	ExpiryDuration time.Duration `mapstructure:"expiry_duration"`
}

// ClaudeConfig holds Claude Code configuration
type ClaudeConfig struct {
	APIBaseURL          string        `mapstructure:"api_base_url"`
	CodePath            string        `mapstructure:"code_path"`
	WorkspaceBasePath   string        `mapstructure:"workspace_base_path"`
	MaxSessionDuration  time.Duration `mapstructure:"max_session_duration"`
	SessionCleanupInterval time.Duration `mapstructure:"session_cleanup_interval"`
	MaxWorkspaceSize    int64         `mapstructure:"max_workspace_size"`
	MaxFileSize         int64         `mapstructure:"max_file_size"`
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	EncryptionKey     string `mapstructure:"encryption_key"`
	CSPPolicy         string `mapstructure:"csp_policy"`
	HSTSMaxAge        int    `mapstructure:"hsts_max_age"`
	EnableHSTS        bool   `mapstructure:"enable_hsts"`
	EnableCSP         bool   `mapstructure:"enable_csp"`
	EnableFrameDeny   bool   `mapstructure:"enable_frame_deny"`
}

// MonitoringConfig holds monitoring configuration
type MonitoringConfig struct {
	Enabled            bool   `mapstructure:"enabled"`
	MetricsPath        string `mapstructure:"metrics_path"`
	HealthPath         string `mapstructure:"health_path"`
	ReadinessPath      string `mapstructure:"readiness_path"`
	EnableRequestLogging bool  `mapstructure:"enable_request_logging"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled    bool    `mapstructure:"enabled"`
	RequestsPerSecond float64 `mapstructure:"requests_per_second"`
	BurstSize  int     `mapstructure:"burst_size"`
	KeyFunc    string  `mapstructure:"key_func"` // "ip", "user", "custom"
}

// WebSocketConfig holds WebSocket server configuration
type WebSocketConfig struct {
	Enabled               bool          `mapstructure:"enabled"`
	Path                  string        `mapstructure:"path"`
	MaxConnectionsPerUser int           `mapstructure:"max_connections_per_user"`
	AllowedOrigins        []string      `mapstructure:"allowed_origins"`
	ReadTimeout           time.Duration `mapstructure:"read_timeout"`
	WriteTimeout          time.Duration `mapstructure:"write_timeout"`
	PingInterval          time.Duration `mapstructure:"ping_interval"`
	BufferSize            int           `mapstructure:"buffer_size"`
}

// Load loads configuration from environment variables, .env files, and CLI flags
func Load() (*Config, error) {
	// Initialize viper
	v := viper.New()
	
	// Set configuration file name and type
	v.SetConfigName(".env")
	v.SetConfigType("env")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")
	
	// Enable environment variable binding
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	
	// Try to load .env file (it's OK if it doesn't exist)
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}
	
	// Try to read config file (optional)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}
	
	// Set defaults
	setDefaults(v)
	
	// Unmarshal into config struct
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}
	
	// Validate configuration
	if err := ValidateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}
	
	return &cfg, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Environment defaults
	v.SetDefault("environment", string(Development))
	v.SetDefault("debug", false)
	
	// Server defaults
	v.SetDefault("server.host", "localhost")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("server.idle_timeout", "120s")
	v.SetDefault("server.shutdown_timeout", "30s")
	v.SetDefault("server.max_header_bytes", 1048576) // 1MB
	v.SetDefault("server.tls.enabled", false)
	v.SetDefault("server.allowed_origins", []string{"http://localhost:3000"})
	
	// Database defaults
	v.SetDefault("database.uri", "mongodb://localhost:27017")
	v.SetDefault("database.database", "claudy")
	v.SetDefault("database.connect_timeout", "10s")
	v.SetDefault("database.query_timeout", "30s")
	v.SetDefault("database.max_pool_size", 100)
	v.SetDefault("database.min_pool_size", 5)
	
	// Redis defaults
	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.dial_timeout", "5s")
	v.SetDefault("redis.read_timeout", "3s")
	v.SetDefault("redis.write_timeout", "3s")
	v.SetDefault("redis.pool_size", 10)
	v.SetDefault("redis.min_idle_conns", 2)
	
	// JWT defaults
	v.SetDefault("jwt.private_key_path", "./keys/jwt_private_key.pem")
	v.SetDefault("jwt.public_key_path", "./keys/jwt_public_key.pem")
	v.SetDefault("jwt.issuer", "claudy")
	v.SetDefault("jwt.expiry_duration", "24h")
	
	// Claude defaults
	v.SetDefault("claude.api_base_url", "https://api.anthropic.com")
	v.SetDefault("claude.code_path", "claude-code")
	v.SetDefault("claude.workspace_base_path", "/tmp/claudy-workspaces")
	v.SetDefault("claude.max_session_duration", "30m")
	v.SetDefault("claude.session_cleanup_interval", "5m")
	v.SetDefault("claude.max_workspace_size", 104857600) // 100MB
	v.SetDefault("claude.max_file_size", 10485760)       // 10MB
	
	// Security defaults
	v.SetDefault("security.encryption_key", "default-32-byte-key-for-dev-only!!") // Default for development
	v.SetDefault("security.csp_policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
	v.SetDefault("security.hsts_max_age", 31536000) // 1 year
	v.SetDefault("security.enable_hsts", true)
	v.SetDefault("security.enable_csp", true)
	v.SetDefault("security.enable_frame_deny", true)
	
	// Monitoring defaults
	v.SetDefault("monitoring.enabled", true)
	v.SetDefault("monitoring.metrics_path", "/metrics")
	v.SetDefault("monitoring.health_path", "/health")
	v.SetDefault("monitoring.readiness_path", "/ready")
	v.SetDefault("monitoring.enable_request_logging", true)
	
	// Rate limit defaults
	v.SetDefault("rate_limit.enabled", true)
	v.SetDefault("rate_limit.requests_per_second", 100.0)
	v.SetDefault("rate_limit.burst_size", 10)
	v.SetDefault("rate_limit.key_func", "ip")
	
	// WebSocket defaults
	v.SetDefault("websocket.enabled", true)
	v.SetDefault("websocket.path", "/ws")
	v.SetDefault("websocket.max_connections_per_user", 3)
	v.SetDefault("websocket.allowed_origins", []string{"http://localhost:3000", "https://app.claudy.com"})
	v.SetDefault("websocket.read_timeout", "60s")
	v.SetDefault("websocket.write_timeout", "10s")
	v.SetDefault("websocket.ping_interval", "30s")
	v.SetDefault("websocket.buffer_size", 1024)
}

// GetAddr returns the server address in host:port format
func (c *Config) GetAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// IsProduction returns true if the environment is production
func (c *Config) IsProduction() bool {
	return c.Environment == Production
}

// IsDevelopment returns true if the environment is development
func (c *Config) IsDevelopment() bool {
	return c.Environment == Development
}

// IsStaging returns true if the environment is staging
func (c *Config) IsStaging() bool {
	return c.Environment == Staging
}