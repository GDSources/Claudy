package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/mongo/options"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field '%s' (value: %v): %s", e.Field, e.Value, e.Message)
}

// ValidationErrors is a collection of validation errors
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return "no validation errors"
	}
	
	var messages []string
	for _, err := range ve {
		messages = append(messages, err.Error())
	}
	return strings.Join(messages, "; ")
}

// ValidateConfig validates the entire configuration
func ValidateConfig(cfg *Config) error {
	var errors ValidationErrors
	
	// Validate environment
	if err := validateEnvironment(cfg); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate server configuration
	if err := validateServerConfig(&cfg.Server, cfg.Environment); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate database configuration
	if err := validateDatabaseConfig(&cfg.Database); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate Redis configuration
	if err := validateRedisConfig(&cfg.Redis); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate JWT configuration
	if err := validateJWTConfig(&cfg.JWT); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate Claude configuration
	if err := validateClaudeConfig(&cfg.Claude); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate security configuration
	if err := validateSecurityConfig(&cfg.Security, cfg.Environment); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate monitoring configuration
	if err := validateMonitoringConfig(&cfg.Monitoring); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate rate limit configuration
	if err := validateRateLimitConfig(&cfg.RateLimit); err != nil {
		errors = append(errors, err...)
	}
	
	if len(errors) > 0 {
		return errors
	}
	
	return nil
}

// validateEnvironment validates environment configuration
func validateEnvironment(cfg *Config) ValidationErrors {
	var errors ValidationErrors
	
	// Validate environment value
	switch cfg.Environment {
	case Development, Staging, Production:
		// Valid environment
	default:
		errors = append(errors, ValidationError{
			Field:   "environment",
			Value:   cfg.Environment,
			Message: "must be one of: development, staging, production",
		})
	}
	
	// Production-specific validations
	if cfg.Environment == Production {
		if cfg.Debug {
			errors = append(errors, ValidationError{
				Field:   "debug",
				Value:   cfg.Debug,
				Message: "debug mode should not be enabled in production",
			})
		}
	}
	
	return errors
}

// validateServerConfig validates server configuration
func validateServerConfig(cfg *ServerConfig, env Environment) ValidationErrors {
	var errors ValidationErrors
	
	// Validate port
	if cfg.Port < 1 || cfg.Port > 65535 {
		errors = append(errors, ValidationError{
			Field:   "server.port",
			Value:   cfg.Port,
			Message: "must be between 1 and 65535",
		})
	}
	
	// Validate timeouts
	if cfg.ReadTimeout < time.Second {
		errors = append(errors, ValidationError{
			Field:   "server.read_timeout",
			Value:   cfg.ReadTimeout,
			Message: "must be at least 1 second",
		})
	}
	
	if cfg.WriteTimeout < time.Second {
		errors = append(errors, ValidationError{
			Field:   "server.write_timeout",
			Value:   cfg.WriteTimeout,
			Message: "must be at least 1 second",
		})
	}
	
	if cfg.ShutdownTimeout < 5*time.Second {
		errors = append(errors, ValidationError{
			Field:   "server.shutdown_timeout",
			Value:   cfg.ShutdownTimeout,
			Message: "must be at least 5 seconds",
		})
	}
	
	// Validate max header bytes
	if cfg.MaxHeaderBytes < 1024 {
		errors = append(errors, ValidationError{
			Field:   "server.max_header_bytes",
			Value:   cfg.MaxHeaderBytes,
			Message: "must be at least 1024 bytes",
		})
	}
	
	// Validate TLS configuration
	if cfg.TLS.Enabled {
		if cfg.TLS.CertFile == "" {
			errors = append(errors, ValidationError{
				Field:   "server.tls.cert_file",
				Value:   cfg.TLS.CertFile,
				Message: "cert file path is required when TLS is enabled",
			})
		} else if err := validateFilePath(cfg.TLS.CertFile, false); err != nil {
			errors = append(errors, ValidationError{
				Field:   "server.tls.cert_file",
				Value:   cfg.TLS.CertFile,
				Message: err.Error(),
			})
		}
		
		if cfg.TLS.KeyFile == "" {
			errors = append(errors, ValidationError{
				Field:   "server.tls.key_file",
				Value:   cfg.TLS.KeyFile,
				Message: "key file path is required when TLS is enabled",
			})
		} else if err := validateFilePath(cfg.TLS.KeyFile, false); err != nil {
			errors = append(errors, ValidationError{
				Field:   "server.tls.key_file",
				Value:   cfg.TLS.KeyFile,
				Message: err.Error(),
			})
		}
	}
	
	// Production-specific TLS validation
	if env == Production && !cfg.TLS.Enabled {
		errors = append(errors, ValidationError{
			Field:   "server.tls.enabled",
			Value:   cfg.TLS.Enabled,
			Message: "TLS should be enabled in production",
		})
	}
	
	// Validate allowed origins
	if len(cfg.AllowedOrigins) == 0 {
		errors = append(errors, ValidationError{
			Field:   "server.allowed_origins",
			Value:   cfg.AllowedOrigins,
			Message: "at least one allowed origin must be specified",
		})
	}
	
	// Production-specific origin validation
	if env == Production {
		for i, origin := range cfg.AllowedOrigins {
			if origin == "*" {
				errors = append(errors, ValidationError{
					Field:   fmt.Sprintf("server.allowed_origins[%d]", i),
					Value:   origin,
					Message: "wildcard origins should not be used in production",
				})
			}
		}
	}
	
	return errors
}

// validateDatabaseConfig validates database configuration
func validateDatabaseConfig(cfg *DatabaseConfig) ValidationErrors {
	var errors ValidationErrors
	
	// Validate MongoDB URI
	if cfg.URI == "" {
		errors = append(errors, ValidationError{
			Field:   "database.uri",
			Value:   cfg.URI,
			Message: "MongoDB URI is required",
		})
	} else {
		// Parse and validate MongoDB URI
		clientOptions := options.Client().ApplyURI(cfg.URI)
		if err := clientOptions.Validate(); err != nil {
			errors = append(errors, ValidationError{
				Field:   "database.uri",
				Value:   cfg.URI,
				Message: fmt.Sprintf("invalid MongoDB URI: %v", err),
			})
		}
	}
	
	// Validate database name
	if cfg.Database == "" {
		errors = append(errors, ValidationError{
			Field:   "database.database",
			Value:   cfg.Database,
			Message: "database name is required",
		})
	}
	
	// Validate timeouts
	if cfg.ConnectTimeout < time.Second {
		errors = append(errors, ValidationError{
			Field:   "database.connect_timeout",
			Value:   cfg.ConnectTimeout,
			Message: "must be at least 1 second",
		})
	}
	
	if cfg.QueryTimeout < time.Second {
		errors = append(errors, ValidationError{
			Field:   "database.query_timeout",
			Value:   cfg.QueryTimeout,
			Message: "must be at least 1 second",
		})
	}
	
	// Validate pool sizes
	if cfg.MaxPoolSize < 1 {
		errors = append(errors, ValidationError{
			Field:   "database.max_pool_size",
			Value:   cfg.MaxPoolSize,
			Message: "must be at least 1",
		})
	}
	
	if cfg.MinPoolSize > cfg.MaxPoolSize {
		errors = append(errors, ValidationError{
			Field:   "database.min_pool_size",
			Value:   cfg.MinPoolSize,
			Message: "cannot be greater than max_pool_size",
		})
	}
	
	return errors
}

// validateRedisConfig validates Redis configuration
func validateRedisConfig(cfg *RedisConfig) ValidationErrors {
	var errors ValidationErrors
	
	// Validate address
	if cfg.Addr == "" {
		errors = append(errors, ValidationError{
			Field:   "redis.addr",
			Value:   cfg.Addr,
			Message: "Redis address is required",
		})
	}
	
	// Validate database number
	if cfg.DB < 0 || cfg.DB > 15 {
		errors = append(errors, ValidationError{
			Field:   "redis.db",
			Value:   cfg.DB,
			Message: "must be between 0 and 15",
		})
	}
	
	// Validate timeouts
	if cfg.DialTimeout < time.Second {
		errors = append(errors, ValidationError{
			Field:   "redis.dial_timeout",
			Value:   cfg.DialTimeout,
			Message: "must be at least 1 second",
		})
	}
	
	// Validate pool settings
	if cfg.PoolSize < 1 {
		errors = append(errors, ValidationError{
			Field:   "redis.pool_size",
			Value:   cfg.PoolSize,
			Message: "must be at least 1",
		})
	}
	
	if cfg.MinIdleConns < 0 {
		errors = append(errors, ValidationError{
			Field:   "redis.min_idle_conns",
			Value:   cfg.MinIdleConns,
			Message: "cannot be negative",
		})
	}
	
	if cfg.MinIdleConns > cfg.PoolSize {
		errors = append(errors, ValidationError{
			Field:   "redis.min_idle_conns",
			Value:   cfg.MinIdleConns,
			Message: "cannot be greater than pool_size",
		})
	}
	
	return errors
}

// validateJWTConfig validates JWT configuration
func validateJWTConfig(cfg *JWTConfig) ValidationErrors {
	var errors ValidationErrors
	
	// Validate private key path
	if cfg.PrivateKeyPath == "" {
		errors = append(errors, ValidationError{
			Field:   "jwt.private_key_path",
			Value:   cfg.PrivateKeyPath,
			Message: "private key path is required",
		})
	} else {
		if err := validateFilePath(cfg.PrivateKeyPath, false); err != nil {
			errors = append(errors, ValidationError{
				Field:   "jwt.private_key_path",
				Value:   cfg.PrivateKeyPath,
				Message: err.Error(),
			})
		} else {
			// Validate RSA private key
			if err := validateRSAPrivateKey(cfg.PrivateKeyPath); err != nil {
				errors = append(errors, ValidationError{
					Field:   "jwt.private_key_path",
					Value:   cfg.PrivateKeyPath,
					Message: err.Error(),
				})
			}
		}
	}
	
	// Validate public key path
	if cfg.PublicKeyPath == "" {
		errors = append(errors, ValidationError{
			Field:   "jwt.public_key_path",
			Value:   cfg.PublicKeyPath,
			Message: "public key path is required",
		})
	} else {
		if err := validateFilePath(cfg.PublicKeyPath, false); err != nil {
			errors = append(errors, ValidationError{
				Field:   "jwt.public_key_path",
				Value:   cfg.PublicKeyPath,
				Message: err.Error(),
			})
		} else {
			// Validate RSA public key
			if err := validateRSAPublicKey(cfg.PublicKeyPath); err != nil {
				errors = append(errors, ValidationError{
					Field:   "jwt.public_key_path",
					Value:   cfg.PublicKeyPath,
					Message: err.Error(),
				})
			}
		}
	}
	
	// Validate key pair match (if both keys are valid)
	if cfg.PrivateKeyPath != "" && cfg.PublicKeyPath != "" {
		if err := validateRSAKeyPairMatch(cfg.PrivateKeyPath, cfg.PublicKeyPath); err != nil {
			errors = append(errors, ValidationError{
				Field:   "jwt.key_pair",
				Value:   fmt.Sprintf("private: %s, public: %s", cfg.PrivateKeyPath, cfg.PublicKeyPath),
				Message: err.Error(),
			})
		}
	}
	
	// Validate issuer
	if cfg.Issuer == "" {
		errors = append(errors, ValidationError{
			Field:   "jwt.issuer",
			Value:   cfg.Issuer,
			Message: "issuer is required",
		})
	}
	
	// Validate expiry duration
	if cfg.ExpiryDuration < 5*time.Minute {
		errors = append(errors, ValidationError{
			Field:   "jwt.expiry_duration",
			Value:   cfg.ExpiryDuration,
			Message: "must be at least 5 minutes",
		})
	}
	
	return errors
}

// validateClaudeConfig validates Claude configuration
func validateClaudeConfig(cfg *ClaudeConfig) ValidationErrors {
	var errors ValidationErrors
	
	// Validate API base URL
	if cfg.APIBaseURL == "" {
		errors = append(errors, ValidationError{
			Field:   "claude.api_base_url",
			Value:   cfg.APIBaseURL,
			Message: "API base URL is required",
		})
	} else {
		if _, err := url.Parse(cfg.APIBaseURL); err != nil {
			errors = append(errors, ValidationError{
				Field:   "claude.api_base_url",
				Value:   cfg.APIBaseURL,
				Message: fmt.Sprintf("invalid URL: %v", err),
			})
		}
	}
	
	// Validate workspace base path
	if cfg.WorkspaceBasePath == "" {
		errors = append(errors, ValidationError{
			Field:   "claude.workspace_base_path",
			Value:   cfg.WorkspaceBasePath,
			Message: "workspace base path is required",
		})
	} else {
		if err := validateDirectoryPath(cfg.WorkspaceBasePath, true); err != nil {
			errors = append(errors, ValidationError{
				Field:   "claude.workspace_base_path",
				Value:   cfg.WorkspaceBasePath,
				Message: err.Error(),
			})
		}
	}
	
	// Validate session duration
	if cfg.MaxSessionDuration < 5*time.Minute {
		errors = append(errors, ValidationError{
			Field:   "claude.max_session_duration",
			Value:   cfg.MaxSessionDuration,
			Message: "must be at least 5 minutes",
		})
	}
	
	// Validate cleanup interval
	if cfg.SessionCleanupInterval < time.Minute {
		errors = append(errors, ValidationError{
			Field:   "claude.session_cleanup_interval",
			Value:   cfg.SessionCleanupInterval,
			Message: "must be at least 1 minute",
		})
	}
	
	// Validate file sizes
	if cfg.MaxFileSize < 1024 {
		errors = append(errors, ValidationError{
			Field:   "claude.max_file_size",
			Value:   cfg.MaxFileSize,
			Message: "must be at least 1024 bytes",
		})
	}
	
	if cfg.MaxWorkspaceSize < cfg.MaxFileSize {
		errors = append(errors, ValidationError{
			Field:   "claude.max_workspace_size",
			Value:   cfg.MaxWorkspaceSize,
			Message: "must be at least max_file_size",
		})
	}
	
	return errors
}

// validateSecurityConfig validates security configuration
func validateSecurityConfig(cfg *SecurityConfig, env Environment) ValidationErrors {
	var errors ValidationErrors
	
	// Validate encryption key
	if cfg.EncryptionKey == "" {
		errors = append(errors, ValidationError{
			Field:   "security.encryption_key",
			Value:   cfg.EncryptionKey,
			Message: "encryption key is required",
		})
	} else if len(cfg.EncryptionKey) < 32 {
		errors = append(errors, ValidationError{
			Field:   "security.encryption_key",
			Value:   "***",
			Message: "encryption key must be at least 32 bytes",
		})
	}
	
	// Validate HSTS max age
	if cfg.EnableHSTS && cfg.HSTSMaxAge < 86400 {
		errors = append(errors, ValidationError{
			Field:   "security.hsts_max_age",
			Value:   cfg.HSTSMaxAge,
			Message: "HSTS max age should be at least 1 day (86400 seconds)",
		})
	}
	
	// Production-specific security validations
	if env == Production {
		if !cfg.EnableHSTS {
			errors = append(errors, ValidationError{
				Field:   "security.enable_hsts",
				Value:   cfg.EnableHSTS,
				Message: "HSTS should be enabled in production",
			})
		}
		
		if !cfg.EnableCSP {
			errors = append(errors, ValidationError{
				Field:   "security.enable_csp",
				Value:   cfg.EnableCSP,
				Message: "CSP should be enabled in production",
			})
		}
		
		if !cfg.EnableFrameDeny {
			errors = append(errors, ValidationError{
				Field:   "security.enable_frame_deny",
				Value:   cfg.EnableFrameDeny,
				Message: "frame deny should be enabled in production",
			})
		}
	}
	
	return errors
}

// validateMonitoringConfig validates monitoring configuration
func validateMonitoringConfig(cfg *MonitoringConfig) ValidationErrors {
	var errors ValidationErrors
	
	// Validate paths
	if cfg.MetricsPath == "" {
		errors = append(errors, ValidationError{
			Field:   "monitoring.metrics_path",
			Value:   cfg.MetricsPath,
			Message: "metrics path is required",
		})
	}
	
	if cfg.HealthPath == "" {
		errors = append(errors, ValidationError{
			Field:   "monitoring.health_path",
			Value:   cfg.HealthPath,
			Message: "health path is required",
		})
	}
	
	if cfg.ReadinessPath == "" {
		errors = append(errors, ValidationError{
			Field:   "monitoring.readiness_path",
			Value:   cfg.ReadinessPath,
			Message: "readiness path is required",
		})
	}
	
	return errors
}

// validateRateLimitConfig validates rate limiting configuration
func validateRateLimitConfig(cfg *RateLimitConfig) ValidationErrors {
	var errors ValidationErrors
	
	if cfg.Enabled {
		// Validate requests per second
		if cfg.RequestsPerSecond <= 0 {
			errors = append(errors, ValidationError{
				Field:   "rate_limit.requests_per_second",
				Value:   cfg.RequestsPerSecond,
				Message: "must be greater than 0",
			})
		}
		
		// Validate burst size
		if cfg.BurstSize < 1 {
			errors = append(errors, ValidationError{
				Field:   "rate_limit.burst_size",
				Value:   cfg.BurstSize,
				Message: "must be at least 1",
			})
		}
		
		// Validate key function
		validKeyFuncs := []string{"ip", "user", "custom"}
		validKeyFunc := false
		for _, valid := range validKeyFuncs {
			if cfg.KeyFunc == valid {
				validKeyFunc = true
				break
			}
		}
		if !validKeyFunc {
			errors = append(errors, ValidationError{
				Field:   "rate_limit.key_func",
				Value:   cfg.KeyFunc,
				Message: "must be one of: ip, user, custom",
			})
		}
	}
	
	return errors
}

// Helper functions

// validateFilePath validates that a file exists and is readable
func validateFilePath(path string, shouldBeDirectory bool) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %v", err)
	}
	
	stat, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", absPath)
		}
		return fmt.Errorf("cannot access file: %v", err)
	}
	
	if shouldBeDirectory && !stat.IsDir() {
		return fmt.Errorf("path is not a directory: %s", absPath)
	}
	
	if !shouldBeDirectory && stat.IsDir() {
		return fmt.Errorf("path is a directory, expected file: %s", absPath)
	}
	
	return nil
}

// validateDirectoryPath validates that a directory exists or can be created
func validateDirectoryPath(path string, createIfNotExists bool) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %v", err)
	}
	
	stat, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			if createIfNotExists {
				if err := os.MkdirAll(absPath, 0755); err != nil {
					return fmt.Errorf("cannot create directory: %v", err)
				}
				return nil
			}
			return fmt.Errorf("directory does not exist: %s", absPath)
		}
		return fmt.Errorf("cannot access directory: %v", err)
	}
	
	if !stat.IsDir() {
		return fmt.Errorf("path is not a directory: %s", absPath)
	}
	
	return nil
}

// validateRSAPrivateKey validates that a file contains a valid RSA private key
func validateRSAPrivateKey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read private key file: %v", err)
	}
	
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("no PEM block found in private key file")
	}
	
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("cannot parse private key: %v", err)
	}
	
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not an RSA key")
	}
	
	if rsaKey.N.BitLen() < 2048 {
		return fmt.Errorf("RSA key is too small (%d bits), minimum 2048 bits required", rsaKey.N.BitLen())
	}
	
	return nil
}

// validateRSAPublicKey validates that a file contains a valid RSA public key
func validateRSAPublicKey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read public key file: %v", err)
	}
	
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("no PEM block found in public key file")
	}
	
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("cannot parse public key: %v", err)
	}
	
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not an RSA key")
	}
	
	if rsaKey.N.BitLen() < 2048 {
		return fmt.Errorf("RSA key is too small (%d bits), minimum 2048 bits required", rsaKey.N.BitLen())
	}
	
	return nil
}

// validateRSAKeyPairMatch validates that private and public keys are a matching pair
func validateRSAKeyPairMatch(privatePath, publicPath string) error {
	// Read private key
	privateData, err := os.ReadFile(privatePath)
	if err != nil {
		return fmt.Errorf("cannot read private key: %v", err)
	}
	
	privateBlock, _ := pem.Decode(privateData)
	if privateBlock == nil {
		return fmt.Errorf("no PEM block in private key")
	}
	
	privateKey, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		return fmt.Errorf("cannot parse private key: %v", err)
	}
	
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not RSA")
	}
	
	// Read public key
	publicData, err := os.ReadFile(publicPath)
	if err != nil {
		return fmt.Errorf("cannot read public key: %v", err)
	}
	
	publicBlock, _ := pem.Decode(publicData)
	if publicBlock == nil {
		return fmt.Errorf("no PEM block in public key")
	}
	
	publicKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		return fmt.Errorf("cannot parse public key: %v", err)
	}
	
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}
	
	// Compare public keys
	if rsaPrivateKey.PublicKey.N.Cmp(rsaPublicKey.N) != 0 ||
		rsaPrivateKey.PublicKey.E != rsaPublicKey.E {
		return fmt.Errorf("private and public keys do not match")
	}
	
	return nil
}