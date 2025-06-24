package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// UserClaims represents the claims included in a JWT token
type UserClaims struct {
	UserID   string    `json:"user_id"`
	GitHubID string    `json:"github_id"`
	Username string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
	jwt.RegisteredClaims
}

// JWTService handles JWT token generation and validation
type JWTService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	mutex      sync.RWMutex
}

// NewJWTService creates a new JWT service with RSA keys
func NewJWTService(privateKeyPEM, publicKeyPEM string) (*JWTService, error) {
	if strings.TrimSpace(privateKeyPEM) == "" {
		return nil, errors.New("private key cannot be empty")
	}
	if strings.TrimSpace(publicKeyPEM) == "" {
		return nil, errors.New("public key cannot be empty")
	}

	// Parse private key
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Parse public key
	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &JWTService{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

// GenerateToken creates a new JWT token with user claims
func (j *JWTService) GenerateToken(userClaims UserClaims, duration time.Duration) (string, error) {
	// Validate user claims
	if err := j.validateUserClaims(userClaims); err != nil {
		return "", fmt.Errorf("invalid user claims: %w", err)
	}

	j.mutex.RLock()
	defer j.mutex.RUnlock()

	now := time.Now()
	expiresAt := now.Add(duration)

	// Create the claims
	claims := UserClaims{
		UserID:    userClaims.UserID,
		GitHubID:  userClaims.GitHubID,
		Username:  userClaims.Username,
		ExpiresAt: expiresAt,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "claudy",
			Subject:   userClaims.UserID,
		},
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign the token
	tokenString, err := token.SignedString(j.privateKey)
	if err != nil {
		log.Printf("JWT: Failed to sign token for user %s: %v", userClaims.UserID, err)
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	log.Printf("JWT: Generated token for user %s (expires: %s)", userClaims.UserID, expiresAt.Format(time.RFC3339))
	return tokenString, nil
}

// ValidateToken validates a JWT token and returns the user claims
func (j *JWTService) ValidateToken(tokenString string) (*UserClaims, error) {
	if strings.TrimSpace(tokenString) == "" {
		return nil, errors.New("token cannot be empty")
	}

	j.mutex.RLock()
	defer j.mutex.RUnlock()

	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.publicKey, nil
	})

	if err != nil {
		log.Printf("JWT: Token validation failed: %v", err)
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(*UserClaims)
	if !ok || !token.Valid {
		log.Printf("JWT: Invalid token claims")
		return nil, errors.New("invalid token claims")
	}

	// Additional validation
	if claims.UserID == "" || claims.GitHubID == "" || claims.Username == "" {
		log.Printf("JWT: Token contains invalid user claims")
		return nil, errors.New("token contains invalid user claims")
	}

	log.Printf("JWT: Successfully validated token for user %s", claims.UserID)
	return claims, nil
}

// validateUserClaims validates the user claims before token generation
func (j *JWTService) validateUserClaims(claims UserClaims) error {
	if strings.TrimSpace(claims.UserID) == "" {
		return errors.New("user ID cannot be empty")
	}
	if strings.TrimSpace(claims.GitHubID) == "" {
		return errors.New("GitHub ID cannot be empty")
	}
	if strings.TrimSpace(claims.Username) == "" {
		return errors.New("username cannot be empty")
	}
	return nil
}

// parsePrivateKey parses a PEM-encoded RSA private key
func parsePrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	// Try PKCS8 format first
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("key is not an RSA private key")
	}

	// Try PKCS1 format
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key")
}

// parsePublicKey parses a PEM-encoded RSA public key
func parsePublicKey(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	// Try PKIX format
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("key is not an RSA public key")
	}

	// Try PKCS1 format
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse public key")
}