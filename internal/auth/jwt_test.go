package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test user data for JWT claims
type TestUserClaims struct {
	UserID   string `json:"user_id"`
	GitHubID string `json:"github_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Helper function to generate test RSA key pair
func generateTestKeyPair(t *testing.T) (privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, privateKeyPEM string, publicKeyPEM string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey = &privateKey.PublicKey

	// Convert to PEM format
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}))

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	publicKeyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}))

	return
}

// TestJWTTokenGeneration - Generate valid JWT with user claims
func TestJWTTokenGeneration(t *testing.T) {
	_, _, privateKeyPEM, publicKeyPEM := generateTestKeyPair(t)
	
	jwtService, err := NewJWTService(privateKeyPEM, publicKeyPEM)
	require.NoError(t, err)

	userClaims := UserClaims{
		UserID:   "user123",
		GitHubID: "github456",
		Username: "testuser",
	}

	tokenString, err := jwtService.GenerateToken(userClaims, time.Hour)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify token structure (should have 3 parts separated by dots)
	parts := strings.Split(tokenString, ".")
	assert.Len(t, parts, 3)
}

// TestJWTTokenValidation - Validate JWT and extract claims
func TestJWTTokenValidation(t *testing.T) {
	_, _, privateKeyPEM, publicKeyPEM := generateTestKeyPair(t)
	
	jwtService, err := NewJWTService(privateKeyPEM, publicKeyPEM)
	require.NoError(t, err)

	originalClaims := UserClaims{
		UserID:   "user123",
		GitHubID: "github456",
		Username: "testuser",
	}

	tokenString, err := jwtService.GenerateToken(originalClaims, time.Hour)
	require.NoError(t, err)

	// Validate token and extract claims
	extractedClaims, err := jwtService.ValidateToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, originalClaims.UserID, extractedClaims.UserID)
	assert.Equal(t, originalClaims.GitHubID, extractedClaims.GitHubID)
	assert.Equal(t, originalClaims.Username, extractedClaims.Username)
	assert.True(t, extractedClaims.ExpiresAt.After(time.Now()))
}

// TestJWTGenerationWithMissingSigningKey - Handle missing/corrupt signing keys
func TestJWTGenerationWithMissingSigningKey(t *testing.T) {
	tests := []struct {
		name       string
		privateKey string
		publicKey  string
		expectErr  bool
	}{
		{
			name:       "empty private key",
			privateKey: "",
			publicKey:  "valid-public-key",
			expectErr:  true,
		},
		{
			name:       "empty public key",
			privateKey: "valid-private-key",
			publicKey:  "",
			expectErr:  true,
		},
		{
			name:       "both keys empty",
			privateKey: "",
			publicKey:  "",
			expectErr:  true,
		},
		{
			name:       "invalid private key format",
			privateKey: "invalid-key-format",
			publicKey:  "valid-public-key",
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewJWTService(tt.privateKey, tt.publicKey)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestJWTValidationWithTamperedToken - Reject modified tokens
func TestJWTValidationWithTamperedToken(t *testing.T) {
	_, _, privateKeyPEM, publicKeyPEM := generateTestKeyPair(t)
	
	jwtService, err := NewJWTService(privateKeyPEM, publicKeyPEM)
	require.NoError(t, err)

	userClaims := UserClaims{
		UserID:   "user123",
		GitHubID: "github456",
		Username: "testuser",
	}

	tokenString, err := jwtService.GenerateToken(userClaims, time.Hour)
	require.NoError(t, err)

	// Tamper with the token by modifying the last character
	tamperedToken := tokenString[:len(tokenString)-1] + "X"

	// Validation should fail
	_, err = jwtService.ValidateToken(tamperedToken)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "signature")
	}
}

// TestJWTValidationWithExpiredToken - Reject expired tokens
func TestJWTValidationWithExpiredToken(t *testing.T) {
	_, _, privateKeyPEM, publicKeyPEM := generateTestKeyPair(t)
	
	jwtService, err := NewJWTService(privateKeyPEM, publicKeyPEM)
	require.NoError(t, err)

	userClaims := UserClaims{
		UserID:   "user123",
		GitHubID: "github456",
		Username: "testuser",
	}

	// Generate token with very short expiration
	tokenString, err := jwtService.GenerateToken(userClaims, time.Millisecond)
	require.NoError(t, err)

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	// Validation should fail
	_, err = jwtService.ValidateToken(tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

// TestJWTValidationWithMalformedToken - Reject invalid format tokens
func TestJWTValidationWithMalformedToken(t *testing.T) {
	_, _, privateKeyPEM, publicKeyPEM := generateTestKeyPair(t)
	
	jwtService, err := NewJWTService(privateKeyPEM, publicKeyPEM)
	require.NoError(t, err)

	malformedTokens := []string{
		"",
		"not.a.jwt",
		"only-one-part",
		"two.parts",
		"invalid..token",
		"header.payload.signature.extra",
	}

	for _, token := range malformedTokens {
		t.Run("malformed_token_"+token, func(t *testing.T) {
			_, err := jwtService.ValidateToken(token)
			assert.Error(t, err)
		})
	}
}

// TestJWTValidationWithWrongSigningAlgorithm - Reject HS256/none algorithms
func TestJWTValidationWithWrongSigningAlgorithm(t *testing.T) {
	_, _, privateKeyPEM, publicKeyPEM := generateTestKeyPair(t)
	
	jwtService, err := NewJWTService(privateKeyPEM, publicKeyPEM)
	require.NoError(t, err)

	// Create token with HS256 algorithm
	claims := TestUserClaims{
		UserID:   "user123",
		GitHubID: "github456",
		Username: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	// Create HS256 token
	hs256Token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	hs256TokenString, err := hs256Token.SignedString([]byte("secret"))
	require.NoError(t, err)

	// Validation should fail
	_, err = jwtService.ValidateToken(hs256TokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")

	// Create "none" algorithm token
	noneToken := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	noneTokenString, err := noneToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	// Validation should fail
	_, err = jwtService.ValidateToken(noneTokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")
}

// TestConcurrentTokenGeneration - Handle race conditions in token creation
func TestConcurrentTokenGeneration(t *testing.T) {
	_, _, privateKeyPEM, publicKeyPEM := generateTestKeyPair(t)
	
	jwtService, err := NewJWTService(privateKeyPEM, publicKeyPEM)
	require.NoError(t, err)

	const numGoroutines = 100
	var wg sync.WaitGroup
	var mu sync.Mutex
	tokens := make([]string, 0, numGoroutines)
	errors := make([]error, 0)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			userClaims := UserClaims{
				UserID:   fmt.Sprintf("user%d", id),
				GitHubID: fmt.Sprintf("github%d", id),
				Username: fmt.Sprintf("testuser%d", id),
			}

			token, err := jwtService.GenerateToken(userClaims, time.Hour)
			
			mu.Lock()
			if err != nil {
				errors = append(errors, err)
			} else {
				tokens = append(tokens, token)
			}
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// All tokens should be generated successfully
	assert.Empty(t, errors, "No errors should occur during concurrent token generation")
	assert.Len(t, tokens, numGoroutines, "All tokens should be generated")

	// All tokens should be unique
	tokenSet := make(map[string]bool)
	for _, token := range tokens {
		assert.False(t, tokenSet[token], "All tokens should be unique")
		tokenSet[token] = true
	}
}

// TestTokenGenerationWithInvalidUserData - Handle nil/empty user claims
func TestTokenGenerationWithInvalidUserData(t *testing.T) {
	_, _, privateKeyPEM, publicKeyPEM := generateTestKeyPair(t)
	
	jwtService, err := NewJWTService(privateKeyPEM, publicKeyPEM)
	require.NoError(t, err)

	tests := []struct {
		name      string
		claims    UserClaims
		expectErr bool
	}{
		{
			name: "empty user ID",
			claims: UserClaims{
				UserID:   "",
				GitHubID: "github456",
				Username: "testuser",
			},
			expectErr: true,
		},
		{
			name: "empty GitHub ID",
			claims: UserClaims{
				UserID:   "user123",
				GitHubID: "",
				Username: "testuser",
			},
			expectErr: true,
		},
		{
			name: "empty username",
			claims: UserClaims{
				UserID:   "user123",
				GitHubID: "github456",
				Username: "",
			},
			expectErr: true,
		},
		{
			name: "all fields empty",
			claims: UserClaims{
				UserID:   "",
				GitHubID: "",
				Username: "",
			},
			expectErr: true,
		},
		{
			name: "valid claims",
			claims: UserClaims{
				UserID:   "user123",
				GitHubID: "github456",
				Username: "testuser",
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := jwtService.GenerateToken(tt.claims, time.Hour)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}