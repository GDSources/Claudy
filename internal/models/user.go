package models

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// GitHubProfile represents the data we get from GitHub API
type GitHubProfile struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// User represents the user model as defined in the PRD
type User struct {
	ID          primitive.ObjectID         `bson:"_id,omitempty" json:"id"`
	GitHubID    int64                      `bson:"github_id" json:"github_id"`
	Username    string                     `bson:"username" json:"username"`
	Email       string                     `bson:"email" json:"email"`
	AvatarURL   string                     `bson:"avatar_url" json:"avatar_url"`
	CreatedAt   time.Time                  `bson:"created_at" json:"created_at"`
	LastLogin   time.Time                  `bson:"last_login" json:"last_login"`
	IsActive    bool                       `bson:"is_active" json:"is_active"`
	Preferences map[string]interface{}     `bson:"preferences" json:"preferences"`
	Metadata    map[string]interface{}     `bson:"metadata" json:"metadata"`
}

// UserRepository defines the interface for user data operations
type UserRepository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByGitHubID(ctx context.Context, githubID int64) (*User, error)
	GetUserByID(ctx context.Context, id primitive.ObjectID) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
}

// validateGitHubProfile validates the GitHub profile data
func validateGitHubProfile(profile GitHubProfile) error {
	if profile.ID == 0 {
		return errors.New("github ID is required")
	}

	if strings.TrimSpace(profile.Login) == "" {
		return errors.New("username is required")
	}

	if len(profile.Login) > 100 {
		return errors.New("username too long: maximum 100 characters allowed")
	}

	if strings.TrimSpace(profile.Email) == "" {
		return errors.New("email is required")
	}

	// Basic email validation
	if !strings.Contains(profile.Email, "@") || !strings.Contains(profile.Email, ".") {
		return errors.New("invalid email format")
	}

	return nil
}

// CreateUserFromGitHubProfile creates a new user from GitHub profile data
func CreateUserFromGitHubProfile(ctx context.Context, repo UserRepository, profile GitHubProfile) (*User, error) {
	// Validate input data
	if err := validateGitHubProfile(profile); err != nil {
		return nil, err
	}

	now := time.Now()
	user := &User{
		GitHubID:    profile.ID,
		Username:    profile.Login,
		Email:       profile.Email,
		AvatarURL:   profile.AvatarURL,
		CreatedAt:   now,
		LastLogin:   now,
		IsActive:    true,
		Preferences: make(map[string]interface{}),
		Metadata:    make(map[string]interface{}),
	}

	// Attempt to create user in repository
	err := repo.CreateUser(ctx, user)
	if err != nil {
		// Handle duplicate key error
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "already exists") {
			return nil, fmt.Errorf("user with GitHub ID %d already exists", profile.ID)
		}
		// Handle other database errors
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// GetUserByGitHubID retrieves a user by their GitHub ID
func GetUserByGitHubID(ctx context.Context, repo UserRepository, githubID int64) (*User, error) {
	if githubID == 0 {
		return nil, errors.New("invalid GitHub ID")
	}

	user, err := repo.GetUserByGitHubID(ctx, githubID)
	if err != nil {
		// Handle database connection errors
		if strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "timeout") {
			return nil, fmt.Errorf("database connection failed: %w", err)
		}
		return nil, err
	}

	return user, nil
}

// GetUserByID retrieves a user by their ObjectID
func GetUserByID(ctx context.Context, repo UserRepository, id primitive.ObjectID) (*User, error) {
	// Validate ObjectID
	if id.IsZero() {
		return nil, errors.New("invalid user ID: cannot be zero")
	}

	user, err := repo.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// UpdateUserLastLogin updates the user's last login timestamp
func UpdateUserLastLogin(ctx context.Context, repo UserRepository, user *User) error {
	if user == nil {
		return errors.New("user cannot be nil")
	}

	user.LastLogin = time.Now()
	return repo.UpdateUser(ctx, user)
}