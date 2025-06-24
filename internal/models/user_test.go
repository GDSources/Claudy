package models

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// MockUserRepository is a mock implementation of UserRepository for testing
type MockUserRepository struct {
	mock.Mock
	mutex sync.RWMutex
}

func (m *MockUserRepository) CreateUser(ctx context.Context, user *User) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserByGitHubID(ctx context.Context, githubID int64) (*User, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	args := m.Called(ctx, githubID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserRepository) GetUserByID(ctx context.Context, id primitive.ObjectID) (*User, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserRepository) UpdateUser(ctx context.Context, user *User) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	args := m.Called(ctx, user)
	return args.Error(0)
}

// TestCreateUserFromGitHubProfile tests creating a user from valid GitHub data
func TestCreateUserFromGitHubProfile(t *testing.T) {
	mockRepo := new(MockUserRepository)
	ctx := context.Background()

	// Valid GitHub profile data
	githubProfile := GitHubProfile{
		ID:        12345,
		Login:     "testuser",
		Email:     "test@example.com",
		AvatarURL: "https://avatars.githubusercontent.com/u/12345",
	}

	// Expected user to be created
	expectedUser := &User{
		GitHubID:    githubProfile.ID,
		Username:    githubProfile.Login,
		Email:       githubProfile.Email,
		AvatarURL:   githubProfile.AvatarURL,
		IsActive:    true,
		Preferences: make(map[string]interface{}),
		Metadata:    make(map[string]interface{}),
	}

	mockRepo.On("CreateUser", ctx, mock.MatchedBy(func(user *User) bool {
		return user.GitHubID == expectedUser.GitHubID &&
			user.Username == expectedUser.Username &&
			user.Email == expectedUser.Email &&
			user.AvatarURL == expectedUser.AvatarURL &&
			user.IsActive == expectedUser.IsActive &&
			!user.CreatedAt.IsZero() &&
			!user.LastLogin.IsZero()
	})).Return(nil)

	// Test the function
	user, err := CreateUserFromGitHubProfile(ctx, mockRepo, githubProfile)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, githubProfile.ID, user.GitHubID)
	assert.Equal(t, githubProfile.Login, user.Username)
	assert.Equal(t, githubProfile.Email, user.Email)
	assert.Equal(t, githubProfile.AvatarURL, user.AvatarURL)
	assert.True(t, user.IsActive)
	assert.False(t, user.CreatedAt.IsZero())
	assert.False(t, user.LastLogin.IsZero())
	assert.NotNil(t, user.Preferences)
	assert.NotNil(t, user.Metadata)

	mockRepo.AssertExpectations(t)
}

// TestGetUserByGitHubID tests retrieving an existing user
func TestGetUserByGitHubID(t *testing.T) {
	mockRepo := new(MockUserRepository)
	ctx := context.Background()

	githubID := int64(12345)
	expectedUser := &User{
		ID:          primitive.NewObjectID(),
		GitHubID:    githubID,
		Username:    "testuser",
		Email:       "test@example.com",
		AvatarURL:   "https://avatars.githubusercontent.com/u/12345",
		CreatedAt:   time.Now(),
		LastLogin:   time.Now(),
		IsActive:    true,
		Preferences: make(map[string]interface{}),
		Metadata:    make(map[string]interface{}),
	}

	mockRepo.On("GetUserByGitHubID", ctx, githubID).Return(expectedUser, nil)

	user, err := GetUserByGitHubID(ctx, mockRepo, githubID)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, expectedUser.ID, user.ID)
	assert.Equal(t, expectedUser.GitHubID, user.GitHubID)
	assert.Equal(t, expectedUser.Username, user.Username)

	mockRepo.AssertExpectations(t)
}

// TestCreateUserWithMalformedGitHubData tests handling of incomplete/null GitHub profile
func TestCreateUserWithMalformedGitHubData(t *testing.T) {
	mockRepo := new(MockUserRepository)
	ctx := context.Background()

	testCases := []struct {
		name          string
		githubProfile GitHubProfile
		expectedError string
	}{
		{
			name: "missing GitHub ID",
			githubProfile: GitHubProfile{
				ID:        0,
				Login:     "testuser",
				Email:     "test@example.com",
				AvatarURL: "https://avatars.githubusercontent.com/u/12345",
			},
			expectedError: "github ID is required",
		},
		{
			name: "empty username",
			githubProfile: GitHubProfile{
				ID:        12345,
				Login:     "",
				Email:     "test@example.com",
				AvatarURL: "https://avatars.githubusercontent.com/u/12345",
			},
			expectedError: "username is required",
		},
		{
			name: "empty email",
			githubProfile: GitHubProfile{
				ID:        12345,
				Login:     "testuser",
				Email:     "",
				AvatarURL: "https://avatars.githubusercontent.com/u/12345",
			},
			expectedError: "email is required",
		},
		{
			name: "invalid email format",
			githubProfile: GitHubProfile{
				ID:        12345,
				Login:     "testuser",
				Email:     "invalid-email",
				AvatarURL: "https://avatars.githubusercontent.com/u/12345",
			},
			expectedError: "invalid email format",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user, err := CreateUserFromGitHubProfile(ctx, mockRepo, tc.githubProfile)

			assert.Error(t, err)
			assert.Nil(t, user)
			assert.Contains(t, err.Error(), tc.expectedError)
		})
	}

	mockRepo.AssertExpectations(t)
}

// TestCreateUserWithDuplicateGitHubID tests handling duplicate user creation attempts
func TestCreateUserWithDuplicateGitHubID(t *testing.T) {
	mockRepo := new(MockUserRepository)
	ctx := context.Background()

	githubProfile := GitHubProfile{
		ID:        12345,
		Login:     "testuser",
		Email:     "test@example.com",
		AvatarURL: "https://avatars.githubusercontent.com/u/12345",
	}

	// Mock repository to return duplicate key error
	duplicateError := errors.New("duplicate key error: github_id already exists")
	mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*models.User")).Return(duplicateError)

	user, err := CreateUserFromGitHubProfile(ctx, mockRepo, githubProfile)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "already exists")

	mockRepo.AssertExpectations(t)
}

// TestGetUserWhenDatabaseUnavailable tests handling MongoDB connection failures
func TestGetUserWhenDatabaseUnavailable(t *testing.T) {
	mockRepo := new(MockUserRepository)
	ctx := context.Background()

	githubID := int64(12345)
	dbError := errors.New("connection to database failed")

	mockRepo.On("GetUserByGitHubID", ctx, githubID).Return(nil, dbError)

	user, err := GetUserByGitHubID(ctx, mockRepo, githubID)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "database connection failed")

	mockRepo.AssertExpectations(t)
}

// TestCreateUserWhenDatabaseUnavailable tests handling write failures during user creation
func TestCreateUserWhenDatabaseUnavailable(t *testing.T) {
	mockRepo := new(MockUserRepository)
	ctx := context.Background()

	githubProfile := GitHubProfile{
		ID:        12345,
		Login:     "testuser",
		Email:     "test@example.com",
		AvatarURL: "https://avatars.githubusercontent.com/u/12345",
	}

	dbError := errors.New("write concern timeout")
	mockRepo.On("CreateUser", ctx, mock.AnythingOfType("*models.User")).Return(dbError)

	user, err := CreateUserFromGitHubProfile(ctx, mockRepo, githubProfile)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "failed to create user")

	mockRepo.AssertExpectations(t)
}

// TestConcurrentUserUpdates tests handling simultaneous user modifications
func TestConcurrentUserUpdates(t *testing.T) {
	mockRepo := new(MockUserRepository)
	ctx := context.Background()

	user := &User{
		ID:          primitive.NewObjectID(),
		GitHubID:    12345,
		Username:    "testuser",
		Email:       "test@example.com",
		AvatarURL:   "https://avatars.githubusercontent.com/u/12345",
		CreatedAt:   time.Now(),
		LastLogin:   time.Now(),
		IsActive:    true,
		Preferences: make(map[string]interface{}),
		Metadata:    make(map[string]interface{}),
	}

	// Simulate concurrent updates
	mockRepo.On("UpdateUser", ctx, user).Return(nil)

	var wg sync.WaitGroup
	errors := make(chan error, 10)

	// Start 10 concurrent updates
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := UpdateUserLastLogin(ctx, mockRepo, user)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check that no errors occurred
	for err := range errors {
		assert.NoError(t, err)
	}

	mockRepo.AssertExpectations(t)
}

// TestUserCreationWithExtremelyLongUsername tests handling data validation limits
func TestUserCreationWithExtremelyLongUsername(t *testing.T) {
	mockRepo := new(MockUserRepository)
	ctx := context.Background()

	// Create username that exceeds reasonable limits (>100 characters)
	longUsername := strings.Repeat("a", 101)

	githubProfile := GitHubProfile{
		ID:        12345,
		Login:     longUsername,
		Email:     "test@example.com",
		AvatarURL: "https://avatars.githubusercontent.com/u/12345",
	}

	user, err := CreateUserFromGitHubProfile(ctx, mockRepo, githubProfile)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "username too long")

	mockRepo.AssertExpectations(t)
}

// TestGetUserWithInvalidObjectID tests handling malformed user ID queries
func TestGetUserWithInvalidObjectID(t *testing.T) {
	mockRepo := new(MockUserRepository)
	ctx := context.Background()

	// Test with zero ObjectID
	zeroID := primitive.ObjectID{}
	user, err := GetUserByID(ctx, mockRepo, zeroID)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "invalid user ID")

	// Test with database error for valid but non-existent ID
	validID := primitive.NewObjectID()
	mockRepo.On("GetUserByID", ctx, validID).Return(nil, errors.New("user not found"))

	user, err = GetUserByID(ctx, mockRepo, validID)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "user not found")

	mockRepo.AssertExpectations(t)
}