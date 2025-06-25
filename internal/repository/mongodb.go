package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"claudy/internal/models"
)

// MongoUserRepository implements UserRepository interface using MongoDB
type MongoUserRepository struct {
	collection *mongo.Collection
}

// NewMongoUserRepository creates a new MongoDB user repository
func NewMongoUserRepository(database *mongo.Database) *MongoUserRepository {
	collection := database.Collection("users")
	
	// Create indexes
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Index on github_id for fast lookups
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "github_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	
	_, err := collection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		// Log error but don't fail - index might already exist
		fmt.Printf("Warning: Failed to create index on github_id: %v\n", err)
	}
	
	// Index on username for searches
	usernameIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "username", Value: 1}},
	}
	
	_, err = collection.Indexes().CreateOne(ctx, usernameIndex)
	if err != nil {
		fmt.Printf("Warning: Failed to create index on username: %v\n", err)
	}

	return &MongoUserRepository{
		collection: collection,
	}
}

// CreateUser creates a new user in MongoDB
func (r *MongoUserRepository) CreateUser(ctx context.Context, user *models.User) error {
	if user == nil {
		return errors.New("user cannot be nil")
	}

	// Set created timestamp
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}

	result, err := r.collection.InsertOne(ctx, user)
	if err != nil {
		// Handle duplicate key error
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("user with GitHub ID %d already exists", user.GitHubID)
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Set the ID from the insert result
	if oid, ok := result.InsertedID.(primitive.ObjectID); ok {
		user.ID = oid
	}

	return nil
}

// GetUserByGitHubID retrieves a user by their GitHub ID
func (r *MongoUserRepository) GetUserByGitHubID(ctx context.Context, githubID int64) (*models.User, error) {
	if githubID == 0 {
		return nil, errors.New("github ID cannot be zero")
	}

	var user models.User
	filter := bson.M{"github_id": githubID}
	
	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user with GitHub ID %d not found", githubID)
		}
		return nil, fmt.Errorf("failed to get user by GitHub ID: %w", err)
	}

	return &user, nil
}

// GetUserByID retrieves a user by their ObjectID
func (r *MongoUserRepository) GetUserByID(ctx context.Context, id primitive.ObjectID) (*models.User, error) {
	if id.IsZero() {
		return nil, errors.New("user ID cannot be zero")
	}

	var user models.User
	filter := bson.M{"_id": id}
	
	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("user with ID %s not found", id.Hex())
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &user, nil
}

// UpdateUser updates an existing user
func (r *MongoUserRepository) UpdateUser(ctx context.Context, user *models.User) error {
	if user == nil {
		return errors.New("user cannot be nil")
	}
	if user.ID.IsZero() {
		return errors.New("user ID cannot be zero")
	}

	filter := bson.M{"_id": user.ID}
	update := bson.M{
		"$set": bson.M{
			"username":     user.Username,
			"email":        user.Email,
			"avatar_url":   user.AvatarURL,
			"last_login":   user.LastLogin,
			"is_active":    user.IsActive,
			"preferences":  user.Preferences,
			"metadata":     user.Metadata,
		},
	}

	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("user with ID %s not found", user.ID.Hex())
	}

	return nil
}

// ListUsers retrieves a list of users with pagination
func (r *MongoUserRepository) ListUsers(ctx context.Context, limit, offset int64) ([]*models.User, error) {
	if limit <= 0 {
		limit = 50 // Default limit
	}
	if limit > 1000 {
		limit = 1000 // Maximum limit
	}

	options := options.Find().
		SetLimit(limit).
		SetSkip(offset).
		SetSort(bson.D{{Key: "created_at", Value: -1}}) // Newest first

	cursor, err := r.collection.Find(ctx, bson.M{}, options)
	if err != nil {
		return nil, fmt.Errorf("failed to find users: %w", err)
	}
	defer cursor.Close(ctx)

	var users []*models.User
	for cursor.Next(ctx) {
		var user models.User
		if err := cursor.Decode(&user); err != nil {
			return nil, fmt.Errorf("failed to decode user: %w", err)
		}
		users = append(users, &user)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return users, nil
}

// CountUsers returns the total number of users
func (r *MongoUserRepository) CountUsers(ctx context.Context) (int64, error) {
	count, err := r.collection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}
	return count, nil
}

// DeleteUser deletes a user by ID
func (r *MongoUserRepository) DeleteUser(ctx context.Context, id primitive.ObjectID) error {
	if id.IsZero() {
		return errors.New("user ID cannot be zero")
	}

	filter := bson.M{"_id": id}
	result, err := r.collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("user with ID %s not found", id.Hex())
	}

	return nil
}

// SearchUsers searches for users by username or email
func (r *MongoUserRepository) SearchUsers(ctx context.Context, query string, limit, offset int64) ([]*models.User, error) {
	if query == "" {
		return r.ListUsers(ctx, limit, offset)
	}

	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	// Create text search filter
	filter := bson.M{
		"$or": []bson.M{
			{"username": bson.M{"$regex": query, "$options": "i"}},
			{"email": bson.M{"$regex": query, "$options": "i"}},
		},
	}

	options := options.Find().
		SetLimit(limit).
		SetSkip(offset).
		SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := r.collection.Find(ctx, filter, options)
	if err != nil {
		return nil, fmt.Errorf("failed to search users: %w", err)
	}
	defer cursor.Close(ctx)

	var users []*models.User
	for cursor.Next(ctx) {
		var user models.User
		if err := cursor.Decode(&user); err != nil {
			return nil, fmt.Errorf("failed to decode user: %w", err)
		}
		users = append(users, &user)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %w", err)
	}

	return users, nil
}

// GetCollection returns the underlying MongoDB collection (for testing)
func (r *MongoUserRepository) GetCollection() *mongo.Collection {
	return r.collection
}

// DropCollection drops the users collection (for testing only)
func (r *MongoUserRepository) DropCollection(ctx context.Context) error {
	return r.collection.Drop(ctx)
}