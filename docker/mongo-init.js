// MongoDB initialization script for Claudy development environment
// This script runs when the MongoDB container starts for the first time

// Switch to the claudy_dev database
db = db.getSiblingDB('claudy_dev');

// Create a development user with read/write access
db.createUser({
  user: 'claudy_dev',
  pwd: 'devpassword',
  roles: [
    {
      role: 'readWrite',
      db: 'claudy_dev'
    }
  ]
});

// Create initial collections with indexes for optimal performance
// Users collection
db.createCollection('users');
db.users.createIndex({ "github_id": 1 }, { unique: true });
db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true });
db.users.createIndex({ "created_at": 1 });

// Sessions collection (for Claude Code sessions)
db.createCollection('sessions');
db.sessions.createIndex({ "user_id": 1 });
db.sessions.createIndex({ "session_id": 1 }, { unique: true });
db.sessions.createIndex({ "created_at": 1 });
db.sessions.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });

// Files collection (for file metadata)
db.createCollection('files');
db.files.createIndex({ "user_id": 1 });
db.files.createIndex({ "workspace_id": 1 });
db.files.createIndex({ "file_path": 1 });
db.files.createIndex({ "created_at": 1 });

// Workspaces collection
db.createCollection('workspaces');
db.workspaces.createIndex({ "user_id": 1 });
db.workspaces.createIndex({ "workspace_id": 1 }, { unique: true });
db.workspaces.createIndex({ "created_at": 1 });

// Insert some development data for testing
print('Inserting development test data...');

// Sample user for development
db.users.insertOne({
  _id: ObjectId(),
  github_id: "123456789",
  username: "dev_user",
  name: "Development User",
  email: "dev@claudy.dev",
  avatar_url: "https://avatars.githubusercontent.com/u/123456789",
  created_at: new Date(),
  updated_at: new Date(),
  last_login: new Date()
});

print('Development database initialization completed successfully!');
print('Database: claudy_dev');
print('Collections created: users, sessions, files, workspaces');
print('Indexes created for optimal query performance');
print('Sample development user inserted');

// Switch to claudy_test database for testing
db = db.getSiblingDB('claudy_test');

// Create test user
db.createUser({
  user: 'claudy_test',
  pwd: 'testpassword',
  roles: [
    {
      role: 'readWrite',
      db: 'claudy_test'
    }
  ]
});

// Create same collections for testing
db.createCollection('users');
db.users.createIndex({ "github_id": 1 }, { unique: true });
db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true });

db.createCollection('sessions');
db.sessions.createIndex({ "user_id": 1 });
db.sessions.createIndex({ "session_id": 1 }, { unique: true });
db.sessions.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });

db.createCollection('files');
db.files.createIndex({ "user_id": 1 });
db.files.createIndex({ "workspace_id": 1 });

db.createCollection('workspaces');
db.workspaces.createIndex({ "user_id": 1 });
db.workspaces.createIndex({ "workspace_id": 1 }, { unique: true });

print('Test database initialization completed!');
print('Database: claudy_test');
print('Test collections and indexes created');