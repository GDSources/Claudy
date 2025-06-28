package websocket

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"claudy/internal/files"
	"claudy/internal/session"
)

// TestWebSocketFileUploadIntegration tests the complete file upload flow through WebSocket
func TestWebSocketFileUploadIntegration(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	mockFileManager := &MockFileManager{}
	mockSessionManager := &MockSessionManager{}

	// Setup user and session
	validClaims := createValidUserClaims()
	validToken := "valid-jwt-token"
	sessionID := primitive.NewObjectID().Hex()
	workspacePath := "/test/workspace/user123"

	// Setup JWT and Redis mocks
	mockJWT.On("ValidateToken", validToken).Return(validClaims, nil)
	mockRedis.On("GetConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(0, nil)

	// Setup session mock
	testSession := &session.ClaudeSession{
		ID:            primitive.ObjectID{},
		UserID:        validClaims.UserID,
		Status:        session.SessionStatusActive,
		WorkspacePath: workspacePath,
	}
	mockSessionManager.On("GetUserSessions", validClaims.UserID).Return([]string{sessionID})
	mockSessionManager.On("GetSession", sessionID).Return(testSession)

	// Setup file manager mock
	expectedResult := &files.UploadResult{
		Filename: "test.py",
		Size:     19,
		Path:     "/test/workspace/user123/test.py",
	}
	mockFileManager.On("UploadFile", 
		context.Background(), 
		workspacePath, 
		"test.py", 
		"print('Hello World')", 
		"utf-8",
	).Return(expectedResult, nil)

	handler := createTestHandler(mockJWT, mockRedis, mockFileManager, mockSessionManager)

	// Create connection and authenticate
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	conn, server := createTestClient(t, handler, headers, validToken)
	defer server.Close()
	defer conn.Close()

	// Connection is already authenticated via token in URL, so we can proceed directly

	// Send file upload message
	fileUploadMsg := Message{
		Type:      "file_upload",
		Content:   "uploading file",
		Timestamp: time.Now().Format(time.RFC3339),
		Data: map[string]interface{}{
			"filename": "test.py",
			"content":  "print('Hello World')",
			"encoding": "utf-8",
		},
	}
	err := conn.WriteJSON(fileUploadMsg)
	require.NoError(t, err)

	// Read file upload response
	var uploadResponse Message
	err = conn.ReadJSON(&uploadResponse)
	require.NoError(t, err)

	// Verify response
	assert.Equal(t, "file_uploaded", uploadResponse.Type)
	assert.Contains(t, uploadResponse.Content, "successfully")
	assert.Equal(t, "test.py", uploadResponse.Data["filename"])
	assert.Equal(t, float64(19), uploadResponse.Data["size"]) // JSON numbers are float64
	assert.Equal(t, "/test/workspace/user123/test.py", uploadResponse.Data["path"])

	// Close connection to trigger cleanup
	conn.Close()
	server.Close()
	
	// Wait for cleanup to complete
	time.Sleep(100 * time.Millisecond)

	// Verify all mocks were called
	mockJWT.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
	mockFileManager.AssertExpectations(t)
	mockSessionManager.AssertExpectations(t)
}

// TestWebSocketFileListIntegration tests the file listing flow
func TestWebSocketFileListIntegration(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	mockFileManager := &MockFileManager{}
	mockSessionManager := &MockSessionManager{}

	// Setup user and session
	validClaims := createValidUserClaims()
	validToken := "valid-jwt-token"
	sessionID := primitive.NewObjectID().Hex()
	workspacePath := "/test/workspace/user123"

	// Setup JWT and Redis mocks
	mockJWT.On("ValidateToken", validToken).Return(validClaims, nil)
	mockRedis.On("GetConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(0, nil)

	// Setup session mock
	testSession := &session.ClaudeSession{
		ID:            primitive.ObjectID{},
		UserID:        validClaims.UserID,
		Status:        session.SessionStatusActive,
		WorkspacePath: workspacePath,
	}
	mockSessionManager.On("GetUserSessions", validClaims.UserID).Return([]string{sessionID})
	mockSessionManager.On("GetSession", sessionID).Return(testSession)

	// Setup file manager mock
	expectedFiles := []files.FileInfo{
		{Name: "app.py", Size: 1024, Path: "/test/workspace/user123/app.py", IsDirectory: false},
		{Name: "config.json", Size: 512, Path: "/test/workspace/user123/config.json", IsDirectory: false},
	}
	mockFileManager.On("ListFiles", context.Background(), workspacePath).Return(expectedFiles, nil)

	handler := createTestHandler(mockJWT, mockRedis, mockFileManager, mockSessionManager)

	// Create connection and authenticate
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	conn, server := createTestClient(t, handler, headers, validToken)
	defer server.Close()
	defer conn.Close()

	// Connection is already authenticated via token in URL, so we can proceed directly

	// Send file list request
	fileListMsg := Message{
		Type:      "file_list",
		Content:   "get file list",
		Timestamp: time.Now().Format(time.RFC3339),
		Data:      map[string]interface{}{},
	}
	err := conn.WriteJSON(fileListMsg)
	require.NoError(t, err)

	// Read file list response
	var listResponse Message
	err = conn.ReadJSON(&listResponse)
	require.NoError(t, err)

	// Verify response
	assert.Equal(t, "file_list", listResponse.Type)
	assert.Contains(t, listResponse.Content, "successfully")
	assert.Equal(t, workspacePath, listResponse.Data["workspace_path"])

	// Verify files array
	filesData, ok := listResponse.Data["files"].([]interface{})
	require.True(t, ok, "files should be an array")
	assert.Len(t, filesData, 2)

	// Convert back to proper structure for verification
	var returnedFiles []files.FileInfo
	filesJSON, _ := json.Marshal(filesData)
	json.Unmarshal(filesJSON, &returnedFiles)

	assert.Equal(t, "app.py", returnedFiles[0].Name)
	assert.Equal(t, int64(1024), returnedFiles[0].Size)
	assert.Equal(t, false, returnedFiles[0].IsDirectory)

	// Close connection to trigger cleanup
	conn.Close()
	server.Close()
	
	// Wait for cleanup to complete
	time.Sleep(100 * time.Millisecond)

	// Verify all mocks were called
	mockJWT.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
	mockFileManager.AssertExpectations(t)
	mockSessionManager.AssertExpectations(t)
}

// TestWebSocketFileUploadNoSession tests file upload without active session
func TestWebSocketFileUploadNoSession(t *testing.T) {
	mockJWT := &MockJWTService{}
	mockRedis := &MockRedisService{}
	mockFileManager := &MockFileManager{}
	mockSessionManager := &MockSessionManager{}

	// Setup user without active session
	validClaims := createValidUserClaims()
	validToken := "valid-jwt-token"

	// Setup JWT and Redis mocks
	mockJWT.On("ValidateToken", validToken).Return(validClaims, nil)
	mockRedis.On("GetConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("IncrementConnectionCount", validClaims.UserID).Return(1, nil)
	mockRedis.On("DecrementConnectionCount", validClaims.UserID).Return(0, nil)

	// Setup session mock - no active sessions
	mockSessionManager.On("GetUserSessions", validClaims.UserID).Return([]string{})

	handler := createTestHandler(mockJWT, mockRedis, mockFileManager, mockSessionManager)

	// Create connection and authenticate
	headers := http.Header{
		"Origin": []string{"http://localhost:3000"},
	}
	conn, server := createTestClient(t, handler, headers, validToken)
	defer server.Close()
	defer conn.Close()

	// Connection is already authenticated via token in URL, so we can proceed directly

	// Send file upload message
	fileUploadMsg := Message{
		Type:      "file_upload",
		Content:   "uploading file",
		Timestamp: time.Now().Format(time.RFC3339),
		Data: map[string]interface{}{
			"filename": "test.py",
			"content":  "print('Hello World')",
			"encoding": "utf-8",
		},
	}
	err := conn.WriteJSON(fileUploadMsg)
	require.NoError(t, err)

	// Read error response
	var errorResponse Message
	err = conn.ReadJSON(&errorResponse)
	require.NoError(t, err)

	// Verify error response
	assert.Equal(t, "error", errorResponse.Type)
	assert.Contains(t, errorResponse.Content, "no active session found")

	// Close connection to trigger cleanup
	conn.Close()
	server.Close()
	
	// Wait for cleanup to complete
	time.Sleep(100 * time.Millisecond)

	// Verify mocks were called appropriately
	mockJWT.AssertExpectations(t)
	mockRedis.AssertExpectations(t)
	mockSessionManager.AssertExpectations(t)
	// File manager should not be called
	mockFileManager.AssertExpectations(t)
}