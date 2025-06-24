package files

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock filesystem interface for testing
type MockFileSystem struct {
	mock.Mock
}

func (m *MockFileSystem) WriteFile(filename string, data []byte, perm os.FileMode) error {
	args := m.Called(filename, data, perm)
	return args.Error(0)
}

func (m *MockFileSystem) ReadDir(dirname string) ([]os.DirEntry, error) {
	args := m.Called(dirname)
	return args.Get(0).([]os.DirEntry), args.Error(1)
}

func (m *MockFileSystem) Stat(name string) (os.FileInfo, error) {
	args := m.Called(name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(os.FileInfo), args.Error(1)
}

func (m *MockFileSystem) MkdirAll(path string, perm os.FileMode) error {
	args := m.Called(path, perm)
	return args.Error(0)
}

func (m *MockFileSystem) RemoveAll(path string) error {
	args := m.Called(path)
	return args.Error(0)
}

func (m *MockFileSystem) CalculateDirectorySize(path string) (int64, error) {
	args := m.Called(path)
	return args.Get(0).(int64), args.Error(1)
}

// Mock file info for testing
type MockFileInfo struct {
	name  string
	size  int64
	mode  os.FileMode
	isDir bool
}

func (m MockFileInfo) Name() string       { return m.name }
func (m MockFileInfo) Size() int64        { return m.size }
func (m MockFileInfo) Mode() os.FileMode  { return m.mode }
func (m MockFileInfo) ModTime() time.Time { return time.Now() }
func (m MockFileInfo) IsDir() bool        { return m.isDir }
func (m MockFileInfo) Sys() interface{}   { return nil }

// Mock directory entry for testing
type MockDirEntry struct {
	name    string
	isDir   bool
	fileInfo MockFileInfo
}

func (m MockDirEntry) Name() string               { return m.name }
func (m MockDirEntry) IsDir() bool                { return m.isDir }
func (m MockDirEntry) Type() os.FileMode          { return m.fileInfo.Mode() }
func (m MockDirEntry) Info() (os.FileInfo, error) { return m.fileInfo, nil }

// TestFileUploadValidFile tests successful file upload
func TestFileUploadValidFile(t *testing.T) {
	mockFS := &MockFileSystem{}
	manager := &FileManager{
		fs:           mockFS,
		maxFileSize:  10 * 1024 * 1024, // 10MB
		maxTotalSize: 100 * 1024 * 1024, // 100MB
	}

	workspacePath := "/test/workspace"
	filename := "test.py"
	content := "print('Hello World')"
	
	// Mock filesystem operations
	mockFS.On("Stat", workspacePath).Return(MockFileInfo{name: "workspace", isDir: true}, nil)
	mockFS.On("CalculateDirectorySize", workspacePath).Return(int64(1024), nil) // 1KB existing
	mockFS.On("WriteFile", filepath.Join(workspacePath, filename), []byte(content), os.FileMode(0644)).Return(nil)

	// Test upload
	result, err := manager.UploadFile(context.Background(), workspacePath, filename, content, "utf-8")
	
	require.NoError(t, err)
	assert.Equal(t, filename, result.Filename)
	assert.Equal(t, int64(len(content)), result.Size)
	assert.Equal(t, filepath.Join(workspacePath, filename), result.Path)
	
	mockFS.AssertExpectations(t)
}

// TestWorkspaceFileListing tests file listing functionality
func TestWorkspaceFileListing(t *testing.T) {
	mockFS := &MockFileSystem{}
	manager := &FileManager{
		fs:           mockFS,
		maxFileSize:  10 * 1024 * 1024,
		maxTotalSize: 100 * 1024 * 1024,
	}

	workspacePath := "/test/workspace"
	
	// Mock directory entries
	entries := []os.DirEntry{
		MockDirEntry{name: "app.py", isDir: false, fileInfo: MockFileInfo{name: "app.py", size: 1024}},
		MockDirEntry{name: "config.json", isDir: false, fileInfo: MockFileInfo{name: "config.json", size: 512}},
		MockDirEntry{name: "subdir", isDir: true, fileInfo: MockFileInfo{name: "subdir", size: 0, isDir: true}},
	}
	
	mockFS.On("ReadDir", workspacePath).Return(entries, nil)

	// Test listing
	files, err := manager.ListFiles(context.Background(), workspacePath)
	
	require.NoError(t, err)
	assert.Len(t, files, 3)
	assert.Equal(t, "app.py", files[0].Name)
	assert.Equal(t, int64(1024), files[0].Size)
	assert.Equal(t, false, files[0].IsDirectory)
	assert.Equal(t, "subdir", files[2].Name)
	assert.Equal(t, true, files[2].IsDirectory)
	
	mockFS.AssertExpectations(t)
}

// TestFileUploadExceedsSize tests file size limit enforcement
func TestFileUploadExceedsSize(t *testing.T) {
	mockFS := &MockFileSystem{}
	manager := &FileManager{
		fs:           mockFS,
		maxFileSize:  1024, // 1KB limit
		maxTotalSize: 100 * 1024 * 1024,
	}

	workspacePath := "/test/workspace"
	filename := "large_file.txt"
	content := strings.Repeat("a", 2048) // 2KB content
	
	// Test upload - should fail due to size
	_, err := manager.UploadFile(context.Background(), workspacePath, filename, content, "utf-8")
	
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file size exceeds limit")
}

// TestFileUploadMaliciousContent tests malicious content detection
func TestFileUploadMaliciousContent(t *testing.T) {
	testCases := []struct {
		name     string
		filename string
		content  string
		errMsg   string
	}{
		{
			name:     "executable script",
			filename: "malicious.sh",
			content:  "#!/bin/bash\nrm -rf /",
			errMsg:   "potentially malicious file detected",
		},
		{
			name:     "directory traversal",
			filename: "../../../etc/passwd",
			content:  "root:x:0:0:root:/root:/bin/bash",
			errMsg:   "invalid filename: contains directory traversal",
		},
		{
			name:     "binary content",
			filename: "binary.txt",
			content:  "\x00\x01\x02\x03\x04\x05",
			errMsg:   "non-UTF8 content detected",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockFS := &MockFileSystem{}
			manager := &FileManager{
				fs:           mockFS,
				maxFileSize:  10 * 1024 * 1024,
				maxTotalSize: 100 * 1024 * 1024,
			}

			// Setup mocks only for tests that get past filename validation
			if tc.name == "executable script" || tc.name == "binary content" {
				mockFS.On("Stat", "/test/workspace").Return(MockFileInfo{name: "workspace", isDir: true}, nil)
				mockFS.On("CalculateDirectorySize", "/test/workspace").Return(int64(1024), nil)
			}

			_, err := manager.UploadFile(context.Background(), "/test/workspace", tc.filename, tc.content, "utf-8")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)

			if tc.name == "executable script" || tc.name == "binary content" {
				mockFS.AssertExpectations(t)
			}
		})
	}
}

// TestFileUploadInvalidEncoding tests non-UTF8 file handling
func TestFileUploadInvalidEncoding(t *testing.T) {
	mockFS := &MockFileSystem{}
	manager := &FileManager{
		fs:           mockFS,
		maxFileSize:  10 * 1024 * 1024,
		maxTotalSize: 100 * 1024 * 1024,
	}

	workspacePath := "/test/workspace"
	filename := "invalid.txt"
	// Invalid UTF-8 sequence
	content := string([]byte{0xff, 0xfe, 0xfd})
	
	// Test upload - should fail due to encoding
	_, err := manager.UploadFile(context.Background(), workspacePath, filename, content, "utf-8")
	
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-UTF8 content detected")
}

// TestFileUploadToNonexistentWorkspace tests missing workspace handling
func TestFileUploadToNonexistentWorkspace(t *testing.T) {
	mockFS := &MockFileSystem{}
	manager := &FileManager{
		fs:           mockFS,
		maxFileSize:  10 * 1024 * 1024,
		maxTotalSize: 100 * 1024 * 1024,
	}

	workspacePath := "/nonexistent/workspace"
	filename := "test.txt"
	content := "test content"
	
	// Mock workspace doesn't exist
	mockFS.On("Stat", workspacePath).Return(nil, os.ErrNotExist)

	// Test upload - should fail due to missing workspace
	_, err := manager.UploadFile(context.Background(), workspacePath, filename, content, "utf-8")
	
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workspace does not exist")
	
	mockFS.AssertExpectations(t)
}

// TestFileUploadWithInsufficientDiskSpace tests storage failure handling
func TestFileUploadWithInsufficientDiskSpace(t *testing.T) {
	mockFS := &MockFileSystem{}
	manager := &FileManager{
		fs:           mockFS,
		maxFileSize:  10 * 1024 * 1024,
		maxTotalSize: 100 * 1024 * 1024,
	}

	workspacePath := "/test/workspace"
	filename := "test.txt"
	content := "test content"
	
	// Mock filesystem operations
	mockFS.On("Stat", workspacePath).Return(MockFileInfo{name: "workspace", isDir: true}, nil)
	mockFS.On("CalculateDirectorySize", workspacePath).Return(int64(1024), nil)
	mockFS.On("WriteFile", filepath.Join(workspacePath, filename), []byte(content), os.FileMode(0644)).Return(errors.New("no space left on device"))

	// Test upload - should fail due to disk space
	_, err := manager.UploadFile(context.Background(), workspacePath, filename, content, "utf-8")
	
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write file")
	
	mockFS.AssertExpectations(t)
}

// TestConcurrentFileOperations tests thread safety
func TestConcurrentFileOperations(t *testing.T) {
	mockFS := &MockFileSystem{}
	manager := &FileManager{
		fs:           mockFS,
		maxFileSize:  10 * 1024 * 1024,
		maxTotalSize: 100 * 1024 * 1024,
		mutex:        sync.RWMutex{},
	}

	workspacePath := "/test/workspace"
	
	// Mock filesystem operations for concurrent uploads
	for i := 0; i < 10; i++ {
		filename := filepath.Join(workspacePath, "test"+string(rune('0'+i))+".txt")
		mockFS.On("Stat", workspacePath).Return(MockFileInfo{name: "workspace", isDir: true}, nil)
		mockFS.On("CalculateDirectorySize", workspacePath).Return(int64(1024), nil)
		mockFS.On("WriteFile", filename, mock.Anything, os.FileMode(0644)).Return(nil)
	}

	// Concurrent uploads
	var wg sync.WaitGroup
	errors := make(chan error, 10)
	
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			filename := "test" + string(rune('0'+id)) + ".txt"
			content := "test content " + string(rune('0'+id))
			_, err := manager.UploadFile(context.Background(), workspacePath, filename, content, "utf-8")
			if err != nil {
				errors <- err
			}
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	// Check no errors occurred
	for err := range errors {
		t.Errorf("Concurrent upload failed: %v", err)
	}
	
	mockFS.AssertExpectations(t)
}

// TestFileUploadWithCorruptedWorkspaceDir tests filesystem corruption handling
func TestFileUploadWithCorruptedWorkspaceDir(t *testing.T) {
	mockFS := &MockFileSystem{}
	manager := &FileManager{
		fs:           mockFS,
		maxFileSize:  10 * 1024 * 1024,
		maxTotalSize: 100 * 1024 * 1024,
	}

	workspacePath := "/test/workspace"
	filename := "test.txt"
	content := "test content"
	
	// Mock corrupted workspace (exists but not a directory)
	mockFS.On("Stat", workspacePath).Return(MockFileInfo{name: "workspace", isDir: false}, nil)

	// Test upload - should fail due to corrupted workspace
	_, err := manager.UploadFile(context.Background(), workspacePath, filename, content, "utf-8")
	
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workspace path is not a directory")
	
	mockFS.AssertExpectations(t)
}

// TestWorkspaceCleanupFailure tests cleanup error handling
func TestWorkspaceCleanupFailure(t *testing.T) {
	mockFS := &MockFileSystem{}
	manager := &FileManager{
		fs:           mockFS,
		maxFileSize:  10 * 1024 * 1024,
		maxTotalSize: 100 * 1024 * 1024,
	}

	workspacePath := "/test/workspace"
	
	// Mock cleanup failure
	mockFS.On("RemoveAll", workspacePath).Return(errors.New("permission denied"))

	// Test cleanup - should handle error gracefully
	err := manager.CleanupWorkspace(context.Background(), workspacePath)
	
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to cleanup workspace")
	
	mockFS.AssertExpectations(t)
}

// TestWorkspaceSizeLimitEnforcement tests workspace size limit
func TestWorkspaceSizeLimitEnforcement(t *testing.T) {
	mockFS := &MockFileSystem{}
	manager := &FileManager{
		fs:           mockFS,
		maxFileSize:  10 * 1024 * 1024,
		maxTotalSize: 1024, // 1KB limit
	}

	workspacePath := "/test/workspace"
	filename := "test.txt"
	content := "test content"
	
	// Mock workspace already at size limit
	mockFS.On("Stat", workspacePath).Return(MockFileInfo{name: "workspace", isDir: true}, nil)
	mockFS.On("CalculateDirectorySize", workspacePath).Return(int64(2048), nil) // 2KB existing

	// Test upload - should fail due to workspace size limit
	_, err := manager.UploadFile(context.Background(), workspacePath, filename, content, "utf-8")
	
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workspace size limit exceeded")
	
	mockFS.AssertExpectations(t)
}

// TestFileListingErrorHandling tests error handling in file listing
func TestFileListingErrorHandling(t *testing.T) {
	mockFS := &MockFileSystem{}
	manager := &FileManager{
		fs:           mockFS,
		maxFileSize:  10 * 1024 * 1024,
		maxTotalSize: 100 * 1024 * 1024,
	}

	workspacePath := "/test/workspace"
	
	// Mock directory read failure
	mockFS.On("ReadDir", workspacePath).Return([]os.DirEntry{}, errors.New("permission denied"))

	// Test listing - should handle error gracefully
	_, err := manager.ListFiles(context.Background(), workspacePath)
	
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read workspace directory")
	
	mockFS.AssertExpectations(t)
}

// TestFilePathValidation tests file path security
func TestFilePathValidation(t *testing.T) {
	testCases := []struct {
		name     string
		filename string
		errMsg   string
	}{
		{
			name:     "directory traversal with dots",
			filename: "../../../etc/passwd",
			errMsg:   "invalid filename: contains directory traversal",
		},
		{
			name:     "absolute path",
			filename: "/etc/passwd",
			errMsg:   "invalid filename: absolute paths not allowed",
		},
		{
			name:     "hidden file",
			filename: ".bashrc",
			errMsg:   "invalid filename: hidden files not allowed",
		},
		{
			name:     "empty filename",
			filename: "",
			errMsg:   "filename cannot be empty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockFS := &MockFileSystem{}
			manager := &FileManager{
				fs:           mockFS,
				maxFileSize:  10 * 1024 * 1024,
				maxTotalSize: 100 * 1024 * 1024,
			}

			_, err := manager.UploadFile(context.Background(), "/test/workspace", tc.filename, "content", "utf-8")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

// Benchmark tests
func BenchmarkFileUpload(b *testing.B) {
	mockFS := &MockFileSystem{}
	manager := &FileManager{
		fs:           mockFS,
		maxFileSize:  10 * 1024 * 1024,
		maxTotalSize: 100 * 1024 * 1024,
	}

	workspacePath := "/test/workspace"
	filename := "benchmark.txt"
	content := strings.Repeat("a", 1024) // 1KB content
	
	// Setup mocks for benchmark
	mockFS.On("Stat", workspacePath).Return(MockFileInfo{name: "workspace", isDir: true}, nil)
	mockFS.On("CalculateDirectorySize", workspacePath).Return(int64(0), nil)
	mockFS.On("WriteFile", filepath.Join(workspacePath, filename), []byte(content), os.FileMode(0644)).Return(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.UploadFile(context.Background(), workspacePath, filename, content, "utf-8")
	}
}

func BenchmarkFileListing(b *testing.B) {
	mockFS := &MockFileSystem{}
	manager := &FileManager{
		fs:           mockFS,
		maxFileSize:  10 * 1024 * 1024,
		maxTotalSize: 100 * 1024 * 1024,
	}

	workspacePath := "/test/workspace"
	
	// Create many mock entries
	entries := make([]os.DirEntry, 100)
	for i := 0; i < 100; i++ {
		entries[i] = MockDirEntry{
			name:     fmt.Sprintf("file%d.txt", i),
			isDir:    false,
			fileInfo: MockFileInfo{name: "file.txt", size: 1024},
		}
	}
	
	mockFS.On("ReadDir", workspacePath).Return(entries, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.ListFiles(context.Background(), workspacePath)
	}
}