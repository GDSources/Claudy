package files

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"
)

// FileInfo represents information about a file
type FileInfo struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	Path        string `json:"path"`
	IsDirectory bool   `json:"is_directory"`
}

// UploadResult represents the result of a file upload
type UploadResult struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	Path     string `json:"path"`
}

// FileSystem interface abstracts filesystem operations for testing
type FileSystem interface {
	WriteFile(filename string, data []byte, perm os.FileMode) error
	ReadDir(dirname string) ([]os.DirEntry, error)
	Stat(name string) (os.FileInfo, error)
	MkdirAll(path string, perm os.FileMode) error
	RemoveAll(path string) error
	CalculateDirectorySize(path string) (int64, error)
}

// LocalFileSystem implements FileSystem for real filesystem operations
type LocalFileSystem struct{}

func (lfs *LocalFileSystem) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return os.WriteFile(filename, data, perm)
}

func (lfs *LocalFileSystem) ReadDir(dirname string) ([]os.DirEntry, error) {
	return os.ReadDir(dirname)
}

func (lfs *LocalFileSystem) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (lfs *LocalFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (lfs *LocalFileSystem) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

func (lfs *LocalFileSystem) CalculateDirectorySize(path string) (int64, error) {
	var totalSize int64
	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	return totalSize, err
}

// FileManager handles file operations within workspaces
type FileManager struct {
	fs           FileSystem
	maxFileSize  int64
	maxTotalSize int64
	mutex        sync.RWMutex
}

// NewFileManager creates a new file manager instance
func NewFileManager(maxFileSize, maxTotalSize int64) *FileManager {
	return &FileManager{
		fs:           &LocalFileSystem{},
		maxFileSize:  maxFileSize,
		maxTotalSize: maxTotalSize,
	}
}

// NewFileManagerWithFS creates a new file manager with custom filesystem (for testing)
func NewFileManagerWithFS(fs FileSystem, maxFileSize, maxTotalSize int64) *FileManager {
	return &FileManager{
		fs:           fs,
		maxFileSize:  maxFileSize,
		maxTotalSize: maxTotalSize,
	}
}

// UploadFile uploads a file to the specified workspace
func (fm *FileManager) UploadFile(ctx context.Context, workspacePath, filename, content, encoding string) (*UploadResult, error) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	// Validate filename
	if err := fm.validateFilename(filename); err != nil {
		return nil, err
	}

	// Validate content encoding
	if encoding == "utf-8" && !utf8.ValidString(content) {
		return nil, fmt.Errorf("non-UTF8 content detected")
	}

	// Check file size limit
	contentSize := int64(len(content))
	if contentSize > fm.maxFileSize {
		return nil, fmt.Errorf("file size exceeds limit: %d bytes > %d bytes", contentSize, fm.maxFileSize)
	}

	// Verify workspace exists and is a directory
	workspaceInfo, err := fm.fs.Stat(workspacePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("workspace does not exist: %s", workspacePath)
		}
		return nil, fmt.Errorf("failed to access workspace: %w", err)
	}
	if !workspaceInfo.IsDir() {
		return nil, fmt.Errorf("workspace path is not a directory: %s", workspacePath)
	}

	// Check workspace size limit
	currentSize, err := fm.fs.CalculateDirectorySize(workspacePath)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate workspace size: %w", err)
	}
	if currentSize+contentSize > fm.maxTotalSize {
		return nil, fmt.Errorf("workspace size limit exceeded: %d + %d > %d bytes", currentSize, contentSize, fm.maxTotalSize)
	}

	// Perform security checks
	if err := fm.performSecurityChecks(filename, content); err != nil {
		return nil, err
	}

	// Write file
	filePath := filepath.Join(workspacePath, filename)
	if err := fm.fs.WriteFile(filePath, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("failed to write file: %w", err)
	}

	return &UploadResult{
		Filename: filename,
		Size:     contentSize,
		Path:     filePath,
	}, nil
}

// ListFiles lists all files in the specified workspace
func (fm *FileManager) ListFiles(ctx context.Context, workspacePath string) ([]FileInfo, error) {
	fm.mutex.RLock()
	defer fm.mutex.RUnlock()

	entries, err := fm.fs.ReadDir(workspacePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read workspace directory: %w", err)
	}

	files := make([]FileInfo, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue // Skip files we can't stat
		}

		fileInfo := FileInfo{
			Name:        entry.Name(),
			Size:        info.Size(),
			Path:        filepath.Join(workspacePath, entry.Name()),
			IsDirectory: entry.IsDir(),
		}
		files = append(files, fileInfo)
	}

	return files, nil
}

// CleanupWorkspace removes all files from a workspace
func (fm *FileManager) CleanupWorkspace(ctx context.Context, workspacePath string) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	if err := fm.fs.RemoveAll(workspacePath); err != nil {
		return fmt.Errorf("failed to cleanup workspace: %w", err)
	}
	return nil
}

// GetWorkspaceSize returns the total size of files in a workspace
func (fm *FileManager) GetWorkspaceSize(ctx context.Context, workspacePath string) (int64, error) {
	fm.mutex.RLock()
	defer fm.mutex.RUnlock()

	return fm.fs.CalculateDirectorySize(workspacePath)
}

// validateFilename validates the filename for security
func (fm *FileManager) validateFilename(filename string) error {
	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}

	// Check for directory traversal
	if strings.Contains(filename, "..") {
		return fmt.Errorf("invalid filename: contains directory traversal")
	}

	// Check for absolute paths
	if filepath.IsAbs(filename) {
		return fmt.Errorf("invalid filename: absolute paths not allowed")
	}

	// Check for hidden files (starting with dot)
	if strings.HasPrefix(filename, ".") {
		return fmt.Errorf("invalid filename: hidden files not allowed")
	}

	return nil
}

// performSecurityChecks performs additional security validation
func (fm *FileManager) performSecurityChecks(filename, content string) error {
	// Check for malicious file extensions
	maliciousExtensions := []string{".sh", ".bat", ".exe", ".cmd", ".com", ".scr", ".pif"}
	ext := strings.ToLower(filepath.Ext(filename))
	for _, malExt := range maliciousExtensions {
		if ext == malExt {
			return fmt.Errorf("potentially malicious file detected: extension %s not allowed", ext)
		}
	}

	// Check for shell script shebang
	if strings.HasPrefix(content, "#!") {
		return fmt.Errorf("potentially malicious file detected: executable scripts not allowed")
	}

	// Check for binary content (contains null bytes)
	if strings.Contains(content, "\x00") {
		return fmt.Errorf("non-UTF8 content detected: binary files not allowed")
	}

	// Check for suspicious content patterns
	suspiciousPatterns := []string{
		"rm -rf",
		"sudo",
		"eval(",
		"exec(",
		"system(",
		"shell_exec",
		"passthru",
		"proc_open",
	}
	
	contentLower := strings.ToLower(content)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(contentLower, pattern) {
			return fmt.Errorf("potentially malicious file detected: suspicious content pattern found")
		}
	}

	return nil
}

// FileUploadMessage represents the WebSocket file upload message structure
type FileUploadMessage struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// FileUploadedResponse represents the WebSocket file uploaded response
type FileUploadedResponse struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	Path     string `json:"path"`
}

// Constants for file management
const (
	MaxFileSize     = 10 * 1024 * 1024  // 10MB
	MaxWorkspaceSize = 100 * 1024 * 1024 // 100MB
)