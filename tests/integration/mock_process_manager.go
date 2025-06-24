package integration

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"claudy/internal/session"
)

// MockProcessManager implements session.ProcessManager for testing
type MockProcessManager struct {
	processes map[int]*MockProcess
	mutex     sync.RWMutex
	nextPID   int
}

// MockProcess represents a simulated Claude Code process
type MockProcess struct {
	PID       int
	Config    session.ProcessConfig
	StartTime time.Time
	Running   bool
	stdin     *MockPipe
	stdout    *MockPipe
}

// MockPipe simulates process pipes
type MockPipe struct {
	data   []byte
	closed bool
	mutex  sync.RWMutex
}

func (mp *MockPipe) Write(p []byte) (n int, err error) {
	mp.mutex.Lock()
	defer mp.mutex.Unlock()
	
	if mp.closed {
		return 0, fmt.Errorf("pipe is closed")
	}
	
	mp.data = append(mp.data, p...)
	return len(p), nil
}

func (mp *MockPipe) Read(p []byte) (n int, err error) {
	mp.mutex.RLock()
	defer mp.mutex.RUnlock()
	
	if mp.closed && len(mp.data) == 0 {
		return 0, fmt.Errorf("pipe is closed")
	}
	
	if len(mp.data) == 0 {
		return 0, nil // No data available
	}
	
	n = copy(p, mp.data)
	mp.data = mp.data[n:]
	return n, nil
}

func (mp *MockPipe) Close() error {
	mp.mutex.Lock()
	defer mp.mutex.Unlock()
	mp.closed = true
	return nil
}

// NewMockProcessManager creates a new mock process manager
func NewMockProcessManager() *MockProcessManager {
	return &MockProcessManager{
		processes: make(map[int]*MockProcess),
		nextPID:   1000,
	}
}

// StartProcess simulates starting a Claude Code process
func (m *MockProcessManager) StartProcess(ctx context.Context, config session.ProcessConfig) (*session.ProcessInfo, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Simulate validation of Claude token
	if config.ClaudeToken == "" {
		return nil, fmt.Errorf("Claude API token is required")
	}
	
	// Create workspace directory if it doesn't exist
	if err := os.MkdirAll(config.WorkspacePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workspace: %w", err)
	}
	
	// Generate a mock PID
	pid := m.nextPID
	m.nextPID++
	
	// Create mock pipes
	stdin := &MockPipe{data: make([]byte, 0), closed: false}
	stdout := &MockPipe{data: make([]byte, 0), closed: false}
	
	// Create mock process
	mockProcess := &MockProcess{
		PID:       pid,
		Config:    config,
		StartTime: time.Now(),
		Running:   true,
		stdin:     stdin,
		stdout:    stdout,
	}
	
	m.processes[pid] = mockProcess
	
	// Simulate some startup output
	stdout.Write([]byte("Claude Code mock process started\n"))
	
	return &session.ProcessInfo{
		ProcessID:     pid,
		WorkspacePath: config.WorkspacePath,
		StartTime:     mockProcess.StartTime,
		StdinPipe:     stdin,
		StdoutPipe:    stdout,
	}, nil
}

// StopProcess simulates stopping a Claude Code process
func (m *MockProcessManager) StopProcess(processID int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	process, exists := m.processes[processID]
	if !exists {
		return fmt.Errorf("process %d not found", processID)
	}
	
	process.Running = false
	process.stdin.Close()
	process.stdout.Close()
	
	delete(m.processes, processID)
	
	return nil
}

// IsProcessRunning checks if a process is still running
func (m *MockProcessManager) IsProcessRunning(processID int) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	process, exists := m.processes[processID]
	if !exists {
		return false
	}
	
	return process.Running
}

// GetProcessMetrics returns mock metrics for a process
func (m *MockProcessManager) GetProcessMetrics(processID int) (*session.ProcessMetrics, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	process, exists := m.processes[processID]
	if !exists {
		return nil, fmt.Errorf("process %d not found", processID)
	}
	
	if !process.Running {
		return nil, fmt.Errorf("process %d is not running", processID)
	}
	
	uptime := time.Since(process.StartTime)
	
	// Return mock metrics that are within acceptable limits
	return &session.ProcessMetrics{
		MemoryUsageMB: 128, // Well under the 512MB limit
		CPUUsage:      25,  // Well under the 100% limit  
		DiskUsageMB:   10,  // Small disk usage
		Uptime:        uptime,
	}, nil
}

// GetProcessCount returns the number of running processes (for testing)
func (m *MockProcessManager) GetProcessCount() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	count := 0
	for _, process := range m.processes {
		if process.Running {
			count++
		}
	}
	return count
}

// Cleanup stops all running processes (for testing)
func (m *MockProcessManager) Cleanup() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	for pid, process := range m.processes {
		if process.Running {
			process.Running = false
			process.stdin.Close()
			process.stdout.Close()
		}
		delete(m.processes, pid)
	}
}