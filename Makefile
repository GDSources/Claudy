# Claudy Backend Makefile
# Provides convenient commands for development, testing, and deployment

.PHONY: help dev build test clean docker-* lint fmt deps

# Default target
.DEFAULT_GOAL := help

# Colors for output
COLOR_RESET   = \033[0m
COLOR_INFO    = \033[36m
COLOR_SUCCESS = \033[32m
COLOR_WARNING = \033[33m
COLOR_ERROR   = \033[31m

# Project configuration
PROJECT_NAME := claudy-backend
VERSION := $(shell git describe --tags --always --dirty)
BUILD_TIME := $(shell date +%FT%T%z)
GO_VERSION := $(shell go version | awk '{print $$3}')

# Build flags
LDFLAGS := -ldflags "\
	-X main.version=${VERSION} \
	-X main.buildTime=${BUILD_TIME} \
	-X main.goVersion=${GO_VERSION} \
	-w -s"

##@ Help
help: ## Display this help message
	@echo "$(COLOR_INFO)Claudy Backend Development Commands$(COLOR_RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make $(COLOR_SUCCESS)<target>$(COLOR_RESET)\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(COLOR_SUCCESS)%-15s$(COLOR_RESET) %s\n", $$1, $$2 } /^##@/ { printf "\n$(COLOR_WARNING)%s$(COLOR_RESET)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development
dev: ## Start development environment with Docker
	@echo "$(COLOR_INFO)Starting development environment...$(COLOR_RESET)"
	@./scripts/docker-dev.sh start

dev-stop: ## Stop development environment
	@echo "$(COLOR_INFO)Stopping development environment...$(COLOR_RESET)"
	@./scripts/docker-dev.sh stop

dev-restart: ## Restart development environment
	@echo "$(COLOR_INFO)Restarting development environment...$(COLOR_RESET)"
	@./scripts/docker-dev.sh restart

dev-logs: ## Show development logs
	@./scripts/docker-dev.sh logs

dev-shell: ## Open shell in development container
	@./scripts/docker-dev.sh exec

dev-status: ## Show development environment status
	@./scripts/docker-dev.sh status

##@ Building
build: ## Build the application binary
	@echo "$(COLOR_INFO)Building $(PROJECT_NAME)...$(COLOR_RESET)"
	@CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(PROJECT_NAME) ./cmd/server
	@echo "$(COLOR_SUCCESS)Build completed: bin/$(PROJECT_NAME)$(COLOR_RESET)"

build-race: ## Build with race detection
	@echo "$(COLOR_INFO)Building with race detection...$(COLOR_RESET)"
	@go build -race $(LDFLAGS) -o bin/$(PROJECT_NAME)-race ./cmd/server

build-linux: ## Build for Linux (cross-compilation)
	@echo "$(COLOR_INFO)Building for Linux...$(COLOR_RESET)"
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(PROJECT_NAME)-linux ./cmd/server

build-all: build build-race build-linux ## Build all variants

##@ Testing
test: ## Run unit tests
	@echo "$(COLOR_INFO)Running unit tests...$(COLOR_RESET)"
	@go test ./... -v

test-short: ## Run unit tests (short mode)
	@echo "$(COLOR_INFO)Running unit tests (short mode)...$(COLOR_RESET)"
	@go test ./... -short

test-race: ## Run tests with race detection
	@echo "$(COLOR_INFO)Running tests with race detection...$(COLOR_RESET)"
	@go test ./... -race

test-cover: ## Run tests with coverage
	@echo "$(COLOR_INFO)Running tests with coverage...$(COLOR_RESET)"
	@go test ./... -coverprofile=coverage.out
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(COLOR_SUCCESS)Coverage report generated: coverage.html$(COLOR_RESET)"

test-integration: ## Run integration tests with Docker
	@echo "$(COLOR_INFO)Running integration tests...$(COLOR_RESET)"
	@./scripts/docker-dev.sh test-integration

test-bench: ## Run benchmark tests
	@echo "$(COLOR_INFO)Running benchmark tests...$(COLOR_RESET)"
	@go test ./... -bench=. -benchmem

test-docker: ## Run all tests in Docker environment
	@echo "$(COLOR_INFO)Running tests in Docker...$(COLOR_RESET)"
	@./scripts/docker-dev.sh test

##@ Code Quality
lint: ## Run linter
	@echo "$(COLOR_INFO)Running linter...$(COLOR_RESET)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "$(COLOR_WARNING)golangci-lint not installed, using go vet...$(COLOR_RESET)"; \
		go vet ./...; \
	fi

fmt: ## Format code
	@echo "$(COLOR_INFO)Formatting code...$(COLOR_RESET)"
	@go fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	fi

vet: ## Run go vet
	@echo "$(COLOR_INFO)Running go vet...$(COLOR_RESET)"
	@go vet ./...

staticcheck: ## Run staticcheck
	@echo "$(COLOR_INFO)Running staticcheck...$(COLOR_RESET)"
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "$(COLOR_WARNING)staticcheck not installed$(COLOR_RESET)"; \
		echo "Install with: go install honnef.co/go/tools/cmd/staticcheck@latest"; \
	fi

check: fmt vet lint ## Run all code quality checks

##@ Dependencies
deps: ## Download and tidy dependencies
	@echo "$(COLOR_INFO)Downloading dependencies...$(COLOR_RESET)"
	@go mod download
	@go mod tidy
	@go mod verify

deps-update: ## Update dependencies
	@echo "$(COLOR_INFO)Updating dependencies...$(COLOR_RESET)"
	@go get -u ./...
	@go mod tidy

deps-graph: ## Generate dependency graph
	@echo "$(COLOR_INFO)Generating dependency graph...$(COLOR_RESET)"
	@go mod graph > deps.txt
	@echo "$(COLOR_SUCCESS)Dependency graph saved to deps.txt$(COLOR_RESET)"

##@ Docker
docker-build: ## Build Docker image
	@echo "$(COLOR_INFO)Building Docker image...$(COLOR_RESET)"
	@docker build -t $(PROJECT_NAME):$(VERSION) .
	@docker tag $(PROJECT_NAME):$(VERSION) $(PROJECT_NAME):latest
	@echo "$(COLOR_SUCCESS)Docker image built: $(PROJECT_NAME):$(VERSION)$(COLOR_RESET)"

docker-build-dev: ## Build development Docker image
	@echo "$(COLOR_INFO)Building development Docker image...$(COLOR_RESET)"
	@docker build -f Dockerfile.dev -t $(PROJECT_NAME):dev .

docker-build-prod: ## Build production Docker image
	@echo "$(COLOR_INFO)Building production Docker image...$(COLOR_RESET)"
	@./scripts/docker-dev.sh build-prod

docker-run: ## Run Docker container
	@echo "$(COLOR_INFO)Running Docker container...$(COLOR_RESET)"
	@docker run -p 8080:8080 $(PROJECT_NAME):latest

docker-clean: ## Clean Docker resources
	@echo "$(COLOR_INFO)Cleaning Docker resources...$(COLOR_RESET)"
	@./scripts/docker-dev.sh clean

##@ Database
db-migrate: ## Run database migrations (placeholder)
	@echo "$(COLOR_INFO)Running database migrations...$(COLOR_RESET)"
	@echo "$(COLOR_WARNING)Migrations not implemented yet$(COLOR_RESET)"

db-seed: ## Seed database with development data (placeholder)
	@echo "$(COLOR_INFO)Seeding database...$(COLOR_RESET)"
	@echo "$(COLOR_WARNING)Database seeding not implemented yet$(COLOR_RESET)"

##@ Utilities
clean: ## Clean build artifacts
	@echo "$(COLOR_INFO)Cleaning build artifacts...$(COLOR_RESET)"
	@rm -rf bin/
	@rm -rf tmp/
	@rm -f coverage.out coverage.html
	@rm -f *.log
	@rm -f deps.txt
	@echo "$(COLOR_SUCCESS)Clean completed$(COLOR_RESET)"

generate: ## Generate Go code
	@echo "$(COLOR_INFO)Generating Go code...$(COLOR_RESET)"
	@go generate ./...

run: ## Run the application locally
	@echo "$(COLOR_INFO)Starting $(PROJECT_NAME) locally...$(COLOR_RESET)"
	@go run ./cmd/server

debug: ## Run with delve debugger
	@echo "$(COLOR_INFO)Starting debugger...$(COLOR_RESET)"
	@if command -v dlv >/dev/null 2>&1; then \
		dlv debug ./cmd/server; \
	else \
		echo "$(COLOR_ERROR)Delve debugger not installed$(COLOR_RESET)"; \
		echo "Install with: go install github.com/go-delve/delve/cmd/dlv@latest"; \
	fi

version: ## Show version information
	@echo "$(COLOR_INFO)Version Information:$(COLOR_RESET)"
	@echo "  Project: $(PROJECT_NAME)"
	@echo "  Version: $(VERSION)"
	@echo "  Go Version: $(GO_VERSION)"
	@echo "  Build Time: $(BUILD_TIME)"

##@ Git
git-hooks: ## Install Git hooks
	@echo "$(COLOR_INFO)Installing Git hooks...$(COLOR_RESET)"
	@cp scripts/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "$(COLOR_SUCCESS)Git hooks installed$(COLOR_RESET)"

##@ Documentation
docs: ## Generate documentation
	@echo "$(COLOR_INFO)Generating documentation...$(COLOR_RESET)"
	@if command -v godoc >/dev/null 2>&1; then \
		echo "Starting godoc server at http://localhost:6060"; \
		godoc -http=:6060; \
	else \
		echo "$(COLOR_WARNING)godoc not installed$(COLOR_RESET)"; \
		echo "Install with: go install golang.org/x/tools/cmd/godoc@latest"; \
	fi

##@ CI/CD
ci: deps check test-race test-cover ## Run CI pipeline locally

pre-commit: fmt vet lint test-short ## Run pre-commit checks

release: ## Create a release (placeholder)
	@echo "$(COLOR_INFO)Creating release...$(COLOR_RESET)"
	@echo "$(COLOR_WARNING)Release process not implemented yet$(COLOR_RESET)"

##@ All-in-one commands
setup: deps docker-build-dev ## Setup development environment
	@echo "$(COLOR_SUCCESS)Development environment setup completed$(COLOR_RESET)"

full-test: test test-race test-integration test-bench ## Run all tests

all: clean deps check build test docker-build ## Build everything