# Claudy Backend Makefile
# Simple, focused commands for development

.PHONY: help dev build test clean fmt lint

# Default target
.DEFAULT_GOAL := help

# Colors for output
COLOR_RESET   = \033[0m
COLOR_INFO    = \033[36m
COLOR_SUCCESS = \033[32m
COLOR_WARNING = \033[33m

##@ Help
help: ## Display this help message
	@echo "$(COLOR_INFO)Claudy Backend Development Commands$(COLOR_RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make $(COLOR_SUCCESS)<target>$(COLOR_RESET)\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(COLOR_SUCCESS)%-15s$(COLOR_RESET) %s\n", $$1, $$2 } /^##@/ { printf "\n$(COLOR_WARNING)%s$(COLOR_RESET)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development
dev: ## Start development environment with Docker
	@./scripts/docker-dev.sh start

dev-stop: ## Stop development environment
	@./scripts/docker-dev.sh stop

dev-logs: ## Show development logs
	@./scripts/docker-dev.sh logs

dev-shell: ## Open shell in development container
	@./scripts/docker-dev.sh exec

##@ Building
build: ## Build the application binary
	@echo "$(COLOR_INFO)Building application...$(COLOR_RESET)"
	@go build -o bin/claudy-backend ./cmd/server

##@ Testing
test: ## Run unit tests
	@go test ./... -v

test-race: ## Run tests with race detection
	@go test ./... -race

test-cover: ## Run tests with coverage
	@go test ./... -coverprofile=coverage.out
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(COLOR_SUCCESS)Coverage report: coverage.html$(COLOR_RESET)"

test-integration: ## Run integration tests with Docker
	@./scripts/docker-dev.sh test-integration

##@ Code Quality
fmt: ## Format code
	@go fmt ./...

lint: ## Run linter (if available)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		go vet ./...; \
	fi

##@ Utilities
clean: ## Clean build artifacts
	@rm -rf bin/ tmp/ coverage.out coverage.html *.log

deps: ## Download and tidy dependencies
	@go mod download
	@go mod tidy

run: ## Run the application locally
	@go run ./cmd/server