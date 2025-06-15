# Default recipe to display help
default:
    @just --list

# List of available commands
alias help := default

# Build the dalfox binary
build:
    @echo "Building dalfox binary..."
    go build -o dalfox .

# Run go unit tests
test:
    @echo "Running Go unit tests..."
    go test ./...

# Run linter and fix issues
fix:
    @echo "Formatting code..."
    go fmt ./...
    @echo "Vetting code..."
    go vet ./...
    # Check if golangci-lint is installed and run it if available
    @if command -v golangci-lint > /dev/null 2>&1; then \
        echo "Running golangci-lint..."; \
        golangci-lint run --fix; \
    else \
        echo "Warning: golangci-lint not installed. Skipping linting."; \
    fi

# Update Go dependencies
update:
    @echo "Updating Go modules..."
    go get -u ./...
    go mod tidy

# Clean build artifacts
clean:
    @echo "Cleaning build artifacts..."
    rm -f dalfox
    rm -rf vendor
    go clean

# Set up the test environment for functional tests
test-functional-setup:
    @echo "Setting up functional test environment..."
    go mod vendor
    go build -o dalfox .

# Run the functional tests (requires RSpec)
test-functional: test-functional-setup
    @echo "Running functional tests..."
    @if command -v bundle > /dev/null 2>&1; then \
        bundle exec rspec spec/functional_tests/**/*_spec.rb; \
    else \
        echo "Error: Ruby bundler is not installed. Please install Ruby and Bundler first."; \
        exit 1; \
    fi

# Run all tests (unit and functional)
test-all:
    @echo "Running all tests..."
    @just test
    @just test-functional

# Full development workflow: clean, update, build, test
dev: clean update build test
    @echo "Development workflow completed successfully!"

# Serve documentation site
docs-serve:
    @echo "Starting documentation server..."
    cd docs || { echo "Error: Directory 'docs' not found"; exit 1; }
    if ! command -v bundle > /dev/null 2>&1; then \
        echo "Error: Ruby bundler is not installed. Please install Ruby and Bundler first."; \
        exit 1; \
    fi
    if ! bundle check > /dev/null 2>&1; then \
        echo "Error: Dependencies are not met. Please run 'just docs-install'."; \
        exit 1; \
    fi
    bundle exec jekyll s

# Install documentation site dependencies
docs-install:
    @echo "Installing documentation dependencies..."
    cd docs || { echo "Error: Directory 'docs' not found"; exit 1; }
    if ! command -v bundle > /dev/null 2>&1; then \
        echo "Error: Ruby bundler is not installed. Please install Ruby and Bundler first."; \
        exit 1; \
    fi
    bundle install

# Check remote assets
assets-check:
    #!/usr/bin/env sh
    endpoints="xss-portswigger xss-payloadbox wl-params wl-assetnote-params"

    for target in $endpoints; do
        echo "Checking ${target}..."
        curl -s "https://assets.hahwul.com/${target}.json" | python3 -m json.tool || \
        curl -s "https://assets.hahwul.com/${target}.json"
    done
