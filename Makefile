# DISSECT Makefile
# Build and test commands for deep static analysis tool

BINARY = dissect
OUT_DIR = out

.PHONY: all build debug release test lint clean help

# Default target
all: build

help: ## Show this help
	@echo "DISSECT Makefile"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build    - Build in debug mode (default)"
	@echo "  debug    - Build in debug mode"
	@echo "  release  - Build in release mode"
	@echo "  test     - Run all tests"
	@echo "  lint     - Run code formatting and linting checks"
	@echo "  clean    - Clean all build artifacts"

build: debug ## Build in debug mode (default)

debug: ## Build in debug mode
	@echo "Building $(BINARY) (debug mode, treating warnings as errors)..."
	cargo build
	@echo "✓ Debug build successful"

release: $(OUT_DIR) ## Build in release mode
	@echo "Building $(BINARY) (release mode, treating warnings as errors)..."
	cargo build --release
	cp target/release/$(BINARY) $(OUT_DIR)/
	@echo "✓ Release binary: $(OUT_DIR)/$(BINARY)"

test: ## Run all tests
	@echo "Running tests..."
	cargo test --workspace
	@echo "✓ All tests passed"

lint: ## Run code formatting and linting checks
	@echo "Checking formatting..."
	cargo fmt --all --check
	@echo "Running clippy (treating warnings as errors)..."
	cargo clippy --workspace -- -D warnings
	@echo "✓ All lints passed"

clean: ## Clean all build artifacts
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf $(OUT_DIR)
	@echo "✓ Clean complete"

$(OUT_DIR):
	mkdir -p $(OUT_DIR)
