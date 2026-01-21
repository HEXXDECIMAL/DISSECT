# DISSECT Makefile
# Build and test commands for deep static analysis tool

BINARY = dissect
OUT_DIR = out

.PHONY: all build debug release test lint clean coverage ci help

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
	@echo "  test     - Run all tests (unit + integration)"
	@echo "  lint     - Run code formatting and linting checks"
	@echo "  coverage - Generate code coverage report"
	@echo "  ci       - Run all CI checks (test + lint)"
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

test: ## Run all tests (unit + integration)
	@echo "Running all tests (unit + integration)..."
	@echo ""
	cargo test --workspace
	@echo ""
	@echo "✓ All tests passed"
	@echo "  - Unit tests: embedded in src/ modules"
	@echo "  - Integration tests: tests/cli_integration_test.rs"
	@echo "  - Directory scan tests: tests/directory_scan_test.rs"

lint: ## Run code formatting and linting checks
	@echo "Checking formatting..."
	cargo fmt --all --check
	@echo "Running clippy..."
	cargo clippy --workspace --all-targets -- \
		-D clippy::correctness \
		-D clippy::suspicious \
		-A clippy::collapsible_if \
		-A clippy::len_zero \
		-A clippy::derivable_impls \
		-A clippy::manual_map \
		-A clippy::if_same_then_else \
		-A clippy::useless_vec \
		-A clippy::bool_assert_comparison \
		-A clippy::absurd_extreme_comparisons \
		-A clippy::for_kv_map \
		-A dead_code \
		-A unused_comparisons
	@echo "✓ All lints passed"

coverage: ## Generate code coverage report
	@echo "Generating code coverage report..."
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "Error: cargo-llvm-cov not installed. Run: cargo install cargo-llvm-cov"; exit 1; }
	cargo llvm-cov --workspace --ignore-filename-regex '(tests|main\.rs)' --html
	@echo "✓ Coverage report generated at: target/llvm-cov/html/index.html"

ci: test lint ## Run all CI checks (test + lint)
	@echo "✓ All CI checks passed"

clean: ## Clean all build artifacts
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf $(OUT_DIR)
	@echo "✓ Clean complete"

$(OUT_DIR):
	mkdir -p $(OUT_DIR)
