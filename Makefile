.PHONY: build test clean lint fmt help install release debug bench doc

# Default target
all: build

# Build the project
build:
	cargo build

# Build release version
release:
	cargo build --release

# Build debug version  
debug:
	cargo build

# Run tests
test:
	cargo test

# Run tests with output
test-verbose:
	cargo test -- --nocapture

# Run benchmarks
bench:
	cargo bench

# Lint the code - pragmatic balance of strictness and usability
lint:
	cargo fmt --check
	cargo clippy --all-targets --all-features -- \
		-D warnings \
		-D clippy::correctness \
		-D clippy::suspicious \
		-D clippy::complexity \
		-D clippy::perf \
		-D clippy::style \
		-W clippy::pedantic \
		-W clippy::nursery \
		-A clippy::missing_errors_doc \
		-A clippy::missing_panics_doc \
		-A clippy::module_name_repetitions \
		-A clippy::similar_names \
		-A clippy::too_many_lines

# Strict linting for CI/CD
lint-strict:
	cargo fmt --check
	cargo clippy --all-targets --all-features -- -D warnings -D clippy::pedantic -W clippy::nursery
	@echo "Running additional security checks..."
	cargo audit || echo "cargo audit not installed, skipping security audit"

# Quick lint fix for development
lint-fix:
	cargo fmt
	cargo clippy --fix --all-targets --all-features --allow-dirty --allow-staged

# Format the code
fmt:
	cargo fmt

# Clean build artifacts
clean:
	cargo clean

# Install locally
install:
	cargo install --path .

# Generate documentation
doc:
	cargo doc --open

# Run the scanner on test files
test-scan:
	cargo run -- scan test_files/

# Check for security issues
audit:
	cargo audit

# Show help
help:
	@echo "Available targets:"
	@echo "  build         - Build the project"
	@echo "  release       - Build release version"
	@echo "  debug         - Build debug version"
	@echo "  test          - Run tests"
	@echo "  test-verbose  - Run tests with output"
	@echo "  bench         - Run benchmarks"
	@echo "  lint          - Lint and check formatting"
	@echo "  fmt           - Format code"
	@echo "  clean         - Clean build artifacts"
	@echo "  install       - Install locally"
	@echo "  doc           - Generate documentation"
	@echo "  test-scan     - Run scanner on test files"
	@echo "  audit         - Check for security issues"
	@echo "  help          - Show this help"