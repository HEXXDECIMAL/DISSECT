.PHONY: build lint run test clean deploy check-deploy-deps help

help:
	@echo "Available targets:"
	@echo "  make build                  Build the web-dissect binary"
	@echo "  make lint                   Run golangci-lint"
	@echo "  make test                   Run tests"
	@echo "  make run                    Run locally (requires dissect in PATH)"
	@echo "  make clean                  Clean build artifacts"
	@echo "  make deploy                 Deploy to Cloud Run"
	@echo ""
	@echo "Deploy options:"
	@echo "  make deploy GCP_PROJECT=my-project GCS_BUCKET=my-bucket"
	@echo ""
	@echo "Environment variables:"
	@echo "  GCP_PROJECT     GCP project ID (required for deploy)"
	@echo "  GCS_BUCKET      GCS bucket name for file storage (required for deploy)"

build:
	CGO_ENABLED=0 go build -o web-dissect -ldflags="-s -w" .

lint:
	golangci-lint run ./...

test:
	go test -v ./...

run: build
	PORT=8080 DISSECT_PATH=dissect ./web-dissect

check-deploy-deps:
	@command -v apko >/dev/null 2>&1 || { echo "❌ apko not found. Install with: go install github.com/chainguard-dev/apko/cmd/apko@latest"; exit 1; }
	@command -v crane >/dev/null 2>&1 || { echo "❌ crane not found. Install with: go install github.com/google/go-containerregistry/cmd/crane@latest"; exit 1; }
	@command -v gcloud >/dev/null 2>&1 || { echo "❌ gcloud not found. Install from: https://cloud.google.com/sdk/docs/install"; exit 1; }
	@echo "✓ All deploy dependencies found"

deploy: check-deploy-deps
	./hacks/deploy.sh "$(GCP_PROJECT)" "$(GCS_BUCKET)"

clean:
	rm -f web-dissect
	rm -rf dist/
