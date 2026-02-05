# web-dissect

Minimalist web interface for static analysis with DISSECT.

## Features

- Simple file upload form
- Terminal-style analysis output with ANSI color preservation
- Automatic SHA256 hashing and GCS storage
- Health check endpoint for container orchestration
- Responsive design, no JavaScript required

## Local Development

### Prerequisites

- Go 1.24+
- dissect binary in PATH or set `DISSECT_PATH`

### Build

```bash
cd tools/web-dissect
make build
```

### Run

```bash
export PORT=8080
export DISSECT_PATH=dissect
./web-dissect
```

Then visit `http://localhost:8080` in your browser.

### Environment Variables

- `PORT` - HTTP server port (default: 8080)
- `DISSECT_PATH` - Path to dissect binary (default: "dissect")
- `GCS_BUCKET` - GCS bucket for file storage (optional)

### Linting

```bash
make lint
```

Must pass before committing.

### Deploy to Cloud Run

Deploy to Google Cloud Run with a single command:

```bash
make deploy GCP_PROJECT=my-project GCS_BUCKET=dissect-uploads
```

This will:
1. Validate all dependencies
2. Build OCI image with apko (native, no VMs)
3. Push to GCR using crane
4. Create/configure service account with GCS permissions
5. Deploy to Cloud Run with environment variables

**Install prerequisites:**
```bash
# Image builder
go install github.com/chainguard-dev/apko/cmd/apko@latest

# Registry push tool
go install github.com/google/go-containerregistry/cmd/crane@latest

# Cloud CLI (gcloud)
# https://cloud.google.com/sdk/docs/install
```

**Check dependencies:**
```bash
make check-deploy-deps
```

## Deployment

### Build Container Image with apko (Native macOS)

Build OCI container images natively on macOS using Chainguard's apko, with no VMs required:

**Prerequisites:**
```bash
# Install apko (declarative image builder)
go install github.com/chainguard-dev/apko/cmd/apko@latest

# Install crane (push images to registry)
go install github.com/google/go-containerregistry/cmd/crane@latest

# Build dependencies (Rust for dissect, Go for web-dissect)
# Install via Homebrew or your preferred method
```

**Build (from repo root):**
```bash
cd tools/web-dissect
./build-apko.sh
```

This workflow:
1. Builds web-dissect Go binary natively (macOS/arm64)
2. Finds dissect Rust binary (from local build or PATH)
3. Uses apko to assemble image with:
   - Alpine base + rizin + dependencies
   - Our binaries and templates
4. Saves OCI archive to `dist/dissect-web-amd64.tar`

**Push to registry:**
```bash
crane push dist/dissect-web-amd64.tar gcr.io/PROJECT/dissect-web:latest
```

**Configuration:**
- `apko.yaml` - Declarative image configuration (packages, entrypoint, env)
- `build-apko.sh` - Build orchestration (handles apko + overlays)


## Architecture

### HTTP Endpoints

- `GET /` - Upload form
- `POST /upload` - Process file upload and analysis
- `GET /health` - Health check (returns 200 OK)

### Analysis Flow

1. User uploads file via HTML form
2. File saved to temporary location
3. SHA256 checksum computed
4. File uploaded to GCS at `gs://bucket/{sha256}/{filename}`
5. dissect binary executed with terminal output format
6. ANSI output converted to HTML with colors preserved
7. Results rendered in browser
8. Temporary file cleaned up

### Dependencies

**Go:**
- `cloud.google.com/go/storage` - GCS integration
- `github.com/buildkite/terminal-to-html` - ANSI-to-HTML conversion
- `net/http`, `html/template` - Standard library

**Container:**
- dissect binary (Rust)
- rizin (for binary analysis)

## File Limits

- Maximum upload: 100 MB
- Analysis timeout: 120 seconds
- Temporary files automatically cleaned up

## Security

- Files validated by dissect, not by size or type
- Service account requires only Storage Object Creator IAM role for GCS
- Temporary files deleted immediately after analysis
- ANSI output escaped to prevent code injection

## Code Style

- Follows Go best practices from go.dev and Google style guide
- Minimal external dependencies
- Simple, readable code suitable for code review
- Golangci-lint configuration included

## GCS Setup

For local development without GCS:

```bash
# Skip GCS uploads by not setting GCS_BUCKET
./web-dissect
```

For production GCS integration:

1. Create GCS bucket:
   ```bash
   gsutil mb gs://dissect-uploads
   ```

2. Set up Cloud Run service account with role:
   ```bash
   gcloud projects add-iam-policy-binding PROJECT_ID \
     --member serviceAccount:dissect-web@PROJECT_ID.iam.gserviceaccount.com \
     --role roles/storage.objectCreator
   ```

3. Deploy with bucket name:
   ```bash
   gcloud run deploy dissect-web \
     --set-env-vars GCS_BUCKET=dissect-uploads
   ```

## Testing

Manual test: upload `/bin/ls` and verify output display.

## Performance

Typical analysis times:
- Small binaries: <1 second
- Large binaries: 5-10 seconds
- Archives: 10-30 seconds depending on content

## Limitations

- Single-file analysis only (no batch processing)
- Results not persisted between requests
- No authentication (consider adding for production)
