#!/bin/bash
set -exuo pipefail

# Build script for web-dissect using apko (no VMs required on macOS)
# Builds binaries natively, then assembles OCI image with apko
# Prerequisites: apko, go 1.24+, cargo/rust, dissect binary

REPO_ROOT=$(git rev-parse --show-toplevel)
BUILD_DIR="${REPO_ROOT}/tools/web-dissect"
OUTPUT_DIR="${BUILD_DIR}/dist"
OVERLAY_DIR="${OUTPUT_DIR}/overlay"

mkdir -p "${OUTPUT_DIR}" "${OVERLAY_DIR}"

echo "=== Building web-dissect Go binary (native) ==="
cd "${BUILD_DIR}"
CGO_ENABLED=0 go build -o "${OUTPUT_DIR}/web-dissect" -ldflags="-s -w" .
echo "✓ Go binary built: ${OUTPUT_DIR}/web-dissect"

echo ""
echo "=== Locating dissect binary ==="
DISSECT_BIN=""
if command -v dissect >/dev/null 2>&1; then
  DISSECT_BIN="$(command -v dissect)"
  echo "✓ Found dissect in PATH: ${DISSECT_BIN}"
elif [ -f "${REPO_ROOT}/target/release/dissect" ]; then
  DISSECT_BIN="${REPO_ROOT}/target/release/dissect"
  echo "✓ Found dissect build: ${DISSECT_BIN}"
elif [ -f "${REPO_ROOT}/target/x86_64-unknown-linux-musl/release/dissect" ]; then
  DISSECT_BIN="${REPO_ROOT}/target/x86_64-unknown-linux-musl/release/dissect"
  echo "✓ Found dissect cross-build: ${DISSECT_BIN}"
else
  echo "❌ dissect binary not found"
  echo "Please:"
  echo "  1. Build: cd ${REPO_ROOT} && cargo build --release"
  echo "  2. Or: cd ${REPO_ROOT} && cargo build --release --target x86_64-unknown-linux-musl"
  echo "  3. Or add dissect to PATH"
  exit 1
fi

echo ""
echo "=== Copying dissect binary to dist ==="
cp "${DISSECT_BIN}" "${OUTPUT_DIR}/dissect"
chmod +x "${OUTPUT_DIR}/dissect"
echo "✓ dissect copied to ${OUTPUT_DIR}/dissect"

echo ""
echo "=== Creating overlay with binaries and templates ==="
mkdir -p "${OVERLAY_DIR}/usr/local/bin" "${OVERLAY_DIR}/templates"
cp "${OUTPUT_DIR}/web-dissect" "${OVERLAY_DIR}/usr/local/bin/web-dissect"
chmod +x "${OVERLAY_DIR}/usr/local/bin/web-dissect"
cp "${DISSECT_BIN}" "${OVERLAY_DIR}/usr/local/bin/dissect"
chmod +x "${OVERLAY_DIR}/usr/local/bin/dissect"
cp -r "${BUILD_DIR}/templates/"* "${OVERLAY_DIR}/templates/"
echo "✓ Overlay created at ${OVERLAY_DIR}"

echo ""
echo "=== Building base image with apko (amd64) ==="
TEMP_BUILD="${OUTPUT_DIR}/apko-build"
mkdir -p "${TEMP_BUILD}"
cd "${TEMP_BUILD}"

# Build image directory (apko outputs directory layout)
apko build \
  --arch amd64 \
  "${BUILD_DIR}/apko.yaml" \
  "dissect-web:latest" \
  .
echo "✓ Base image built"

# Verify OCI structure
if [ ! -f "index.json" ] || [ ! -d "blobs" ]; then
  echo "❌ OCI image structure not found"
  ls -la
  exit 1
fi

echo ""
echo "=== Adding application files ==="
# Find the gzipped layer blob (not JSON blobs)
BLOB=$(find blobs/sha256 -type f -exec sh -c 'file "$1" | grep -q "gzip" && echo "$1"' _ {} \;)
if [ -z "$BLOB" ]; then
  echo "❌ No gzipped layer blob found in OCI image"
  exit 1
fi

# Extract layer, add files, re-compress
mkdir -p layer-tmp
cd layer-tmp

# Extract the gzipped blob (ignore device creation errors which aren't critical)
tar -xzf "../${BLOB}" 2>&1 | grep -v "Can't create" || true
echo "✓ Extracted gzipped blob"

mkdir -p usr/local/bin templates
cp "${OUTPUT_DIR}/web-dissect" usr/local/bin/web-dissect
chmod +x usr/local/bin/web-dissect
cp "${DISSECT_BIN}" usr/local/bin/dissect
chmod +x usr/local/bin/dissect
cp -r "${BUILD_DIR}/templates/"* templates/ 2>/dev/null || true

# Recreate blob with gzip compression
cd ..
BLOB_NAME=$(basename "${BLOB}")
BLOB_DIR=$(dirname "${BLOB}")
tar -czf "${BLOB_NAME}.new" -C layer-tmp .
rm "${BLOB}"
mv "${BLOB_NAME}.new" "${BLOB}"
rm -rf layer-tmp
echo "✓ Application files added"

echo ""
echo "=== Creating deployable OCI archive ==="
cd "${OUTPUT_DIR}"
tar -czf dissect-web-image.tar.gz -C apko-build blobs/ index.json oci-layout
echo "✓ OCI archive: ${OUTPUT_DIR}/dissect-web-image.tar.gz"

echo ""
echo "Build complete!"
echo ""
echo "Next steps:"
echo "  1. Push to GCR:"
echo "     crane push ${OUTPUT_DIR}/dissect-web-amd64.tar gcr.io/PROJECT/dissect-web:latest"
echo ""
echo "  2. Or deploy to Cloud Run:"
echo "     make deploy GCP_PROJECT=hexx-tools GCS_BUCKET=hexx-divine"
