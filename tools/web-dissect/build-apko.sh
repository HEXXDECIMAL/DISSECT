#!/bin/bash
set -exuo pipefail

# Build script for web-dissect using apko + manual layer addition
# 1. apko builds base image with Alpine packages (radare2, etc.)
# 2. Manually add binaries layer to OCI layout
# Builds for ARM64 (native on ARM Mac, fast builds)

export COPYFILE_DISABLE=1

REPO_ROOT=$(git rev-parse --show-toplevel)
BUILD_DIR="${REPO_ROOT}/tools/web-dissect"
OUTPUT_DIR="${BUILD_DIR}/dist"
OCI_BUILD="${OUTPUT_DIR}/apko-build"

rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

echo "=== Building web-dissect Go binary (linux/arm64) ==="
cd "${BUILD_DIR}"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "${OUTPUT_DIR}/web-dissect" -ldflags="-s -w" .
echo "Built: ${OUTPUT_DIR}/web-dissect"

echo ""
echo "=== Locating dissect binary (Linux ARM64) ==="
DISSECT_BIN="${REPO_ROOT}/target/aarch64-unknown-linux-musl/release/dissect"
if [ ! -f "${DISSECT_BIN}" ]; then
  echo "Linux dissect binary not found at: ${DISSECT_BIN}"
  echo ""
  echo "Building dissect for Linux ARM64 using Podman..."

  if ! command -v podman >/dev/null 2>&1; then
    echo "podman not found. Install with: brew install podman"
    exit 1
  fi

  # Build with Podman using rust:alpine image (native ARM64)
  podman run --rm --platform linux/arm64 \
    -v "${REPO_ROOT}:/build:z" \
    -w /build \
    docker.io/library/rust:alpine \
    sh -c "apk add --no-cache musl-dev g++ && rustup target add aarch64-unknown-linux-musl && cargo build --release --target aarch64-unknown-linux-musl"

  if [ ! -f "${DISSECT_BIN}" ]; then
    echo "Failed to build dissect for Linux"
    exit 1
  fi
fi
echo "Found dissect Linux binary: ${DISSECT_BIN}"

echo ""
echo "=== Building base image with apko ==="
rm -rf "${OCI_BUILD}"
mkdir -p "${OCI_BUILD}"

apko build \
  --arch arm64 \
  "${BUILD_DIR}/apko.yaml" \
  "dissect-web:base" \
  "${OCI_BUILD}"

echo "Base image built"

echo ""
echo "=== Creating binaries layer ==="
LAYER_DIR=$(mktemp -d)
trap "rm -rf ${LAYER_DIR}" EXIT

mkdir -p "${LAYER_DIR}/usr/local/bin"
cp "${OUTPUT_DIR}/web-dissect" "${LAYER_DIR}/usr/local/bin/web-dissect"
chmod +x "${LAYER_DIR}/usr/local/bin/web-dissect"
cp "${DISSECT_BIN}" "${LAYER_DIR}/usr/local/bin/dissect"
chmod +x "${LAYER_DIR}/usr/local/bin/dissect"

# Copy templates if they exist
if [ -d "${BUILD_DIR}/templates" ]; then
  mkdir -p "${LAYER_DIR}/templates"
  cp -r "${BUILD_DIR}/templates/"* "${LAYER_DIR}/templates/" 2>/dev/null || true
fi

# Create gzipped tarball for the layer
cd "${LAYER_DIR}"
tar -czf "${OUTPUT_DIR}/binaries.tar.gz" .

# Calculate layer digest
LAYER_DIGEST=$(sha256sum "${OUTPUT_DIR}/binaries.tar.gz" | awk '{print $1}')
LAYER_SIZE=$(stat -f%z "${OUTPUT_DIR}/binaries.tar.gz" 2>/dev/null || stat -c%s "${OUTPUT_DIR}/binaries.tar.gz")

# Calculate diffID (uncompressed digest)
DIFF_ID=$(gzip -dc "${OUTPUT_DIR}/binaries.tar.gz" | sha256sum | awk '{print $1}')

echo "Layer digest: sha256:${LAYER_DIGEST}"
echo "Layer size: ${LAYER_SIZE}"
echo "DiffID: sha256:${DIFF_ID}"

echo ""
echo "=== Adding layer to OCI image ==="

# Copy layer blob
cp "${OUTPUT_DIR}/binaries.tar.gz" "${OCI_BUILD}/blobs/sha256/${LAYER_DIGEST}"

# Get current manifest digest from index
MANIFEST_DIGEST=$(jq -r '.manifests[0].digest' "${OCI_BUILD}/index.json" | sed 's/sha256://')
MANIFEST_FILE="${OCI_BUILD}/blobs/sha256/${MANIFEST_DIGEST}"

# Get current config digest
CONFIG_DIGEST=$(jq -r '.config.digest' "${MANIFEST_FILE}" | sed 's/sha256://')
CONFIG_FILE="${OCI_BUILD}/blobs/sha256/${CONFIG_DIGEST}"

# Update config to add new layer diffID
jq --arg diffid "sha256:${DIFF_ID}" '.rootfs.diff_ids += [$diffid]' "${CONFIG_FILE}" > "${CONFIG_FILE}.new"
mv "${CONFIG_FILE}.new" "${CONFIG_FILE}"

# Recalculate config digest
NEW_CONFIG_DIGEST=$(sha256sum "${CONFIG_FILE}" | awk '{print $1}')
NEW_CONFIG_SIZE=$(stat -f%z "${CONFIG_FILE}" 2>/dev/null || stat -c%s "${CONFIG_FILE}")
mv "${CONFIG_FILE}" "${OCI_BUILD}/blobs/sha256/${NEW_CONFIG_DIGEST}"

# Update manifest to add new layer and update config reference
jq --arg layer_digest "sha256:${LAYER_DIGEST}" \
   --arg layer_size "${LAYER_SIZE}" \
   --arg config_digest "sha256:${NEW_CONFIG_DIGEST}" \
   --arg config_size "${NEW_CONFIG_SIZE}" \
   '.layers += [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": ($layer_size | tonumber), "digest": $layer_digest}] | .config.digest = $config_digest | .config.size = ($config_size | tonumber)' \
   "${MANIFEST_FILE}" > "${MANIFEST_FILE}.new"
mv "${MANIFEST_FILE}.new" "${MANIFEST_FILE}"

# Recalculate manifest digest
NEW_MANIFEST_DIGEST=$(sha256sum "${MANIFEST_FILE}" | awk '{print $1}')
NEW_MANIFEST_SIZE=$(stat -f%z "${MANIFEST_FILE}" 2>/dev/null || stat -c%s "${MANIFEST_FILE}")
mv "${MANIFEST_FILE}" "${OCI_BUILD}/blobs/sha256/${NEW_MANIFEST_DIGEST}"

# Update index.json
jq --arg manifest_digest "sha256:${NEW_MANIFEST_DIGEST}" \
   --arg manifest_size "${NEW_MANIFEST_SIZE}" \
   '.manifests[0].digest = $manifest_digest | .manifests[0].size = ($manifest_size | tonumber)' \
   "${OCI_BUILD}/index.json" > "${OCI_BUILD}/index.json.new"
mv "${OCI_BUILD}/index.json.new" "${OCI_BUILD}/index.json"

echo "Layer added to OCI image"

echo ""
echo "Build complete!"
echo ""
echo "OCI layout: ${OCI_BUILD}"
echo ""
echo "To push to GCR:"
echo "  crane push ${OCI_BUILD} gcr.io/PROJECT/dissect-web:latest"
echo ""
echo "Or run deploy:"
echo "  GCP_PROJECT=hexx-tools GCS_BUCKET=hexx-divine make deploy"
