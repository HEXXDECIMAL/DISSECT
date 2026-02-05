#!/bin/bash
set -exuo pipefail

# Disable macOS resource fork files in tarballs
export COPYFILE_DISABLE=1

# Build script for web-dissect using apko + custom APK package
# Simple approach: create APK manually (it's just a tar.gz), then apko includes it
# Prerequisites: apko, go 1.24+, cargo/rust, dissect binary

REPO_ROOT=$(git rev-parse --show-toplevel)
BUILD_DIR="${REPO_ROOT}/tools/web-dissect"
OUTPUT_DIR="${BUILD_DIR}/dist"
OCI_BUILD="${OUTPUT_DIR}/apko-build"
APK_REPO="${BUILD_DIR}/apk-repo"
APK_ARCH_REPO="${APK_REPO}/x86_64"

mkdir -p "${OUTPUT_DIR}" "${APK_ARCH_REPO}"

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
echo "=== Creating APK package ==="

# Create temporary directory for APK contents
APK_TMP=$(mktemp -d)
trap "rm -rf ${APK_TMP}" EXIT

# Create .PKGINFO metadata file
cat > "${APK_TMP}/.PKGINFO" <<'EOF'
pkgname = dissect-tools
pkgver = 0.0.1-r0
pkgdesc = web-dissect and dissect binaries
url = https://example.com
builddate = 1
packager = build <build@example.com>
size = 0
installed_size = 0
origin = dissect-tools
maintainer = build <build@example.com>
arch = x86_64
EOF

# Create filesystem directories and copy binaries
mkdir -p "${APK_TMP}/usr/local/bin" "${APK_TMP}/templates"
cp "${OUTPUT_DIR}/web-dissect" "${APK_TMP}/usr/local/bin/web-dissect"
chmod +x "${APK_TMP}/usr/local/bin/web-dissect"
cp "${DISSECT_BIN}" "${APK_TMP}/usr/local/bin/dissect"
chmod +x "${APK_TMP}/usr/local/bin/dissect"
cp -r "${BUILD_DIR}/templates/"* "${APK_TMP}/templates/" 2>/dev/null || true

# Create the APK file (tar.gz with .PKGINFO at root)
cd "${APK_TMP}"
tar --exclude='._*' -czf "${APK_ARCH_REPO}/dissect-tools-0.0.1-r0.apk" .
echo "✓ APK created: dissect-tools-0.0.1-r0.apk"

echo ""
echo "=== Creating APKINDEX ==="

# Create APKINDEX file
APK_CHECKSUM=$(sha256sum "${APK_ARCH_REPO}/dissect-tools-0.0.1-r0.apk" | awk '{print $1}')
APK_SIZE=$(stat -f%z "${APK_ARCH_REPO}/dissect-tools-0.0.1-r0.apk" 2>/dev/null || stat -c%s "${APK_ARCH_REPO}/dissect-tools-0.0.1-r0.apk")

cat > "${APK_TMP}/APKINDEX" <<EOF
C:Q1z3DKXJ0kKmlBsH6hVX9qbUo=
P:dissect-tools
V:0.0.1-r0
A:x86_64
M:Q1z3DKXJ0kKmlBsH6hVX9qbUo=
D:
o:dissect-tools
m:build
L:GPL
t:1
c:abc1234567890
S:${APK_SIZE}
I:${APK_SIZE}
Z:${APK_CHECKSUM}
EOF

# Create APKINDEX.tar.gz
cd "${APK_TMP}"
tar --exclude='._*' -czf "${APK_ARCH_REPO}/APKINDEX.tar.gz" APKINDEX
echo "✓ APKINDEX created"

# List what we created
echo ""
echo "APK Repository contents:"
ls -lh "${APK_ARCH_REPO}/"

echo ""
echo "=== Building OCI image with apko ==="
rm -rf "${OCI_BUILD}"
mkdir -p "${OCI_BUILD}"

apko build \
  --arch amd64 \
  --ignore-signatures \
  --repository-append "${APK_REPO}" \
  "${BUILD_DIR}/apko.yaml" \
  "dissect-web:latest" \
  "${OCI_BUILD}"
echo "✓ OCI image built with dissect-tools package"

# Verify OCI structure
if [ ! -f "${OCI_BUILD}/index.json" ] || [ ! -d "${OCI_BUILD}/blobs" ]; then
  echo "❌ OCI image structure not found at ${OCI_BUILD}"
  ls -la "${OCI_BUILD}" || true
  exit 1
fi

echo ""
echo "✓ Build complete!"
echo ""
echo "OCI layout directory: ${OCI_BUILD}"
echo "APK repository: ${APK_REPO}"
echo ""
echo "Next steps:"
echo "  1. Push to GCR with crane:"
echo "     crane push ${OCI_BUILD} gcr.io/hexx-tools/dissect-web:latest"
echo ""
echo "  2. Or deploy to Cloud Run:"
echo "     GCP_PROJECT=hexx-tools GCS_BUCKET=hexx-divine make deploy"
