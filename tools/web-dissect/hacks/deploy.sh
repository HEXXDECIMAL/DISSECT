#!/bin/bash
# Deploy web-dissect to Google Cloud Run using apko/melange and crane
#
# usage:
#   make deploy GCP_PROJECT=my-project GCS_BUCKET=my-bucket
#   ./hacks/deploy.sh my-project my-bucket
set -eux -o pipefail

GCP_PROJECT="${1:-${GCP_PROJECT:?GCP_PROJECT not set}}"
GCS_BUCKET="${2:-${GCS_BUCKET:?GCS_BUCKET not set}}"
REGION="us-central1"
APP_NAME="dissect-web"
REGISTRY="${GCP_PROJECT}"
APP_IMAGE="gcr.io/${REGISTRY}/${APP_NAME}"

# Ensure service account exists
gcloud iam service-accounts list --project "${GCP_PROJECT}" | grep -q "${APP_NAME}@${GCP_PROJECT}.iam.gserviceaccount.com" ||
	{ gcloud iam service-accounts create "${APP_NAME}" --project "${GCP_PROJECT}"; sleep 2; }

# Grant storage.objectCreator role for GCS uploads
gcloud projects add-iam-policy-binding "${GCP_PROJECT}" \
	--member "serviceAccount:${APP_NAME}@${GCP_PROJECT}.iam.gserviceaccount.com" \
	--role roles/storage.objectCreator \
	--quiet || true

# Build image with apko/melange
echo "Building image with apko/melange..."
./build-apko.sh

# Push image to GCR using crane
echo "Pushing image to ${APP_IMAGE}:latest..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OCI_DIR="${SCRIPT_DIR}/dist/apko-build"
if [ ! -d "${OCI_DIR}" ]; then
  echo "❌ OCI directory not found: ${OCI_DIR}"
  exit 1
fi

# Try to push using the layout directory
# crane expects OCI layout format with index.json at root
cd "${OCI_DIR}"
if command -v podman >/dev/null 2>&1; then
  echo "Using podman to push image..."
  podman push -v "oci:." "${APP_IMAGE}:latest"
else
  echo "podman not found, attempting with crane..."
  # Use crane pull to load from OCI layout, then push
  crane push . "${APP_IMAGE}:latest" 2>&1 || {
    echo "Error pushing image"
    exit 1
  }
fi

# Deploy to Cloud Run
echo "Deploying to Cloud Run..."
gcloud run deploy "${APP_NAME}" \
	--image="${APP_IMAGE}:latest" \
	--region="${REGION}" \
	--service-account="${APP_NAME}@${GCP_PROJECT}.iam.gserviceaccount.com" \
	--project "${GCP_PROJECT}" \
	--allow-unauthenticated \
	--set-env-vars GCS_BUCKET="${GCS_BUCKET}" \
	--memory 2Gi \
	--timeout 120s

echo "✓ Deployed ${APP_NAME} to Cloud Run"
echo "Service URL: https://${APP_NAME}-$(gcloud run services describe ${APP_NAME} --project ${GCP_PROJECT} --region ${REGION} --format='value(status.url)' | cut -d'/' -f3)"
