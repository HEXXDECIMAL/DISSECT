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

# Push image to GCR using gcloud builds
echo "Building and pushing image to ${APP_IMAGE}:latest..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Use gcloud builds submit to build from Dockerfile
# First check if Dockerfile exists
if [ ! -f "${SCRIPT_DIR}/Dockerfile" ]; then
  echo "❌ Dockerfile not found"
  exit 1
fi

# Create a GCS bucket for build artifacts if needed
BUILD_BUCKET="gs://dissect-builds-${GCP_PROJECT}"

gcloud builds submit \
  --tag "${APP_IMAGE}:latest" \
  --project "${GCP_PROJECT}" \
  --file "${SCRIPT_DIR}/Dockerfile" \
  "${SCRIPT_DIR}" || exit 1

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
