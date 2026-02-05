#!/bin/bash
# Deploy web-dissect to Google Cloud Run using apko + crane
# Uses only apko, crane, and gcloud - no Cloud Build or Docker required
#
# usage:
#   make deploy GCP_PROJECT=my-project GCS_BUCKET=my-bucket
#   ./hacks/deploy.sh my-project my-bucket
set -eux -o pipefail

GCP_PROJECT="${1:-${GCP_PROJECT:?GCP_PROJECT not set}}"
GCS_BUCKET="${2:-${GCS_BUCKET:?GCS_BUCKET not set}}"
REGION="us-central1"
APP_NAME="dissect-web"
APP_IMAGE="gcr.io/${GCP_PROJECT}/${APP_NAME}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Ensure gcloud is authenticated
if ! gcloud auth list --filter=status:ACTIVE --format='value(account)' | grep -q .; then
	echo "❌ gcloud not authenticated. Run: gcloud auth login"
	exit 1
fi

# Ensure service account exists
echo "Setting up service account..."
gcloud iam service-accounts list --project "${GCP_PROJECT}" | grep -q "${APP_NAME}@${GCP_PROJECT}.iam.gserviceaccount.com" ||
	{ gcloud iam service-accounts create "${APP_NAME}" --project "${GCP_PROJECT}"; sleep 2; }

# Grant necessary IAM roles
echo "Granting IAM roles..."
gcloud projects add-iam-policy-binding "${GCP_PROJECT}" \
	--member "serviceAccount:${APP_NAME}@${GCP_PROJECT}.iam.gserviceaccount.com" \
	--role roles/storage.objectCreator \
	--quiet || true

gcloud projects add-iam-policy-binding "${GCP_PROJECT}" \
	--member "serviceAccount:${APP_NAME}@${GCP_PROJECT}.iam.gserviceaccount.com" \
	--role roles/run.admin \
	--quiet || true

# Build OCI image using apko (outputs OCI layout directory)
echo "Building OCI image with apko..."
"${SCRIPT_DIR}/build-apko.sh"

# Get the OCI layout directory from build-apko.sh
OCI_BUILD="${SCRIPT_DIR}/dist/apko-build"

if [ ! -f "${OCI_BUILD}/index.json" ] || [ ! -d "${OCI_BUILD}/blobs" ]; then
	echo "❌ OCI image structure not found at ${OCI_BUILD}"
	exit 1
fi

# Configure gcloud auth for crane
echo "Configuring authentication for crane..."
gcloud auth configure-docker gcr.io --quiet

# Push OCI image directly to GCR using crane
echo "Publishing image to ${APP_IMAGE}:latest using crane..."
crane push "${OCI_BUILD}" "${APP_IMAGE}:latest"

# Deploy to Cloud Run
echo "Deploying to Cloud Run..."
gcloud run deploy "${APP_NAME}" \
	--image="${APP_IMAGE}:latest" \
	--region="${REGION}" \
	--service-account="${APP_NAME}@${GCP_PROJECT}.iam.gserviceaccount.com" \
	--project "${GCP_PROJECT}" \
	--allow-unauthenticated \
	--set-env-vars "GCS_BUCKET=${GCS_BUCKET}" \
	--memory 2Gi \
	--timeout 120s

echo "✓ Deployed ${APP_NAME} to Cloud Run"

# Get the service URL
SERVICE_URL=$(gcloud run services describe "${APP_NAME}" \
	--project "${GCP_PROJECT}" \
	--region "${REGION}" \
	--format='value(status.url)')

echo "Service URL: ${SERVICE_URL}"
