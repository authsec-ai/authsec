#!/usr/bin/env bash
# AuthSec GCP reader setup — rendered by AuthSec for one workspace and one
# scope. Run this in a terminal authenticated (gcloud auth login) as a
# principal with IAM admin rights on the reader project below, and on the
# scope you are connecting.
#
# This script creates ONE read-only service account and grants it read-only
# roles. It creates no other resources in your project, and it never asks
# you to paste a secret back to AuthSec: the recommended path below (Workload
# Identity Federation) is keyless end to end.
#
# Scope:            {{.ScopeKind}} {{.ScopeID}}
# Reader project:    {{.ReaderProjectID}}
# Role set status:   {{.RoleSetStatus}}
# Script version:    {{.SetupScriptVersion}}
set -euo pipefail

READER_PROJECT_ID="{{.ReaderProjectID}}"
READER_SA_NAME="authsec-reader"
READER_SA_EMAIL="${READER_SA_NAME}@${READER_PROJECT_ID}.iam.gserviceaccount.com"

echo "=== Creating the reader service account in ${READER_PROJECT_ID} ==="
gcloud iam service-accounts create "${READER_SA_NAME}" \
  --display-name="AuthSec Reader" \
  --project="${READER_PROJECT_ID}" || echo "(already exists — continuing)"

echo ""
echo "=== Granting read-only roles at {{.ScopeKind}} scope {{.ScopeID}} ==="
{{range .RoleGrantCommands}}
{{.}}
{{end}}

echo ""
echo "############################################################"
echo "# Option A (recommended): Workload Identity Federation      #"
echo "# Keyless. No key file, no secret, ever leaves your account. #"
echo "############################################################"
echo ""
echo "Run this section, then copy the TWO printed values at the end into"
echo "the AuthSec console's WIF form."
echo ""

PROJECT_NUMBER=$(gcloud projects describe "${READER_PROJECT_ID}" --format='value(projectNumber)')

gcloud iam workload-identity-pools create "{{.PoolID}}" \
  --location=global --project="${READER_PROJECT_ID}" \
  --display-name="AuthSec Reader Pool" || echo "(already exists — continuing)"

gcloud iam workload-identity-pools providers create-oidc "{{.ProviderID}}" \
  --location=global --workload-identity-pool="{{.PoolID}}" \
  --issuer-uri="{{.IssuerURL}}" \
  --attribute-mapping="google.subject=assertion.sub" \
  --project="${READER_PROJECT_ID}" || echo "(already exists — continuing)"

# Scoped to ONE subject. Never grant this to the wildcard
# principalSet://.../* form — that binds every identity the pool could ever
# federate, not just the one AuthSec derived for this workspace and scope.
gcloud iam service-accounts add-iam-policy-binding "${READER_SA_EMAIL}" \
  --member="principal://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/{{.PoolID}}/subject/{{.WIFSubject}}" \
  --role=roles/iam.workloadIdentityUser \
  --project="${READER_PROJECT_ID}"

PROVIDER_RESOURCE=$(gcloud iam workload-identity-pools providers describe "{{.ProviderID}}" \
  --location=global --workload-identity-pool="{{.PoolID}}" \
  --project="${READER_PROJECT_ID}" --format='value(name)')

echo ""
echo "=== COPY THESE TWO VALUES INTO THE AUTHSEC CONSOLE ==="
echo "Reader SA email:        ${READER_SA_EMAIL}"
echo "WIF provider resource:  ${PROVIDER_RESOURCE}"
echo "======================================================="
echo ""
echo "############################################################"
echo "# Option B (fallback): JSON key upload                      #"
echo "# Only run this if you are NOT using Option A above.         #"
echo "############################################################"
echo ""
echo "This creates a downloadable key file. Upload it once through the"
echo "AuthSec console, then delete the local copy."
echo ""
echo "  gcloud iam service-accounts keys create reader-key.json \\"
echo "    --iam-account=\"${READER_SA_EMAIL}\""
echo ""
echo "Reader SA email (if using Option B): ${READER_SA_EMAIL}"
