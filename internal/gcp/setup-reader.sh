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

echo "=== Enabling required APIs in ${READER_PROJECT_ID} ==="
# A fresh GCP project has none of these on by default. Every step below —
# creating the service account, the WIF pool/provider, the IAM binding, and
# AuthSec's later token exchange and read-only calls — depends on one of
# these being enabled, so this runs first and unconditionally.
gcloud services enable \
{{range .CoreServices}}  {{.}} \
{{end}}  --project="${READER_PROJECT_ID}"

# The rest are read surfaces discovery uses. Enabled ONE AT A TIME and
# never fatally: some of these are Beta or are not available in every
# project, and a single unavailable API must not abort a script running
# under `set -e` before the federation resources below are created.
# A surface that cannot be enabled is reported by AuthSec as unavailable;
# everything else still works.
for _svc in \
{{range .DiscoveryServices}}  {{.}} \
{{end}}  ; do
  gcloud services enable "${_svc}" --project="${READER_PROJECT_ID}" 2>/dev/null \
    || echo "  (skipped ${_svc} - not available in this project)"
done

echo ""
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
echo "# Workload Identity Federation                              #"
echo "# Keyless. No key file, no secret, ever leaves your account. #"
echo "############################################################"
echo ""
echo "Copy the ONE value this prints at the end into"
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

if [ -z "${PROVIDER_RESOURCE}" ]; then
  echo "ERROR: the workload identity provider was not created, so there is"
  echo "nothing to paste back. Scroll up for the step that failed."
  exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo " AuthSec GCP setup completed successfully"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Copy the value below and paste it into AuthSec's WIF provider field:"
echo ""
echo "  ${PROVIDER_RESOURCE}"
echo ""
echo "AuthSec derives everything else (reader SA email, pool, audience)"
echo "from this one value plus the project you entered — nothing else to"
echo "copy or configure."
echo "(reader SA, for reference only, not needed by AuthSec: ${READER_SA_EMAIL})"
echo "════════════════════════════════════════════════════════════"
echo ""
