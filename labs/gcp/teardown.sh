#!/usr/bin/env bash
# =============================================================================
# AuthSec GCP IGA test environment — teardown (ticket GCP-0)
#
#   bash teardown.sh          # remove the resources that cost money; keep the
#                             # org structure, IAM scenarios and projects
#   bash teardown.sh --all    # also shut down the three projects (30-day
#                             # recovery window) and delete the two folders
# =============================================================================
set -uo pipefail
export CLOUDSDK_CORE_DISABLE_PROMPTS=1
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/config.env"
[[ -f "$HERE/.state.env" ]] || { echo "No .state.env — nothing was seeded from this folder."; exit 0; }
source "$HERE/.state.env"
REGION="${REGION:-us-central1}"; ZONE="${ZONE:-us-central1-a}"; PREFIX="${PREFIX:-iga}"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
try() { "$@" >/dev/null 2>&1 && echo "    removed: ${*: -1}" || echo "    not present: ${*: -1}"; }

log "Costly resources"
try gcloud container clusters delete "${PREFIX}-gke" --project="$PROD" --region="$REGION"
try gcloud compute instances delete "${PREFIX}-vm" --project="$DEV" --zone="$ZONE"
try gcloud run services delete "${PREFIX}-run" --project="$DEV" --region="$REGION"
try gcloud functions delete "${PREFIX}-fn" --project="$DEV" --region="$REGION" --gen2
try gcloud scheduler jobs pause "${PREFIX}-daily" --project="$DEV" --location="$REGION"

if [[ "${1:-}" == "--all" ]]; then
  log "Projects and folders"
  for b in "gs://${PREFIX}-public-iam-${SUFFIX}" "gs://${PREFIX}-public-acl-${SUFFIX}"; do
    try gcloud storage rm --recursive "$b"
  done
  try gcloud iam policies delete iga-deny-delete --attachment-point="cloudresourcemanager.googleapis.com%2Fprojects%2F${PROD}" --kind=denypolicies
  for p in "$DEV" "$PROD" "$SHARED"; do try gcloud projects delete "$p"; done
  echo "    waiting 30s before deleting folders"; sleep 30
  try gcloud resource-manager folders delete "$FOLDER_A"
  try gcloud resource-manager folders delete "$FOLDER_B"
  try gcloud iam roles delete igaOrgAuditor --organization="$ORG_ID"
  for g in "${PREFIX}-finance-readers@$DOMAIN" "${PREFIX}-contractors@$DOMAIN"; do try gcloud identity groups delete "$g"; done
  echo "    Projects are recoverable for 30 days. Remove .state.env to start fresh."
fi
log "Done"
