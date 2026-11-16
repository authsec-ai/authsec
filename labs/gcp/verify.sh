#!/usr/bin/env bash
# =============================================================================
# AuthSec GCP IGA test environment — verify (ticket GCP-0)
# Checks that every seeded scenario exists. Read-only. Run in Cloud Shell from
# the same folder as seed.sh:   bash verify.sh
# Writes verify-report.txt next to it.
# =============================================================================
set -uo pipefail
export CLOUDSDK_CORE_DISABLE_PROMPTS=1
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/config.env"
[[ -f "$HERE/.state.env" ]] || { echo "Nothing to verify: seed.sh has not completed its first step (no .state.env). See seed-log.txt."; exit 1; }
source "$HERE/.state.env"
FOLDER_A="${FOLDER_A:-}"; FOLDER_B="${FOLDER_B:-}"; DEV="${DEV:-}"; PROD="${PROD:-}"; SHARED="${SHARED:-}"
[[ -n "${SINGLE_PROJECT:-}" ]] && { DEV="$SINGLE_PROJECT"; PROD="$SINGLE_PROJECT"; SHARED="$SINGLE_PROJECT"; }
REGION="${REGION:-us-central1}"; ZONE="${ZONE:-us-central1-a}"; PREFIX="${PREFIX:-iga}"
REPORT="$HERE/verify-report.txt"; : > "$REPORT"
PASS=0; FAIL=0; SKIPN=0
sa() { echo "$1@$2.iam.gserviceaccount.com"; }
out() { echo "$*" | tee -a "$REPORT"; }
check() {  # id description command...
  local id="$1" desc="$2"; shift 2
  if "$@" >/dev/null 2>&1; then out "PASS  [$id] $desc"; PASS=$((PASS+1))
  else out "FAIL  [$id] $desc"; FAIL=$((FAIL+1)); fi
}
skipc() { out "SKIP  [$1] $2"; SKIPN=$((SKIPN+1)); }
pol() { gcloud projects get-iam-policy "$1" --format=json 2>/dev/null; }
has() { grep -q -- "$2" <<<"$1"; }

BILLED="${BILLED:-yes}"
NO_ORG=no; [[ -z "${ORG_ID:-}" ]] && NO_ORG=yes
DEV_POL="$(pol "$DEV")"; PROD_POL="$(pol "$PROD")"
FA_POL=""; [[ "$NO_ORG" == "no" ]] && FA_POL="$(gcloud resource-manager folders get-iam-policy "$FOLDER_A" --format=json 2>/dev/null)"

out "GCP-0 verification  $(date -u +%FT%TZ)"
out "org=$ORG_ID folderA=$FOLDER_A folderB=$FOLDER_B dev=$DEV prod=$PROD shared=$SHARED"
out "------------------------------------------------------------------"

if [[ "$NO_ORG" == "yes" ]]; then skipc 0 "folders (no organization)"; else
check 0  "folder A exists"                         gcloud resource-manager folders describe "$FOLDER_A"
check 0  "folder B exists"                         gcloud resource-manager folders describe "$FOLDER_B"
fi
for p in "$DEV" "$PROD" "$SHARED"; do check 0 "project $p exists" gcloud projects describe "$p"; done

check 1  "old-key-sa has a user-managed key"       bash -c "[[ -n \$(gcloud iam service-accounts keys list --iam-account=$(sa old-key-sa "$DEV") --managed-by=user --format='value(name)') ]]"
if [[ "$BILLED" == "no" ]]; then skipc 2 "default compute SA (no billing)"; else check 2  "default compute SA has roles/editor"     bash -c "jq -e '.bindings[]|select(.role==\"roles/editor\")|.members[]|select(test(\"-compute@developer\"))' <<<'$DEV_POL'"; fi
check 3  "a Google service agent is bound in dev"  has "$DEV_POL" "gcp-sa-"
if [[ "$BILLED" == "no" ]]; then skipc 4 "HMAC key (no billing)"; else check 4  "HMAC key on old-key-sa"                  bash -c "[[ -n \$(gcloud storage hmac list --project=$DEV --service-account=$(sa old-key-sa "$DEV") --format='value(accessId)') ]]"; fi
check 4  "API key ${PREFIX}-restricted-key"        bash -c "[[ -n \$(gcloud services api-keys list --project=$DEV --filter='displayName=${PREFIX}-restricted-key' --format='value(name)') ]]"
if [[ "$NO_ORG" == "yes" ]]; then check 5 "folder-reader-sa bound (project level, no org)" has "$PROD_POL" "folder-reader-sa@"
else check 5  "folder A binding for folder-reader-sa"   has "$FA_POL" "folder-reader-sa@"; fi
check 6  "conditional binding expiring 2027"       has "$PROD_POL" "expires-2027-06"
check 6  "conditional binding already expired"    has "$PROD_POL" "expired-2026-01"
if [[ "$NO_ORG" == "yes" ]]; then skipc 7 "custom org role (no organization)"
else check 7  "custom org role igaOrgAuditor"           gcloud iam roles describe igaOrgAuditor --organization="$ORG_ID"; fi
check 7  "custom project role igaDeployer (actAs)" bash -c "gcloud iam roles describe igaDeployer --project=$DEV --format=json | grep -q iam.serviceAccounts.actAs"
if [[ "$BILLED" == "no" ]]; then skipc 8 "public bucket via IAM (no billing)"; else check 8  "public bucket via IAM (allUsers)"        bash -c "gcloud storage buckets get-iam-policy gs://${PREFIX}-public-iam-${SUFFIX} --format=json | grep -q allUsers"; fi
if [[ "$BILLED" == "no" ]]; then skipc 8 "public bucket via ACL (no billing)"; else check 8  "public bucket via ACL (allUsers)"        bash -c "gcloud storage buckets describe gs://${PREFIX}-public-acl-${SUFFIX} --format=json | grep -q allUsers"; fi
check 9  "deleted principal still bound in dev"    has "$DEV_POL" "deleted:serviceAccount:deleted-later-sa"
check 10 "project-level Token Creator in dev"      has "$DEV_POL" "roles/iam.serviceAccountTokenCreator"
check 10 "SA User on app-sa for deployer-sa"       bash -c "gcloud iam service-accounts get-iam-policy $(sa app-sa "$PROD") --format=json | grep -q deployer-sa@"
[[ "$DEV" == "$PROD" ]] && skipc 11 "cross-project (single project)" || check 11 "cross-project SA bound in prod"          has "$PROD_POL" "cross-project-sa@$SHARED"
if [[ -n "${EXTERNAL_USER_EMAIL:-}" ]]; then check 12 "external user bound in prod" has "$PROD_POL" "$EXTERNAL_USER_EMAIL"
else skipc 12 "external user (EXTERNAL_USER_EMAIL not set)"; fi
check 13 "WIF pool iga-github"                     gcloud iam workload-identity-pools describe iga-github --project="$DEV" --location=global
if [[ -n "${GITHUB_REPO:-}" ]]; then
  check 13 "GitHub provider with condition"        bash -c "gcloud iam workload-identity-pools providers describe github --project=$DEV --location=global --workload-identity-pool=iga-github --format='value(attributeCondition)' | grep -q repository"
else skipc 13 "GitHub provider (GITHUB_REPO not set)"; fi
check 13 "broad provider gitlab-broad"             gcloud iam workload-identity-pools providers describe gitlab-broad --project="$DEV" --location=global --workload-identity-pool=iga-github
[[ "$BILLED" == "no" ]] && skipc 14 "KSA→GSA binding (needs GKE / billing)" || check 14 "KSA→GSA Workload Identity binding"       bash -c "gcloud iam service-accounts get-iam-policy $(sa gke-app-gsa "$PROD") --format=json | grep -q 'svc.id.goog\[iga/app-ksa\]'"
if [[ "${ENABLE_GKE:-no}" == "yes" ]]; then check 14 "GKE Autopilot cluster" gcloud container clusters describe "${PREFIX}-gke" --project="$PROD" --region="$REGION"
else skipc 14 "GKE cluster (ENABLE_GKE=no)"; fi
if [[ "$BILLED" == "no" ]]; then skipc 15 "Cloud Run (no billing)"; else check 15 "Cloud Run ${PREFIX}-run on run-sa"       bash -c "gcloud run services describe ${PREFIX}-run --project=$DEV --region=$REGION --format='value(spec.template.spec.serviceAccountName)' | grep -q run-sa@"; fi
if [[ "$BILLED" == "no" ]]; then skipc 15 "Cloud Function (no billing)"; else check 15 "Cloud Function ${PREFIX}-fn"             gcloud functions describe "${PREFIX}-fn" --project="$DEV" --region="$REGION" --gen2; fi
if [[ "$BILLED" == "no" ]]; then skipc 15 "VM (no billing)"; else check 15 "VM ${PREFIX}-vm on default SA"           bash -c "gcloud compute instances describe ${PREFIX}-vm --project=$DEV --zone=$ZONE --format='value(serviceAccounts[0].email)' | grep -q -- -compute@developer"; fi
if [[ "$BILLED" == "no" ]]; then skipc 15 "Scheduler job (no billing)"; else check 15 "Scheduler job as active-sa"              bash -c "gcloud scheduler jobs describe ${PREFIX}-daily --project=$DEV --location=$REGION --format=json | grep -q active-sa@"; fi
if [[ "$BILLED" == "no" ]]; then skipc 16 "SSH key in VM (no billing)"; else check 16 "SSH key in VM metadata"                  bash -c "gcloud compute instances describe ${PREFIX}-vm --project=$DEV --zone=$ZONE --format=json | grep -q iga-test-user"; fi
if [[ "$BILLED" == "no" ]]; then skipc 16 "project-wide SSH key (no billing)"; else check 16 "project-wide SSH key"                    bash -c "gcloud compute project-info describe --project=$DEV --format=json | grep -q iga-project-user"; fi
[[ "${NO_ORG:-no}" == "yes" ]] && skipc 17 "deny policy (needs an organization)" || check 17 "deny policy on prod"                     gcloud iam policies get iga-deny-delete --attachment-point="cloudresourcemanager.googleapis.com%2Fprojects%2F${PROD}" --kind=denypolicies
if [[ "$NO_ORG" == "yes" ]]; then skipc 18 "org policy (no organization)"; else
check 18 "folder B: key creation disabled"         bash -c "gcloud org-policies describe iam.disableServiceAccountKeyCreation --folder=$FOLDER_B --format=json | grep -q '\"enforce\": true'"
check 18 "folder B: domain-restricted sharing"     gcloud org-policies describe iam.allowedPolicyMemberDomains --folder="$FOLDER_B"
fi
check 19 "owner label on prod"                     bash -c "gcloud projects describe $PROD --format='value(labels.owner)' | grep -q ."
check 19 "Essential Contact on prod"               bash -c "[[ -n \$(gcloud essential-contacts list --project=$PROD --format='value(email)') ]]"
check 20 "BigQuery table iga_finance.ap_invoices"  bq --project_id="$PROD" show "${PREFIX//-/_}_finance.ap_invoices"
check 21 "active-sa and idle-sa exist"             bash -c "gcloud iam service-accounts describe $(sa active-sa "$DEV") && gcloud iam service-accounts describe $(sa idle-sa "$PROD")"
check L  "Data Access logs ON in prod"             has "$PROD_POL" "DATA_READ"
if [[ "$DEV" == "$PROD" ]]; then skipc L "Data Access OFF case (single project)"
else check L  "Data Access logs OFF in dev"             bash -c "! grep -q DATA_READ <<<'$DEV_POL'"; fi
if [[ "$NO_ORG" == "yes" ]]; then skipc 22 "groups (no organization)"; else
check 22 "group finance-readers"                   gcloud identity groups describe "${PREFIX}-finance-readers@$DOMAIN"
check 22 "contractors nested in finance-readers"   bash -c "gcloud identity groups memberships list --group-email=${PREFIX}-finance-readers@$DOMAIN --format='value(preferredMemberKey.id)' | grep -q ${PREFIX}-contractors@"
check 22 "group bound on prod"                     has "$PROD_POL" "group:${PREFIX}-finance-readers@$DOMAIN"
if [[ -n "${SUSPENDED_USER_EMAIL:-}" ]]; then check 22 "suspended user in contractors" bash -c "gcloud identity groups memberships list --group-email=${PREFIX}-contractors@$DOMAIN --format='value(preferredMemberKey.id)' | grep -qi $SUSPENDED_USER_EMAIL"
else skipc 22 "suspended user (SUSPENDED_USER_EMAIL not set)"; fi
fi

out "------------------------------------------------------------------"
out "PASS $PASS   FAIL $FAIL   SKIP $SKIPN"
out ""
out "For AuthSec onboarding:  ${ORG_ID:+organization $ORG_ID}${ORG_ID:-project scope: $DEV, $PROD, $SHARED}"
out "Report saved to $REPORT"
