#!/usr/bin/env bash
# =============================================================================
# AuthSec GCP IGA test environment — seed script (ticket GCP-0)
#
# Creates the folder / project tree and every test scenario that the GCP
# discovery tickets (GCP-1 .. GCP-11) are verified against. See README.md.
#
# Safe to re-run: every step checks before it creates, and IAM bindings are
# idempotent. Project IDs are generated once and saved in .state.env.
#
# Run in Google Cloud Shell (already signed in, has gcloud / bq / jq / ssh-keygen):
#   1. fill in config.env (copy from config.example.env)
#   2. bash seed.sh            # everything except the costly parts
#   3. ENABLE_GKE=yes bash seed.sh   # adds the GKE cluster when you need it
# =============================================================================
set -euo pipefail
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

HERE="$(cd "$(dirname "$0")" && pwd)"
[[ -f "$HERE/config.env" ]] || { echo "Missing config.env — copy config.example.env and fill it in."; exit 1; }
# shellcheck disable=SC1091
source "$HERE/config.env"

: "${ADMIN_EMAIL:?set ADMIN_EMAIL in config.env}"
# No organization (personal account): leave ORG_ID empty. Org-only scenarios
# (folders, org policy, custom org role, groups) are skipped.
ORG_ID="${ORG_ID:-}"
NO_ORG=no; [[ -z "$ORG_ID" ]] && NO_ORG=yes
if [[ "$NO_ORG" == "no" ]]; then : "${DOMAIN:?set DOMAIN in config.env}"; fi
# Billing: set BILLING_ACCOUNT, or BILLING_FROM_PROJECT to reuse that project's account.
if [[ -z "${BILLING_ACCOUNT:-}" && -n "${BILLING_FROM_PROJECT:-}" ]]; then
  gcloud services enable cloudbilling.googleapis.com --project="$BILLING_FROM_PROJECT" >/dev/null
  BILLING_ACCOUNT="$(gcloud billing projects describe "$BILLING_FROM_PROJECT" --format='value(billingAccountName)' | sed 's|billingAccounts/||')"
fi
if [[ -z "${BILLING_ACCOUNT:-}" ]]; then
  echo "No billing account found. ${BILLING_FROM_PROJECT:-That project} has no billing linked."
  echo "Link one in Console > Billing, or set BILLING_ACCOUNT in config.env (gcloud billing accounts list)."; exit 1
fi
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-us-central1-a}"
PREFIX="${PREFIX:-iga}"
ENABLE_GKE="${ENABLE_GKE:-no}"
ENABLE_DLP="${ENABLE_DLP:-no}"
ENABLE_DATA_ACCESS_LOGS="${ENABLE_DATA_ACCESS_LOGS:-yes}"
BUDGET_AMOUNT="${BUDGET_AMOUNT:-10}"

STATE="$HERE/.state.env"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

log()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    \033[33mWARN:\033[0m %s\n' "$*"; }
skip() { printf '    skip: %s\n' "$*"; }

# ---------------------------------------------------------------- state ------
if [[ -f "$STATE" ]]; then source "$STATE"; fi
if [[ -z "${SUFFIX:-}" ]]; then
  SUFFIX="$(printf '%08x' $(( RANDOM * 32768 + RANDOM )) | cut -c4-8)"
  echo "SUFFIX=$SUFFIX" > "$STATE"
fi
DEV="${PREFIX}-dev-${SUFFIX}"
PROD="${PREFIX}-prod-${SUFFIX}"
SHARED="${PREFIX}-shared-${SUFFIX}"
# Single-project mode: put every scenario in one existing project (e.g. Proj1).
if [[ -n "${SINGLE_PROJECT:-}" ]]; then DEV="$SINGLE_PROJECT"; PROD="$SINGLE_PROJECT"; SHARED="$SINGLE_PROJECT"; fi
save_state() { grep -q "^$1=" "$STATE" 2>/dev/null && sed -i "s|^$1=.*|$1=$2|" "$STATE" || echo "$1=$2" >> "$STATE"; }

# --------------------------------------------------------------- helpers -----
# Unconditional project binding. --condition=None is required once any
# conditional binding exists on the policy, otherwise gcloud refuses.
bind_project() { gcloud projects add-iam-policy-binding "$1" --member="$2" --role="$3" --condition=None >/dev/null && info "bind $3 → $2 on $1"; }
bind_folder()  { gcloud resource-manager folders add-iam-policy-binding "$1" --member="$2" --role="$3" --condition=None >/dev/null && info "bind $3 → $2 on folders/$1"; }
bind_sa()      { gcloud iam service-accounts add-iam-policy-binding "$1" --member="$2" --role="$3" --project="$4" --condition=None >/dev/null && info "bind $3 → $2 on $1"; }
sa_email()     { echo "$1@$2.iam.gserviceaccount.com"; }
ensure_sa() {  # name project display
  local email; email="$(sa_email "$1" "$2")"
  gcloud iam service-accounts describe "$email" --project="$2" >/dev/null 2>&1 \
    || { gcloud iam service-accounts create "$1" --project="$2" --display-name="$3" >/dev/null; info "created SA $email"; sleep 5; }
}
project_number() { gcloud projects describe "$1" --format='value(projectNumber)'; }
org_policy() {  # name(file stem) yaml-body
  local f="$TMP/$1.yaml"; printf '%s\n' "$2" > "$f"
  gcloud org-policies set-policy "$f" --billing-project="$DEV" >/dev/null && info "org policy $1"
}

# ======================================================================
log "0. Pre-flight"
ACTIVE="$(gcloud config get-value account 2>/dev/null)"
info "signed in as: $ACTIVE"
if [[ "$NO_ORG" == "yes" ]]; then
  warn "NO ORGANIZATION: folders, org policy, custom org role and groups will be skipped"
else
  gcloud organizations describe "$ORG_ID" >/dev/null || { echo "Cannot read organization $ORG_ID"; exit 1; }
  CUSTOMER_ID="$(gcloud organizations describe "$ORG_ID" --format='value(owner.directoryCustomerId)')"
  info "organization $ORG_ID (customer $CUSTOMER_ID), domain $DOMAIN"
fi
gcloud billing accounts describe "$BILLING_ACCOUNT" >/dev/null || { echo "Cannot read billing account $BILLING_ACCOUNT"; exit 1; }
info "billing account $BILLING_ACCOUNT"

# ======================================================================
log "1. Folders and projects"
folder_id() {  # display-name
  gcloud resource-manager folders list --organization="$ORG_ID" \
    --filter="displayName=$1" --format='value(name)' 2>/dev/null | sed -n '1s|folders/||p'
}
if [[ "$NO_ORG" == "yes" ]]; then FOLDER_A=""; FOLDER_B=""; skip "folders (no organization)"; else
FOLDER_A="$(folder_id "${PREFIX}-folder-a")"
[[ -n "$FOLDER_A" ]] || { gcloud resource-manager folders create --display-name="${PREFIX}-folder-a" --organization="$ORG_ID" >/dev/null; sleep 5; FOLDER_A="$(folder_id "${PREFIX}-folder-a")"; info "created folder A"; }
FOLDER_B="$(folder_id "${PREFIX}-folder-b")"
[[ -n "$FOLDER_B" ]] || { gcloud resource-manager folders create --display-name="${PREFIX}-folder-b" --organization="$ORG_ID" >/dev/null; sleep 5; FOLDER_B="$(folder_id "${PREFIX}-folder-b")"; info "created folder B"; }
save_state FOLDER_A "$FOLDER_A"; save_state FOLDER_B "$FOLDER_B"
info "folder A = $FOLDER_A, folder B = $FOLDER_B"
fi

ensure_project() {  # id folder
  gcloud projects describe "$1" >/dev/null 2>&1 && return 0
  if [[ -n "$2" ]]; then gcloud projects create "$1" --folder="$2" --name="$1" >/dev/null
  else gcloud projects create "$1" --name="$1" >/dev/null; fi
  info "created project $1"
}
ensure_project "$DEV"    "$FOLDER_A"
ensure_project "$PROD"   "$FOLDER_A"
ensure_project "$SHARED" "$FOLDER_B"
save_state DEV "$DEV"; save_state PROD "$PROD"; save_state SHARED "$SHARED"

log "1b. Billing (dev + prod only) and budget"
for p in "$DEV" "$PROD"; do
  cur="$(gcloud billing projects describe "$p" --format='value(billingAccountName)')"
  if [[ "$cur" != "billingAccounts/$BILLING_ACCOUNT" ]]; then
    gcloud billing projects link "$p" --billing-account="$BILLING_ACCOUNT" >/dev/null && info "linked billing to $p" \
      || { echo "    Could not link billing to $p. Personal billing accounts allow only a few linked projects:"; \
           echo "    unlink an unused project in Console > Billing > Account management, then re-run."; exit 1; }
  else skip "billing already linked to $p"; fi
done
BILLED=yes
for p in "$DEV" "$PROD"; do
  if [[ "$(gcloud billing projects describe "$p" --format='value(billingEnabled)')" != "True" ]]; then BILLED=no; fi
done
if [[ "$BILLED" == "no" ]]; then
  warn "Billing is NOT active (billingEnabled=false). The billing account is closed or the free trial ended."
  warn "Continuing with the free scenarios only. Skipped: buckets, HMAC key, secret, VM, SSH keys,"
  warn "Cloud Run, Cloud Function, scheduler, GKE, budget. Re-run after fixing billing to add them."
fi
save_state BILLED "$BILLED"

log "1c. Enable APIs"
enable_apis() {  # project api...  (one at a time so one refusal doesn't stop the rest)
  local p="$1"; shift
  for a in "$@"; do gcloud services enable "$a" --project="$p" >/dev/null 2>&1 || warn "could not enable $a on $p"; done
}
FREE_APIS="iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com cloudresourcemanager.googleapis.com cloudasset.googleapis.com orgpolicy.googleapis.com essentialcontacts.googleapis.com apikeys.googleapis.com logging.googleapis.com policyanalyzer.googleapis.com recommender.googleapis.com bigquery.googleapis.com"
BILLED_APIS="billingbudgets.googleapis.com compute.googleapis.com run.googleapis.com cloudfunctions.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com cloudscheduler.googleapis.com storage.googleapis.com secretmanager.googleapis.com container.googleapis.com"
# shellcheck disable=SC2086
for p in $(printf '%s\n' "$DEV" "$PROD" "$SHARED" | sort -u); do
  enable_apis "$p" $FREE_APIS
  [[ "$NO_ORG" == "no" ]] && enable_apis "$p" cloudidentity.googleapis.com
  [[ "$BILLED" == "yes" && "$p" != "$SHARED" ]] && enable_apis "$p" $BILLED_APIS
done
info "APIs enabled"

if [[ "$BILLED" == "no" ]]; then skip "budget (billing not active)"
elif ! gcloud billing budgets list --billing-account="$BILLING_ACCOUNT" --billing-project="$DEV" \
     --format='value(displayName)' 2>/dev/null | grep -x "${PREFIX}-test-budget" >/dev/null; then
  gcloud billing budgets create --billing-account="$BILLING_ACCOUNT" --billing-project="$DEV" \
    --display-name="${PREFIX}-test-budget" --budget-amount="${BUDGET_AMOUNT}USD" \
    --filter-projects="$( [[ "$DEV" == "$PROD" ]] && echo "projects/$DEV" || echo "projects/$DEV,projects/$PROD")" \
    --threshold-rule=percent=0.5 --threshold-rule=percent=0.9 --threshold-rule=percent=1.0 >/dev/null
  info "budget ${BUDGET_AMOUNT} USD created with 50/90/100% alerts"
else skip "budget exists"; fi

DEV_NUM="$(project_number "$DEV")"; PROD_NUM="$(project_number "$PROD")"; SHARED_NUM="$(project_number "$SHARED")"
save_state DEV_NUM "$DEV_NUM"; save_state PROD_NUM "$PROD_NUM"

# ======================================================================
log "2. Org policy: relax secure-by-default on test projects, add guardrails on folder B"
if [[ "$NO_ORG" == "yes" ]]; then skip "no organization: no org policies exist, nothing to relax; scenario 18 skipped"; else
# Organizations created after early 2024 enforce several constraints by default
# (no SA keys, domain-restricted sharing, uniform bucket access, no automatic
# Editor for default SAs). The scenarios need those relaxed on dev/prod only.
for p in "$DEV" "$PROD"; do
  org_policy "keys-$p" "name: projects/$p/policies/iam.disableServiceAccountKeyCreation
spec:
  rules:
  - enforce: false"
  org_policy "drs-$p" "name: projects/$p/policies/iam.allowedPolicyMemberDomains
spec:
  rules:
  - allowAll: true"
done
org_policy "ubla-$PROD" "name: projects/$PROD/policies/storage.uniformBucketLevelAccess
spec:
  rules:
  - enforce: false"
# Scenario 18: guardrails on folder B (iga-shared)
org_policy "folderB-keys" "name: folders/$FOLDER_B/policies/iam.disableServiceAccountKeyCreation
spec:
  rules:
  - enforce: true"
org_policy "folderB-drs" "name: folders/$FOLDER_B/policies/iam.allowedPolicyMemberDomains
spec:
  rules:
  - values:
      allowedValues:
      - $CUSTOMER_ID"
info "waiting 60s for org policy to propagate"; sleep 60
fi

# ======================================================================
log "3. Identities and credentials (scenarios 1–4, 9)"
# 1. user-managed SA with a key (age accrues; findings use a configurable N)
ensure_sa old-key-sa "$DEV" "IGA: user-managed SA with key"
OLD_SA="$(sa_email old-key-sa "$DEV")"
if [[ -z "$(gcloud iam service-accounts keys list --iam-account="$OLD_SA" --managed-by=user --format='value(name)')" ]]; then
  gcloud iam service-accounts keys create "$TMP/k.json" --iam-account="$OLD_SA" >/dev/null
  shred -u "$TMP/k.json" 2>/dev/null || rm -f "$TMP/k.json"   # key material never kept
  info "created user-managed key on $OLD_SA (local file destroyed)"
else skip "key exists on $OLD_SA"; fi
bind_project "$DEV" "serviceAccount:$OLD_SA" roles/viewer

# 2. default compute SA holding Editor (explicit: new orgs no longer auto-grant it)
DEFAULT_SA="${DEV_NUM}-compute@developer.gserviceaccount.com"
if [[ "$BILLED" == "yes" ]]; then bind_project "$DEV" "serviceAccount:$DEFAULT_SA" roles/editor
else skip "default compute SA (needs Compute Engine, i.e. billing)"; fi

# 3. Google service agents appear automatically once APIs are enabled (above).

# 4. HMAC key + restricted API key
if [[ "$BILLED" == "no" ]]; then skip "HMAC key (needs Cloud Storage, i.e. billing)"
elif [[ -z "$(gcloud storage hmac list --project="$DEV" --service-account="$OLD_SA" --format='value(accessId)' 2>/dev/null)" ]]; then
  gcloud storage hmac create "$OLD_SA" --project="$DEV" >/dev/null && info "HMAC key created (secret not stored)"
else skip "HMAC key exists"; fi
if [[ -z "$(gcloud services api-keys list --project="$DEV" --filter="displayName=${PREFIX}-restricted-key" --format='value(name)' 2>/dev/null)" ]]; then
  gcloud services api-keys create --project="$DEV" --display-name="${PREFIX}-restricted-key" \
    --api-target=service=storage.googleapis.com --allowed-ips=203.0.113.10 >/dev/null 2>&1 && info "API key created (key string not shown)" || warn "API key not created"
else skip "API key exists"; fi

# 9. binding to a deleted SA
DEL_SA="$(sa_email deleted-later-sa "$DEV")"
if ! grep -q "deleted-later" <<<"$(gcloud projects get-iam-policy "$DEV" --format=json)"; then
  ensure_sa deleted-later-sa "$DEV" "IGA: will be deleted"
  bind_project "$DEV" "serviceAccount:$DEL_SA" roles/viewer
  gcloud iam service-accounts delete "$DEL_SA" --project="$DEV" >/dev/null && info "deleted $DEL_SA (binding remains as deleted:)"
else skip "deleted-principal binding already present"; fi

# ======================================================================
log "4. Access: bindings, conditions, custom roles, public buckets (5–8)"
# 5. folder-level binding inherited by dev and prod
ensure_sa folder-reader-sa "$SHARED" "IGA: folder A reader"
if [[ "$NO_ORG" == "yes" ]]; then
  bind_project "$PROD" "serviceAccount:$(sa_email folder-reader-sa "$SHARED")" roles/viewer
  skip "folder inheritance (no organization); bound at project level instead"
else
  bind_folder "$FOLDER_A" "serviceAccount:$(sa_email folder-reader-sa "$SHARED")" roles/viewer
fi

# 6. conditional bindings: one future expiry, one already expired
ensure_sa contractor-sa "$PROD" "IGA: time-bound access"
CON_SA="$(sa_email contractor-sa "$PROD")"
gcloud projects add-iam-policy-binding "$PROD" --member="serviceAccount:$CON_SA" --role=roles/storage.objectViewer \
  --condition='expression=request.time < timestamp("2027-06-30T00:00:00Z"),title=expires-2027-06,description=Contractor access until June 2027' >/dev/null && info "future-expiry conditional binding"
gcloud projects add-iam-policy-binding "$PROD" --member="serviceAccount:$CON_SA" --role=roles/bigquery.dataViewer \
  --condition='expression=request.time < timestamp("2026-01-01T00:00:00Z"),title=expired-2026-01,description=Already expired' >/dev/null && info "expired conditional binding"

# 7. custom roles
if [[ "$NO_ORG" == "yes" ]]; then skip "custom org role (no organization)"
elif ! gcloud iam roles describe igaOrgAuditor --organization="$ORG_ID" >/dev/null 2>&1; then
  gcloud iam roles create igaOrgAuditor --organization="$ORG_ID" --title="IGA Org Auditor" \
    --permissions=resourcemanager.projects.get,resourcemanager.projects.list,iam.roles.list --stage=GA >/dev/null && info "custom org role igaOrgAuditor"
else skip "custom org role exists"; fi
if ! gcloud iam roles describe igaDeployer --project="$DEV" >/dev/null 2>&1; then
  gcloud iam roles create igaDeployer --project="$DEV" --title="IGA Deployer (has actAs)" \
    --permissions=iam.serviceAccounts.actAs,run.services.create,run.services.update,run.services.get --stage=GA >/dev/null && info "custom project role igaDeployer (actAs)"
else skip "custom project role exists"; fi
ensure_sa deployer-sa "$DEV" "IGA: deployer"
DEPLOYER_SA="$(sa_email deployer-sa "$DEV")"
bind_project "$DEV" "serviceAccount:$DEPLOYER_SA" "projects/$DEV/roles/igaDeployer"
[[ "$NO_ORG" == "no" ]] && bind_project "$DEV" "user:$ADMIN_EMAIL" "organizations/$ORG_ID/roles/igaOrgAuditor"

# 8. public bucket via IAM (uniform) and public bucket via ACL (non-uniform)
PUB_BUCKET="gs://${PREFIX}-public-iam-${SUFFIX}"
if [[ "$BILLED" == "yes" ]]; then
ACL_BUCKET="gs://${PREFIX}-public-acl-${SUFFIX}"
gcloud storage buckets describe "$PUB_BUCKET" >/dev/null 2>&1 || gcloud storage buckets create "$PUB_BUCKET" --project="$PROD" --location="$REGION" --uniform-bucket-level-access >/dev/null
gcloud storage buckets add-iam-policy-binding "$PUB_BUCKET" --member=allUsers --role=roles/storage.objectViewer >/dev/null && info "allUsers on $PUB_BUCKET"
gcloud storage buckets describe "$ACL_BUCKET" >/dev/null 2>&1 || gcloud storage buckets create "$ACL_BUCKET" --project="$PROD" --location="$REGION" --no-uniform-bucket-level-access >/dev/null
gcloud storage buckets update "$ACL_BUCKET" --add-acl-grant=entity=allUsers,role=READER >/dev/null && info "allUsers ACL on $ACL_BUCKET"
gcloud storage buckets update "$PUB_BUCKET" "$ACL_BUCKET" --update-labels=owner=akash,team=iga,env=prod >/dev/null

# Secret + BigQuery as resource-level IAM targets
if ! gcloud secrets describe "${PREFIX}-sap-password" --project="$PROD" >/dev/null 2>&1; then
  printf 'not-a-real-password' | gcloud secrets create "${PREFIX}-sap-password" --project="$PROD" --data-file=- --labels=owner=akash,env=prod >/dev/null && info "secret created (dummy value)"
fi
else skip "buckets and secret (need billing)"; fi

# ======================================================================
log "5. Trust: impersonation, cross-project, external member (10–12)"
ensure_sa app-sa "$PROD" "IGA: application SA"
APP_SA="$(sa_email app-sa "$PROD")"
[[ "$BILLED" == "yes" ]] && { gcloud secrets add-iam-policy-binding "${PREFIX}-sap-password" --project="$PROD" --member="serviceAccount:$APP_SA" --role=roles/secretmanager.secretAccessor --condition=None >/dev/null && info "app-sa can read the secret"; }
bind_project "$PROD" "serviceAccount:$APP_SA" roles/editor   # scenario: prod SA with Editor at project
# 10. project-level Token Creator for a user → can impersonate every SA in dev
bind_project "$DEV" "user:${TEST_USER_EMAIL:-$ADMIN_EMAIL}" roles/iam.serviceAccountTokenCreator
#     SA-level Service Account User on one SA
bind_sa "$APP_SA" "serviceAccount:$DEPLOYER_SA" roles/iam.serviceAccountUser "$PROD"
# 11. SA from shared project granted a role in prod (cross-project)
ensure_sa cross-project-sa "$SHARED" "IGA: cross-project SA"
bind_project "$PROD" "serviceAccount:$(sa_email cross-project-sa "$SHARED")" roles/storage.objectAdmin
# 12. member from outside the domain
if [[ -n "${EXTERNAL_USER_EMAIL:-}" ]]; then bind_project "$PROD" "user:$EXTERNAL_USER_EMAIL" roles/viewer
else warn "EXTERNAL_USER_EMAIL not set — scenario 12 skipped"; fi

# ======================================================================
log "6. Federation: GitHub OIDC (13)"
POOL=iga-github
if ! gcloud iam workload-identity-pools describe "$POOL" --project="$DEV" --location=global >/dev/null 2>&1; then
  gcloud iam workload-identity-pools create "$POOL" --project="$DEV" --location=global --display-name="IGA GitHub" >/dev/null && info "pool $POOL"; sleep 5
fi
if [[ -n "${GITHUB_REPO:-}" ]]; then
  if ! gcloud iam workload-identity-pools providers describe github --project="$DEV" --location=global --workload-identity-pool="$POOL" >/dev/null 2>&1; then
    gcloud iam workload-identity-pools providers create-oidc github --project="$DEV" --location=global --workload-identity-pool="$POOL" \
      --issuer-uri=https://token.actions.githubusercontent.com \
      --attribute-mapping=google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref \
      --attribute-condition="assertion.repository=='${GITHUB_REPO}'" >/dev/null && info "provider github (conditioned on $GITHUB_REPO)"
  fi
  bind_sa "$DEPLOYER_SA" "principalSet://iam.googleapis.com/projects/$DEV_NUM/locations/global/workloadIdentityPools/$POOL/attribute.repository/$GITHUB_REPO" roles/iam.workloadIdentityUser "$DEV"
else warn "GITHUB_REPO not set — conditioned provider skipped"; fi
# Broad provider: Google may require a condition for well-known issuers; fall
# back to a condition that admits every subject, which is the same exposure.
if ! gcloud iam workload-identity-pools providers describe gitlab-broad --project="$DEV" --location=global --workload-identity-pool="$POOL" >/dev/null 2>&1; then
  if gcloud iam workload-identity-pools providers create-oidc gitlab-broad --project="$DEV" --location=global --workload-identity-pool="$POOL" \
       --issuer-uri=https://gitlab.com --attribute-mapping=google.subject=assertion.sub,attribute.project_path=assertion.project_path >/dev/null 2>&1; then
    info "provider gitlab-broad (no attribute condition)"
  else
    gcloud iam workload-identity-pools providers create-oidc gitlab-broad --project="$DEV" --location=global --workload-identity-pool="$POOL" \
      --issuer-uri=https://gitlab.com --attribute-mapping=google.subject=assertion.sub,attribute.project_path=assertion.project_path \
      --attribute-condition="assertion.sub != ''" >/dev/null && warn "Google required a condition; gitlab-broad created with an always-true condition"
  fi
fi
bind_project "$DEV" "principalSet://iam.googleapis.com/projects/$DEV_NUM/locations/global/workloadIdentityPools/$POOL/*" roles/viewer

# ======================================================================
log "7. Workloads (15) and SSH keys (16)"
if [[ "$BILLED" == "no" ]]; then
  skip "workloads, SSH keys and scheduler (need billing)"
  ensure_sa active-sa "$DEV" "IGA: used every day"; ensure_sa idle-sa "$PROD" "IGA: never used"
  bind_project "$PROD" "serviceAccount:$(sa_email idle-sa "$PROD")" roles/storage.admin
else
# Cloud Run with its own SA (public sample image, scales to zero)
ensure_sa run-sa "$DEV" "IGA: Cloud Run runtime"
RUN_SA="$(sa_email run-sa "$DEV")"
gcloud run services describe "${PREFIX}-run" --project="$DEV" --region="$REGION" >/dev/null 2>&1 || \
  gcloud run deploy "${PREFIX}-run" --project="$DEV" --region="$REGION" --image=us-docker.pkg.dev/cloudrun/container/hello \
    --service-account="$RUN_SA" --no-allow-unauthenticated --min-instances=0 --max-instances=1 --labels=owner=akash,env=dev >/dev/null
info "Cloud Run ${PREFIX}-run runs as $RUN_SA"

# Cloud Function (gen2) on its own SA
ensure_sa fn-sa "$DEV" "IGA: function runtime"
mkdir -p "$TMP/fn"; printf 'def hello(request):\n    return "ok"\n' > "$TMP/fn/main.py"; : > "$TMP/fn/requirements.txt"
gcloud functions describe "${PREFIX}-fn" --project="$DEV" --region="$REGION" --gen2 >/dev/null 2>&1 || \
  gcloud functions deploy "${PREFIX}-fn" --gen2 --project="$DEV" --region="$REGION" --runtime=python312 --source="$TMP/fn" \
    --entry-point=hello --trigger-http --no-allow-unauthenticated --service-account="$(sa_email fn-sa "$DEV")" --max-instances=1 >/dev/null
info "Cloud Function ${PREFIX}-fn"

# VM on the default compute SA (free-tier e2-micro) with an SSH key in instance metadata
ssh-keygen -q -t ed25519 -N '' -C "iga-test-user" -f "$TMP/vmkey" >/dev/null
INST_KEY="iga-test-user:$(cat "$TMP/vmkey.pub")"
gcloud compute instances describe "${PREFIX}-vm" --project="$DEV" --zone="$ZONE" >/dev/null 2>&1 || \
  gcloud compute instances create "${PREFIX}-vm" --project="$DEV" --zone="$ZONE" --machine-type=e2-micro \
    --image-family=debian-12 --image-project=debian-cloud --boot-disk-size=10GB \
    --service-account="$DEFAULT_SA" --scopes=cloud-platform \
    --metadata=ssh-keys="$INST_KEY" --labels=owner=akash,env=dev >/dev/null
info "VM ${PREFIX}-vm on default compute SA, SSH key in instance metadata"
# project-wide SSH key
ssh-keygen -q -t ed25519 -N '' -C "iga-project-user" -f "$TMP/projkey" >/dev/null
gcloud compute project-info add-metadata --project="$DEV" --metadata=ssh-keys="iga-project-user:$(cat "$TMP/projkey.pub")" >/dev/null
info "project-wide SSH key (private keys discarded)"

# Cloud Scheduler job running as an SA every day (also scenario 21: the active SA)
ensure_sa active-sa "$DEV" "IGA: used every day"
ACTIVE_SA="$(sa_email active-sa "$DEV")"
bind_project "$DEV" "serviceAccount:$ACTIVE_SA" roles/browser
gcloud scheduler jobs describe "${PREFIX}-daily" --project="$DEV" --location="$REGION" >/dev/null 2>&1 || \
  gcloud scheduler jobs create http "${PREFIX}-daily" --project="$DEV" --location="$REGION" --schedule="17 9 * * *" \
    --uri="https://cloudresourcemanager.googleapis.com/v3/projects/$DEV" --http-method=GET \
    --oauth-service-account-email="$ACTIVE_SA" --oauth-token-scope=https://www.googleapis.com/auth/cloud-platform >/dev/null
info "scheduler job ${PREFIX}-daily authenticates as $ACTIVE_SA daily"
# idle SA with broad unused access
ensure_sa idle-sa "$PROD" "IGA: never used"
bind_project "$PROD" "serviceAccount:$(sa_email idle-sa "$PROD")" roles/storage.admin

# ======================================================================
fi
log "8. GKE Workload Identity (14) — ENABLE_GKE=$ENABLE_GKE"
GKE_GSA="$(sa_email gke-app-gsa "$PROD")"
ensure_sa gke-app-gsa "$PROD" "IGA: GKE app GSA"
# Bindings exist even without a cluster, so discovery can be tested cheaply.
GKE_BOUND=no
bind_sa "$GKE_GSA" "serviceAccount:${PROD}.svc.id.goog[iga/app-ksa]" roles/iam.workloadIdentityUser "$PROD" 2>/dev/null && GKE_BOUND=yes \
  || warn "KSA→GSA binding refused: the GKE identity namespace exists only after GKE is enabled (needs billing)"
if [[ "$ENABLE_GKE" == "yes" && "$BILLED" == "yes" ]]; then
  gcloud container clusters describe "${PREFIX}-gke" --project="$PROD" --region="$REGION" >/dev/null 2>&1 || \
    gcloud container clusters create-auto "${PREFIX}-gke" --project="$PROD" --region="$REGION" >/dev/null
  info "Autopilot cluster ${PREFIX}-gke (remove with teardown.sh when done)"
  gcloud storage buckets add-iam-policy-binding "$PUB_BUCKET" \
    --member="principal://iam.googleapis.com/projects/$PROD_NUM/locations/global/workloadIdentityPools/${PROD}.svc.id.goog/subject/ns/iga/sa/direct-ksa" \
    --role=roles/storage.objectViewer >/dev/null && info "direct principal:// grant for KSA iga/direct-ksa"
else skip "cluster (set ENABLE_GKE=yes and active billing)"; fi

# ======================================================================
log "9. Guardrails: deny policy (17)"
cat > "$TMP/deny.json" <<EOF
{
  "displayName": "IGA test: block project deletion",
  "rules": [{
    "denyRule": {
      "deniedPrincipals": ["principalSet://goog/public:all"],
      "exceptionPrincipals": ["principal://goog/subject/$ADMIN_EMAIL"],
      "deniedPermissions": ["cloudresourcemanager.googleapis.com/projects.delete"]
    }
  }]
}
EOF
ATTACH="cloudresourcemanager.googleapis.com%2Fprojects%2F${PROD}"
if gcloud iam policies get iga-deny-delete --attachment-point="$ATTACH" --kind=denypolicies >/dev/null 2>&1 \
   || gcloud iam policies create iga-deny-delete --attachment-point="$ATTACH" --kind=denypolicies --policy-file="$TMP/deny.json" >/dev/null 2>&1; then
  info "deny policy on $PROD with exception for $ADMIN_EMAIL"
else warn "deny policy not created: needs the Deny Admin role, which is granted only at organization level — scenario 17 skipped"; fi

# ======================================================================
log "10. Ownership + sensitivity (19–20)"
label_project() { gcloud alpha projects update "$1" --update-labels="$2" >/dev/null 2>&1 && info "labels $2 on $1" || warn "could not label $1"; }
if [[ "$DEV" == "$PROD" ]]; then label_project "$DEV" owner=akash,team=iga,env=test
else label_project "$DEV" owner=akash,team=iga,env=dev; label_project "$PROD" owner=akash,team=iga,env=prod; label_project "$SHARED" team=platform,env=shared; fi
if [[ -z "$(gcloud essential-contacts list --project="$PROD" --format='value(email)' 2>/dev/null)" ]]; then
  gcloud essential-contacts create --project="$PROD" --email="$ADMIN_EMAIL" --notification-categories=technical,security >/dev/null && info "Essential Contact on $PROD" || warn "Essential Contact not created"
fi
DS="${PREFIX//-/_}_finance"
{ bq --project_id="$PROD" show "$DS" >/dev/null 2>&1 || bq --project_id="$PROD" mk --location=US --label=owner:akash --label=env:prod "$DS" >/dev/null; } || warn "BigQuery dataset not created"
printf 'invoice_id,customer_name,email,card_last4,amount\n1,Test Person,test.person@example.com,4242,120.50\n2,Sample User,sample.user@example.com,1881,99.00\n' > "$TMP/inv.csv"
bq --project_id="$PROD" show "$DS.ap_invoices" >/dev/null 2>&1 || \
  bq --project_id="$PROD" load --source_format=CSV --skip_leading_rows=1 "$DS.ap_invoices" "$TMP/inv.csv" \
    invoice_id:INTEGER,customer_name:STRING,email:STRING,card_last4:STRING,amount:FLOAT >/dev/null || warn "BigQuery table not loaded"
info "BigQuery $DS.ap_invoices with fake data"
bq --project_id="$PROD" query --use_legacy_sql=false --quiet \
  "GRANT \`roles/bigquery.dataViewer\` ON TABLE \`$PROD.$DS.ap_invoices\` TO \"serviceAccount:$APP_SA\"" >/dev/null && info "table-level grant to app-sa" || warn "table-level grant not applied"
[[ "$ENABLE_DLP" == "yes" ]] && warn "DLP discovery: enable it in the console (Security > Sensitive Data Protection > Discovery) for $PROD — not scripted" || skip "DLP (optional)"

# ======================================================================
log "11. Data Access logs on prod only (enables the 'on' vs 'off' case)"
if [[ "$ENABLE_DATA_ACCESS_LOGS" == "yes" ]]; then
  gcloud projects get-iam-policy "$PROD" --format=json > "$TMP/pol.json"
  if ! jq -e '.auditConfigs // [] | map(select(.service=="allServices")) | length > 0' "$TMP/pol.json" >/dev/null; then
    jq '.auditConfigs = ((.auditConfigs // []) + [{"service":"allServices","auditLogConfigs":[{"logType":"DATA_READ"},{"logType":"DATA_WRITE"}]}])' "$TMP/pol.json" > "$TMP/pol2.json"
    gcloud projects set-iam-policy "$PROD" "$TMP/pol2.json" >/dev/null && info "Data Access logs ON for $PROD"
  else skip "Data Access logs already on"; fi
fi

# ======================================================================
log "12. Directory: groups, nesting, group binding (22)"
if [[ "$NO_ORG" == "yes" ]]; then skip "groups need Cloud Identity (no organization) — scenario 22 skipped"; else
if gcloud identity groups describe "${PREFIX}-finance-readers@$DOMAIN" >/dev/null 2>&1; then skip "groups exist"; else
  gcloud identity groups create "${PREFIX}-finance-readers@$DOMAIN" --organization="$DOMAIN" --display-name="IGA finance readers" >/dev/null && info "group finance-readers"
  gcloud identity groups create "${PREFIX}-contractors@$DOMAIN" --organization="$DOMAIN" --display-name="IGA contractors" >/dev/null && info "group contractors"
fi
gcloud identity groups memberships add --group-email="${PREFIX}-finance-readers@$DOMAIN" --member-email="${PREFIX}-contractors@$DOMAIN" >/dev/null 2>&1 && info "contractors nested in finance-readers" || skip "nesting exists"
for u in "${TEST_USER_EMAIL:-}" "${SUSPENDED_USER_EMAIL:-}"; do
  [[ -z "$u" ]] && continue
  gcloud identity groups memberships add --group-email="${PREFIX}-contractors@$DOMAIN" --member-email="$u" >/dev/null 2>&1 && info "$u in contractors" || skip "$u already member"
done
bind_project "$PROD" "group:${PREFIX}-finance-readers@$DOMAIN" roles/bigquery.dataViewer
[[ -z "${SUSPENDED_USER_EMAIL:-}" ]] && warn "SUSPENDED_USER_EMAIL not set — create and suspend a user in admin.google.com (see README)"
fi

# ======================================================================
log "Done"
cat <<EOF
    Org:     ${ORG_ID:-none}   Folder A: ${FOLDER_A:-none}   Folder B: ${FOLDER_B:-none}
    dev:     $DEV ($DEV_NUM)
    prod:    $PROD ($PROD_NUM)
    shared:  $SHARED ($SHARED_NUM)
    State saved in $STATE

    Next: onboard in AuthSec (Discovery → GCP): organization scope if you have one,
    otherwise project scope, once per project ($DEV, $PROD, $SHARED),
    then compare scan results with expected.json.
EOF
