# GCP IGA test environment (ticket GCP-0)

A real Google Cloud organization with every scenario the GCP discovery tickets are tested against.

| File | What it is |
|---|---|
| `config.example.env` | Settings to copy to `config.env` and fill in |
| `seed.sh` | Creates folders, projects and all scenarios. Safe to re-run |
| `teardown.sh` | Removes costly resources; `--all` removes everything |
| `expected.json` | What AuthSec must discover, per scenario |
| `github-oidc-workflow.yml` | GitHub Actions workflow for the federation scenario |

## Step 1 — one-time manual setup (browser)

These cannot be done from the command line.

1. **Domain.** Use a separate test domain you control, not the company domain. Signing the company domain up for Cloud Identity affects real company accounts.
2. **Organization.** Sign up for Cloud Identity Free at <https://workspace.google.com/gcpidentity/signup> with that domain and verify it (DNS TXT record). The organization appears in Google Cloud automatically after verification.
3. **Move billing.** The billing account Proj1 uses can be linked to the new projects. Make sure your account has *Billing Account User* on it.
4. **Give yourself org roles** (Cloud Console → IAM at the organization level, as the super admin):
   Organization Administrator, Folder Admin, Project Creator, Organization Policy Administrator, Organization Role Administrator, Deny Admin, Billing Account User, Essential Contacts Admin.
5. **Test users** in <https://admin.google.com>:
   - `test.user@<domain>` — active
   - `test.suspended@<domain>` — create it now, suspend it after `seed.sh` has added it to the group
   - Any outside account, for example a personal Gmail, as the external member
6. **GitHub repo** (optional but recommended): any repo you control. Copy `github-oidc-workflow.yml` into `.github/workflows/` after the seed run and fill in the values it prints.

## Step 2 — run

Use **Google Cloud Shell** (top right of the console). It is already signed in and has `gcloud`, `bq`, `jq` and `ssh-keygen`.

```bash
# upload this folder to Cloud Shell (⋮ → Upload), then:
cd gcp-lab
cp config.example.env config.env && nano config.env     # fill in
bash seed.sh                                             # 10–15 minutes
```

Add the GKE cluster only on days you test GKE (costs while it runs):

```bash
ENABLE_GKE=yes bash seed.sh
```

To find your IDs:

```bash
gcloud organizations list                              # ORG_ID
gcloud billing projects describe <proj1-id>            # BILLING_ACCOUNT
```

## Step 3 — onboard into AuthSec

AuthSec console → Discovery → GCP → connect at **organization** scope. Then run a scan and compare with `expected.json`.

## What the script changes and why

- **Secure-by-default org policies.** New organizations block SA keys, outside members and non-uniform buckets. `seed.sh` relaxes these **only on the dev and prod test projects**, because several scenarios need them, and adds guardrails on folder B so both cases exist.
- **No key material kept.** The SA key file is destroyed immediately; HMAC secrets and API key strings are never printed or saved; SSH private keys are generated in a temp folder and deleted.
- **Billing is linked to dev and prod only.** `shared` stays unbilled.
- **Budget alert** at `BUDGET_AMOUNT` USD (default 10) on the two billed projects.

## Cost

Everything is sized for the free tier: one e2-micro VM, Cloud Run and Functions scaled to zero, tiny buckets and a two-row BigQuery table. The GKE Autopilot cluster is the only thing with a real hourly cost — create it with `ENABLE_GKE=yes` only when needed and run `bash teardown.sh` afterwards. Check Google's current free-tier limits; they change.

## Not scripted (do by hand if needed)

| Scenario | How |
|---|---|
| 20 DLP data profiles | Console → Security → Sensitive Data Protection → Discovery → BigQuery, scope `<prod>` |
| 23 VPC Service Controls | Console → Security → VPC Service Controls → new perimeter around one project |
| Suspended user | admin.google.com → Users → suspend `test.suspended` |
| SA key older than 90 days | Age accrues; set the finding threshold N to 0 for testing |
| Cloud Build trigger | Needs a connected repo; the Cloud Scheduler job covers the "workload with SA" case |

## Teardown

```bash
bash teardown.sh          # removes GKE, VM, Cloud Run, Function; pauses the scheduler
bash teardown.sh --all    # also deletes buckets, projects (30-day recovery), folders, custom org role, groups
```
