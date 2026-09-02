# GCP-01 — Pre-build feasibility validation (evidence ledger)

**Status: PARTIAL** — live GCP access was available and used for every
question that doesn't require billing. Two sub-items remain genuinely
unverified for reasons recorded below (no live GKE cluster: billing
unavailable; no publicly-reachable AuthSec OIDC issuer: only a local dev
instance exists). All four original blocking questions (a–d) and question
(e)'s mechanism-level behavior are answered with real evidence; (d) is fully
UNVERIFIED and (e)'s full round trip (successful impersonation against a real
external issuer) is UNVERIFIED. Nothing below is fabricated — every claim
cites the exact command and its exact output.

Spike run: 2026-09-01, against a real GCP org/project (not a mock).

## Test environment used

- Org: `akashmaurya885506-org` (`organizations/695908590846`)
- Project: `authsec-gcp-test` (project number `438408545566`), parented
  directly under the org (no intermediate folder exists in this org — folder
  scope is therefore covered by role-definition inspection and a real
  `folders.list` call returning zero rows, not by a real folder-scoped
  binding; see question (a)).
- Billing: **not enabled** on `authsec-gcp-test`, and the only billing
  account on the identity (`0176FF-CD3D25-A7EADF`) is **closed**
  (`OPEN=False`). This is a real, load-bearing constraint recorded throughout
  this ledger, not a gap in effort — billing-gated services could not be
  enabled by any available credential.
- Disposable reader identity: `authsec-reader-spike@authsec-gcp-test.iam.gserviceaccount.com`,
  created fresh for this spike, distinct from the pre-existing
  `authsec-reader@authsec-gcp-test.iam.gserviceaccount.com` found already in
  the project (left untouched — appears to be a leftover from a prior,
  unrelated setup pass and was not used or modified by this spike).
- All API calls attributed to "the reader" below were made **as the reader
  identity** via `gcloud ... --impersonate-service-account=authsec-reader-spike@...`,
  not as the operator's own owner account, so they reflect what the reader's
  actual grants allow — not what the operator can do.

## Correction to gcp-test-environment-setup.md found while executing Phase 2

`roles/resourcemanager.projectViewer`, named in Phase 2 as one of the four
candidate baseline roles, **does not exist**:

```
$ gcloud projects add-iam-policy-binding authsec-gcp-test \
    --member=serviceAccount:authsec-reader-spike@... \
    --role=roles/resourcemanager.projectViewer
ERROR: (gcloud.projects.add-iam-policy-binding) INVALID_ARGUMENT: Role
roles/resourcemanager.projectViewer is not supported for this resource.

$ gcloud iam roles describe roles/resourcemanager.projectViewer
ERROR: (gcloud.iam.roles.describe) Roles instance
[resourcemanager.projectViewer] not found
```

There is no project-level equivalent of `roles/resourcemanager.folderViewer`
/ `roles/resourcemanager.organizationViewer`. The correct role for
`projects.get`/`.list`, `folders.get`/`.list` and `organizations.get` in one
grant is **`roles/browser`**:

```
$ gcloud iam roles describe roles/browser --format="yaml(includedPermissions)"
includedPermissions:
- resourcemanager.folders.get
- resourcemanager.folders.list
- resourcemanager.organizations.get
- resourcemanager.projects.get
- resourcemanager.projects.getIamPolicy
- resourcemanager.projects.list
```

Live-tested and confirmed below (question a). **This is a documentation fix
gcp-test-environment-setup.md and the plan's role-set language both need**;
it is not a schema or design decision, just a wrong role name.

## Question (a) — Can the reader identity hold every permission in plan §5's API matrix?

**Yes**, with the role-name correction above. Every call below was made as
the reader identity via impersonation.

| Plan §5 surface | API call | Role granted | Result |
|---|---|---|---|
| IAM service accounts | `iam.serviceAccounts.list` | `roles/iam.serviceAccountViewer` (project) | Succeeded — returned 4 SAs in the project |
| IAM service accounts | `iam.serviceAccounts.get` | `roles/iam.serviceAccountViewer` (project) | Succeeded — returned own SA's email/uniqueId |
| Service-account keys | `serviceAccounts.keys.list` (filtered `USER_MANAGED`) | `roles/iam.serviceAccountViewer` (project) | Succeeded — `Listed 0 items` (see note below on why 0, not an error) |
| Service-account keys | `serviceAccounts.keys.list` (unfiltered) | `roles/iam.serviceAccountViewer` (project) | Succeeded — returned 2 `SYSTEM_MANAGED` keys, confirming the API and the managed-by filter both work as documented |
| IAM allow policies | `cloudasset.searchAllIamPolicies` | `roles/cloudasset.viewer` (project) | Succeeded — see question (b)/(c) for the actual payload |
| Roles | `iam.roles.get` (predefined) | `roles/iam.roleViewer` (project) | Succeeded — `roles/storage.objectViewer` |
| Roles | `iam.roles.get` (custom) | `roles/iam.roleViewer` (project) | Succeeded — `authsec_test_reader` with its 3 `includedPermissions` |
| Scope hierarchy | `organizations.get` | `roles/browser` (org) | Succeeded — `organizations/695908590846` |
| Scope hierarchy | `folders.list`/`.get` | `roles/browser` (**org**, not project — see below) | Succeeded — `Listed 0 items` (no folder exists in this org; the call itself is what's being verified, not the count) |
| Scope hierarchy | `projects.get` | `roles/browser` (project) | Succeeded — returned `authsec-gcp-test`, parent type `organization`, parent id `695908590846` |

**Important scoping finding, not obvious from the plan/doc:** `roles/browser`
bound only at the **project** grants `projects.get` for that project but
**not** `folders.list`/`organizations.get` — those require the role (or an
equivalent) bound at the **folder or org** level, because GCP IAM grants
apply to the bound resource and its descendants, never its ancestors.
`folders.list` against the org failed with `PERMISSION_DENIED` until
`roles/browser` was also bound at the org. **Recommendation:** the real
`setup-reader.sh` must bind the hierarchy-read role (`roles/browser`) at
whichever scope the customer picks as `scope_kind` (org, folder, or
project) — binding it only at the project (as Phase 2's example does) is
insufficient for a customer who onboards at org or folder scope and expects
`organizations.get`/`folders.list` to work.

`roles/resourcemanager.organizationViewer` was also live-tested (before the
`browser` correction) and confirmed to include **only**
`resourcemanager.organizations.get` — it does not cover folders at all, so
it is redundant with (a strict subset of) `roles/browser` bound at org scope
and should be dropped from the final role list rather than stacked with it.

**Key-metadata fixture caveat (real finding, not a gap in effort):** creating
an actual `USER_MANAGED` key for the `test-sa-with-key` fixture SA failed:

```
$ gcloud iam service-accounts keys create key1.json --iam-account=test-sa-with-key@...
ERROR: FAILED_PRECONDITION: Key creation is not allowed on this service account.
  violations: constraints/iam.disableServiceAccountKeyCreation
```

This org policy constraint is enforced by default on this org (a Google
default for newer orgs) and blocked creating the fixture. This is directly
relevant to GCP-D9/GCP-03: **the JSON-key fallback onboarding path will not
work at all for a customer org that enforces
`constraints/iam.disableServiceAccountKeyCreation`** (a real, non-exotic
default) — reinforcing that WIF must be the primary path and the JSON-key
path's error handling must have a clean, specific `key_invalid`/
`permission_denied`-class response for this exact failure mode, not a
generic one. `keys.list` itself was still verified against the SA's existing
`SYSTEM_MANAGED` keys (see table above), confirming the API/role/filter are
correct even without a `USER_MANAGED` fixture.

## Question (b) — Does searchAllIamPolicies return federated principals, and in what string form?

**Yes.** Fixture: a `roles/storage.objectViewer` binding on the project with
member `principalSet://iam.googleapis.com/projects/438408545566/locations/global/workloadIdentityPools/authsec-spike-pool/attribute.subject/test-external-agent`,
alongside an ordinary `serviceAccount:` member on the same role.
`cloudasset.searchAllIamPolicies` (called as the reader) returned it
**verbatim, unmodified, in the same `members` array as the ordinary
service-account member**, on the same binding:

```json
{
  "members": [
    "principalSet://iam.googleapis.com/projects/438408545566/locations/global/workloadIdentityPools/authsec-spike-pool/attribute.subject/test-external-agent",
    "serviceAccount:test-sa-with-key@authsec-gcp-test.iam.gserviceaccount.com"
  ],
  "role": "roles/storage.objectViewer"
}
```

Conclusion for the connector: a `cloud_permission`/`cloud_assume_edge` writer
must not assume every CAI `members[]` entry has a `serviceAccount:`/`user:`
prefix — `principalSet://` (and, per Google's IAM member-string reference,
`principal://` for a single scoped subject) are real, live member kinds CAI
returns unparsed. The full string (including the pool/provider path and the
`attribute.subject/<value>` or `subject/<value>` suffix) is exactly what the
common schema's `cloud_assume_edge.subject` "stored verbatim" design already
anticipates — no parsing needed, just don't drop or choke on the `://` form.

## Question (c) — How are IAM Conditions represented in CAI output?

Fixture: a `roles/secretmanager.viewer` binding with condition expression
`resource.name.startsWith("projects/authsec-gcp-test/secrets/test-secret")`,
title `only-test-secret`. `searchAllIamPolicies` (as the reader) returned:

```json
{
  "condition": {
    "expression": "resource.name.startsWith(\"projects/authsec-gcp-test/secrets/test-secret\")",
    "title": "only-test-secret"
  },
  "members": ["serviceAccount:test-sa-google-managed@authsec-gcp-test.iam.gserviceaccount.com"],
  "role": "roles/secretmanager.viewer"
}
```

The condition is a **third top-level key on the binding object**, a peer of
`members` and `role` — not folded into either, and there is no `effect` key
anywhere in a `searchAllIamPolicies` binding (every binding CAI returns this
way is implicitly an allow; deny is a structurally separate object, which is
exactly what the plan's §10/GCP-D5 gap already states — this spike confirms
it structurally rather than just documenting it as absent).

**They do not fit cleanly into `cloud_permission` as currently landed.**
`cloud_permission` (migration 013) has `role_name`, `actions[]`, `effect`,
`scope_kind`, `derivation`, `sensitivity` — no column for a condition
expression or title, and per this ticket's own instruction, inventing one is
schema-owner territory, not GCP-01's. Also worth flagging alongside
GCP-D11 (`cloud_permission` has no `attrs` column for rule/note text): the
same missing-column problem applies to IAM Conditions, which is a second,
independent reason `cloud_permission.attrs jsonb` is worth having — not
raised here as a new decision, just recorded as a second data point for
whoever resolves GCP-D11. **Recommendation for now (M1): if a binding has a
condition, either drop it from the M1 write (record only unconditional
grants) or note its presence via a boolean/rule-fired note once GCP-D11
lands an attrs column — do not silently write the binding as unconditionally
granted, since that overstates what the identity can actually reach.**

## Question (d) — Can the reader see GKE Workload Identity annotations at all?

**UNVERIFIED — BILLING REQUIRED.** No GKE cluster exists or could be created:

```
$ gcloud services enable container.googleapis.com --project=authsec-gcp-test
ERROR: FAILED_PRECONDITION: Billing account for project '438408545566' is not
found. Billing must be enabled for activation of service(s)
'container.googleapis.com,...'
```

The only billing account on this identity is closed
(`gcloud billing accounts list` → `OPEN=False`), so this is not a
credential/permission gap — no available identity can enable the GKE API on
any project reachable here. **What would resolve this:** an open billing
account attached to a test project (any small budget), then Phase 4's
`gcloud container clusters create ... --workload-pool=...` +
`kubectl annotate serviceaccount ... iam.gke.io/gcp-service-account=...`,
then a `container.googleapis.com` read call (e.g.
`google.container.v1.ClusterManager.GetCluster` or reading the KSA's
annotation via the Kubernetes API) as the reader identity. This is an M2
dependency per the plan (§4, GKE Workload Identity join), so it does not
block M1/GCP-02..05, but it should be re-run before M2 discovery code is
written.

## Question (e) — WIF mechanism spike (arbitrary external OIDC issuer → STS → impersonation)

Per this file's instructions and `prompt.md`'s GCP-D9 design: created the
pool/provider and impersonation binding exactly as specified, with the
**scoped `principal://.../subject/<value>` binding, not the wildcard
`principalSet://.../*`** that `gcp-test-environment-setup.md` Phase 2 uses
for its own disposable rig (that wildcard is explicitly flagged in this
ledger as unfit for the production script, per the correction the task
description itself calls out).

**Live AuthSec issuer reachability check (done first, per the task's own
branching instruction):** the only AuthSec OIDC issuer available in this
environment is the local dev config, `BASE_URL=http://localhost:7001`
(`authsec/.env`) — not reachable from Google's STS infrastructure, which
must fetch `<issuer>/.well-known/openid-configuration` and its JWKS over the
public internet to verify a token's signature. `.env.example` documents a
real production-shaped issuer (`OAUTH_ISSUER_URL=https://api.authsec.dev`),
but this spike has no credentials to authenticate against that deployment
and mint a real token there, and probing a real customer-facing domain's
endpoints is out of scope for a disposable spike without separate
authorization. **Per the task's own instructions, this is exactly the "no
reachable AuthSec deployment" branch** — so the live-issuer round trip is
marked UNVERIFIED — LIVE ISSUER REQUIRED below, and the mechanism was
instead spiked with a self-signed token against a synthetic issuer, which is
what the instructions call for in that branch ("record the exact STS
request/response either way").

**Setup (real, live GCP calls):**

```
$ gcloud iam workload-identity-pools create authsec-spike-pool --location=global --project=authsec-gcp-test
Created workload identity pool [authsec-spike-pool].

$ gcloud iam workload-identity-pools providers create-oidc authsec-spike-provider \
    --location=global --workload-identity-pool=authsec-spike-pool \
    --issuer-uri="https://authsec-wif-spike-test.invalid" \
    --attribute-mapping="google.subject=assertion.sub" \
    --project=authsec-gcp-test
Created workload identity pool provider [authsec-spike-provider].
```

**Finding: GCP does not validate issuer reachability at provider-creation
time.** `https://authsec-wif-spike-test.invalid` is a non-resolving,
deliberately synthetic domain, and provider creation still succeeded
immediately — confirming the first half of question (e): **yes, an
arbitrary, non-Google-recognized external OIDC issuer can be configured**,
with no live validation until an actual token exchange is attempted.

**Scoped impersonation binding (never wildcard):**

```
$ gcloud iam service-accounts add-iam-policy-binding authsec-reader-spike@authsec-gcp-test.iam.gserviceaccount.com \
    --member="principal://iam.googleapis.com/projects/438408545566/locations/global/workloadIdentityPools/authsec-spike-pool/subject/wif-spike-test-subject-001" \
    --role=roles/iam.workloadIdentityUser
Updated IAM policy ... (single scoped principal, not principalSet://.../*)
```

**STS exchange attempt with a self-signed RS256 JWT** (generated locally with
Node's `crypto` module — 2048-bit RSA keypair never written to disk, `iss`
set to the synthetic issuer, `sub` set to the exact bound subject
`wif-spike-test-subject-001`, `aud` set to the provider's resource path):

```
$ curl -s -X POST https://sts.googleapis.com/v1/token -H "Content-Type: application/json" -d '{
    "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
    "audience": "//iam.googleapis.com/projects/438408545566/locations/global/workloadIdentityPools/authsec-spike-pool/providers/authsec-spike-provider",
    "scope": "https://www.googleapis.com/auth/cloud-platform",
    "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
    "subjectToken": "<self-signed RS256 JWT>",
    "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt"
  }'

{"error":"invalid_grant","error_description":"Error connecting to the given credential's issuer."}
```

**Conclusion:** the request reached Google's STS, was accepted as
well-formed (correct grant type, correct `//iam.googleapis.com/...`
audience format, correct subject-token-type), and STS attempted to fetch the
issuer's OIDC discovery/JWKS document to verify the JWT — and failed
**exactly and only** because `authsec-wif-spike-test.invalid` does not
resolve. This is precisely the reachability dependency the GCP-D9 design
relies on, and it is a real, externally-verified data point that the
mechanism (arbitrary external issuer → pool/provider → scoped principal
binding → STS token-exchange call) works up to and including the point where
it needs a real, publicly-reachable issuer — which is exactly what
`config.AppConfig.OAuthBaseURL()` already provides in every non-local
AuthSec deployment (per `prompt.md`'s existing FACT that
`/.well-known/openid-configuration` and `/oauth/jwks` are already served
publicly and unauthenticated). **The full success path (valid signature
verification → subject-mapped principal → actual service-account
impersonation → usable access token) remains UNVERIFIED — LIVE ISSUER
REQUIRED.** What would resolve it: run the identical `create-oidc` +
`add-iam-policy-binding` + STS-exchange sequence above with `--issuer-uri`
pointed at a real, internet-reachable AuthSec deployment (dev or staging),
using a token minted by that deployment's actual `NativeIssuer` (once
GCP-03's `IssueCloudOnboardingToken` exists) or any existing AuthSec-issued
token whose `sub` claim is known in advance.

## STEP 4 — CAI quota-project behavior

Tested three ways, all live, all as the reader identity:

1. **No `--billing-project` flag at all**, `gcloud config core/project` set
   to `authsec-gcp-test`: succeeded, returned real data (see questions
   b/c). The call defaulted to the reader's own configured project as the
   quota project.
2. **`--billing-project=authsec-gcp-test`** (the reader's own home
   project, explicit): succeeded identically. Notably, none of the reader's
   granted roles (`browser`, `cloudasset.viewer`, `iam.roleViewer`,
   `iam.serviceAccountViewer`) include `serviceusage.services.use` in their
   `includedPermissions` (checked directly via `gcloud iam roles describe`)
   — yet quota-project use of the reader's **own** project succeeded anyway,
   meaning Google does not require an explicit `serviceusage.services.use`
   grant for a principal to use its own home project as its CAI quota
   project.
3. **`--billing-project=project-83765d3e-2819-4177-8ea`** (a real project
   the reader has zero grants on): failed cleanly —
   ```
   ERROR: [authsec-reader-spike@...] does not have permission to access
   projects instance [authsec-gcp-test:searchAllIamPolicies]: Caller does
   not have required permission to use project
   project-83765d3e-2819-4177-8ea. Grant the caller the
   roles/serviceusage.serviceUsageConsumer role, or a custom role with the
   serviceusage.services.use permission ...
   reason: USER_PROJECT_DENIED
   ```

**Conclusion:** CAI bills against whatever project is supplied as the quota
project (explicitly via `--billing-project` / the `X-Goog-User-Project`
header, or implicitly the caller's own configured project if omitted). A
principal may always use **its own home project** as quota project with no
extra grant; using **any other** project as quota project requires
`roles/serviceusage.serviceUsageConsumer` (or equivalent) on that other
project specifically. **For the real connector: the reader SA's own home
project (`reader_project_id`, already a first-class onboarding field per
GCP-D9) is the correct, zero-extra-permission default quota project for
every CAI call** — there is no need to grant the reader
`serviceusage.serviceUsageConsumer` anywhere as long as CAI calls are always
billed to `reader_project_id`.

## STEP 5 — SDK / client library confirmation

**REST/gRPC surface, confirmed via `go build` against real, currently
published module versions** (throwaway module at `authsec/docs/gcp/spike/`,
its own `go.mod`, not touching the main module):

- `google.golang.org/api` — resolved to **v0.296.0** (latest as of this
  spike). `iam/v1`, `cloudasset/v1`, `cloudresourcemanager/v3` packages all
  import and build cleanly under Go **1.26.5** (the toolchain available
  here; the main repo's `go.mod` pins `go 1.25.0` — both are compatible,
  `google.golang.org/api` v0.296.0 has no floor above 1.25).
- Each generated client (`iam.NewService`, etc.) takes
  `...option.ClientOption`, confirmed via `go doc`.

**External-account / WIF programmatic subject-token supplier — the API
GCP-03 actually needs.** Both candidate libraries were inspected directly
with `go doc` against the real downloaded source (not from memory):

**Recommended: `cloud.google.com/go/auth/credentials/externalaccount`**
(module `cloud.google.com/go/auth`, resolved to **v0.23.2**) — the current,
actively-developed library, and the one `google.golang.org/api` v0.296.0's
`option.WithAuthCredentials(*auth.Credentials)` is built to consume directly:

```go
type SubjectTokenProvider interface {
    // SubjectToken should return a valid subject token or an error.
    // The external account token provider does not cache the returned
    // subject token, so caching logic should be implemented in the
    // provider to prevent multiple requests for the same subject token.
    SubjectToken(ctx context.Context, opts *RequestOptions) (string, error)
}

type Options struct {
    Audience                        string // "//iam.googleapis.com/projects/<NUM>/locations/global/workloadIdentityPools/<pool>/providers/<provider>"
    SubjectTokenType                string // "urn:ietf:params:oauth:token-type:jwt"
    SubjectTokenProvider            SubjectTokenProvider // <- the programmatic supplier hook GCP-03 implements
    ServiceAccountImpersonationURL  string // REQUIRED for WIF SA impersonation — see note below
    QuotaProjectID                  string
    Scopes                          []string
    // ...
}

func NewCredentials(opts *Options) (*auth.Credentials, error)
```

`google.golang.org/api/option.WithAuthCredentials(creds *auth.Credentials) ClientOption`
takes the `*auth.Credentials` this returns directly — confirmed present in
the resolved v0.296.0 via `go doc`.

**Impersonation nuance GCP-03 must not miss:** `Options.Audience` alone
authenticates the *external identity*, not the target service account.
`ServiceAccountImpersonationURL` must also be set — per the library's own
doc comment, to
`https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<reader_sa_email>:generateAccessToken`
— or the resulting credential will represent the federated external
principal itself, not the impersonated reader SA. This matches
`prompt.md`'s design ("impersonating the reader SA email the customer pasted
back") but the exact field that makes impersonation actually happen was not
spelled out there, and is the one part of GCP-03 most likely to silently
produce the wrong (unimpersonated) credential if skipped.

**Audience string format, confirmed live (not just from docs):** the STS
`audience` field format `//iam.googleapis.com/projects/<NUM>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`
(double-slash prefix, no `https://`) was used verbatim in the question-(e)
`curl` call above and was accepted by `sts.googleapis.com` as well-formed
(the request proceeded to the issuer-connectivity stage rather than
rejecting the audience format itself) — this is the same string
`externalaccount.Options.Audience` expects.

**Alternative (older, still current) library, inspected for completeness:**
`golang.org/x/oauth2/google/externalaccount` (module `golang.org/x/oauth2`,
resolved to **v0.36.0**) exposes the same shape one layer down —
`SubjectTokenSupplier` interface (`SubjectToken(ctx, SupplierOptions) (string, error)`)
on a `Config` struct paired with `option.WithTokenSource`. Functionally
equivalent; **not recommended as the primary path** because
`cloud.google.com/go/auth` is Google's actively-promoted direction for new
code and integrates one step more directly with the already-latest
`google.golang.org/api` client constructors used here. Recording both is
deliberate: if `cloud.google.com/go/auth` version drift ever breaks GCP-03's
build, `golang.org/x/oauth2/google/externalaccount` is a same-shape fallback
without a design change.

**JSON-key path confirmation:** `option.WithCredentialsJSON([]byte) ClientOption`
is present and unchanged in the same `google.golang.org/api/option` package
— no new library needed for the fallback path.

**Exact versions to pin in the main module's `go.mod` when GCP-03 adds the
dependency** (resolved by `go get ...@latest` against the real module proxy
on the date of this spike):

```
google.golang.org/api v0.296.0
cloud.google.com/go/auth v0.23.2
golang.org/x/oauth2 v0.36.0   (already indirectly present at v0.34.0 in the main repo's go.sum — this bumps it)
```

## Final candidate reader role list (replaces gcp-test-environment-setup.md Phase 2's four-role list)

| Role | Scope | Justifies |
|---|---|---|
| `roles/iam.serviceAccountViewer` | project (bind at `scope_kind`) | `iam.serviceAccounts.list`/`.get`, `serviceAccounts.keys.list` |
| `roles/iam.roleViewer` | project (bind at `scope_kind`) | `iam.roles.get` (predefined + custom) |
| `roles/cloudasset.viewer` | project (bind at `scope_kind`) | `cloudasset.searchAllIamPolicies` |
| `roles/browser` | **bind at whatever scope_kind the customer picks (org, folder, or project)** — not project-only | `organizations.get`, `folders.get`/`.list`, `projects.get`/`.list` |

**Changes from the candidate baseline in gcp-test-environment-setup.md:**
- Drop `roles/resourcemanager.projectViewer` — **does not exist** (see
  correction above).
- Drop `roles/viewer` (folder/org bindings in Phase 2 use the broad
  `roles/viewer`, which is far wider than plan §5 needs) and
  `roles/resourcemanager.organizationViewer` (subset of `browser`) —
  replace both with `roles/browser` bound at the actual `scope_kind`.
- No write permission anywhere in this list — confirmed by reading every
  role's `includedPermissions` directly (see question (a)).

Folder-level `browser` was not live-tested against a real folder (none
exists in this org — see Test environment used); its permission set is
confirmed by direct role-definition inspection (`folders.get`/`.list` are
in `roles/browser`'s `includedPermissions`) and by the successful org-level
`folders.list` call above, which exercises the same permission the folder
binding would use one level down.

## Production `setup-reader.sh` note

Confirmed and recorded per this ticket's own instruction: the **impersonation
binding** in the real customer-facing script must use the scoped
`principal://iam.googleapis.com/projects/<NUM>/locations/global/workloadIdentityPools/<pool_id>/subject/<wif_subject>`
form — exactly as GCP-D9's design in `prompt.md` already specifies — **never**
the wildcard `principalSet://.../*` that `gcp-test-environment-setup.md`
Phase 2 shows for its own disposable rig. This spike used the scoped form
throughout (see question (e)) and confirms it works identically to the
wildcard form for the one-subject case a real onboarding needs. The
`principalSet://...` form remains correct and unchanged for the *separate*
question-(b) fixture, which is deliberately testing a federated **resource
binding** (a grant a workload can use), not the WIF **impersonation**
binding — the two are different bindings on different resources and the
scoping correction applies only to the latter.

## Resources created by this spike (for cleanup)

- SA `authsec-reader-spike@authsec-gcp-test.iam.gserviceaccount.com` +
  project/org IAM policy bindings for it (`browser`, `cloudasset.viewer`,
  `iam.roleViewer`, `iam.serviceAccountViewer` at project;
  `resourcemanager.organizationViewer`, `browser` at org) + a self-granted
  `iam.serviceAccountTokenCreator` binding (operator → SA, testing-only, not
  part of the candidate role list).
- WIF pool `authsec-spike-pool` / provider `authsec-spike-provider` (issuer
  `https://authsec-wif-spike-test.invalid`) + the scoped
  `roles/iam.workloadIdentityUser` binding on the reader SA.
- M1 test fixtures matching gcp-test-environment-setup.md Phase 3, left in
  place for reuse by GCP-02+ (not spike-disposable — these are the
  documented persistent test data): `test-sa-with-key`,
  `test-sa-google-managed`, custom role `authsec_test_reader`, and the
  various project-level bindings (storage.objectViewer, custom-role,
  compute.viewer, the conditional secretmanager.viewer binding, the
  federated-principal storage.objectViewer binding).
- No SA keys were ever created (blocked by org policy — see question a) —
  there is no key material to delete.
- `authsec/docs/gcp/spike/` — throwaway Go module (own `go.mod`/`go.sum`,
  not referenced by or added to the main module's `go.mod`). Flagged per
  this ticket's validation checklist; left in place since it has value as a
  reference for GCP-03 unless the reviewer prefers it deleted.

**No cleanup was performed without explicit confirmation** — deleting IAM
bindings and the disposable SA/pool is a real, if reversible (30-day SA soft
delete), action on a live GCP identity, and this ledger's job is the
evidence, not the teardown. Flagging exactly what exists above so the
teardown (or a decision to keep it for GCP-02/03/04's own testing) is a
separate, explicit step.

## Summary of acceptance criteria

- All five blocking questions answered against a real scope, with evidence
  (call, response, error) recorded: **yes**, four fully live-verified,
  question (d) UNVERIFIED (billing), question (e) live-verified up to and
  including the issuer-connectivity boundary with the full success path
  UNVERIFIED (no reachable issuer available).
- Final reader role set published, every permission mapped to a named plan
  §5 API call, no write permission anywhere: **yes**, see table above.
- CAI quota-project behavior documented with a working example: **yes**,
  three real calls (default, own-project explicit, foreign-project denied).
- SDK client choice fixed; pagination/retry behavior verified: SDK/library
  choice and exact versions fixed and confirmed to build; pagination/retry
  behavior for the M1 matrix's specific calls was not separately
  live-exercised in this spike (no data volume existed to page over) — the
  generated clients' standard `.Pages(ctx, callback)` iterator pattern is
  documented Google behavior for all three chosen packages and is expected
  to apply unchanged; flag for a quick confirmation once GCP-06 has real
  scan volume to page through.
