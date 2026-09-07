# GCP cloud discovery — onboarding and the workload identity foundation

How AuthSec connects to a customer's Google Cloud scope, what that connection is
allowed to do, where credentials live, and what is stored.

Two onboarding paths reach the same end state — one `cloud_connector` row that
everything else resolves against:

1. **Google Authentication** — a one-time Google sign-in that AuthSec spends
   immediately to configure Workload Identity Federation on the customer's
   behalf, then discards.
2. **Manual Workload Identity Federation** — the customer runs a setup script in
   their own project and pastes back one value.

Both end with a connector authenticated by **Workload Identity Federation**:
AuthSec holds no long-lived Google credential, and neither path stores key
material. (A legacy JSON-key path still exists for connectors created before
these — see below.)

> **Discovery is not implemented yet.** Onboarding establishes and proves the
> connection. Enumerating service accounts, IAM bindings, keys and resources is
> later work. See [Implementation status](#implementation-status) — nothing in
> this document describes discovery as working today.

**Scope:** this document covers GCP only. AWS onboarding and discovery are a
separate implementation with their own flow, and nothing here describes them.

Related: `aws-cloud-discovery-onboarding.md` for the AWS equivalent;
`connectors.md` for why discovery does not sit on the connector broker.

---

## The flow

```mermaid
flowchart LR
    subgraph B["Console"]
        W["GCP onboarding wizard"]
    end
    subgraph A["AuthSec"]
        C1["CloudGCPOAuthController"]
        C2["CloudGCPController"]
        S1["GCPOAuthProvisionService"]
        S2["GCPOnboardingService"]
        S3["GCPAuthService"]
    end
    subgraph G["Customer's Google Cloud"]
        OA["Google OAuth"]
        STS["Security Token Service"]
        IAM["IAM · Resource Manager<br/>Service Usage · IAM Credentials"]
    end
    subgraph D["AuthSec state"]
        R[("Redis<br/>short-lived OAuth state")]
        V[("Vault<br/>legacy JSON key only")]
        P[("PostgreSQL<br/>cloud_connector")]
    end

    W -->|Google Authentication| C1 --> S1
    W -->|Manual WIF| C2 --> S2
    S1 --> OA
    S1 --> IAM
    S1 --> S2
    S2 --> S3 --> STS --> IAM
    S1 <--> R
    S3 <--> V
    S2 --> P
```

A connector is one row per **scope** — a project, folder or organization. The
scope is what AuthSec is permitted to read; the **reader project** is where the
service account and federation resources live. They are usually the same
project.

---

## Path 1 — Google Authentication

The operator signs in with Google once. AuthSec uses that short-lived
authorization to create the federation resources, then throws it away. Nothing
about the operator's Google account is retained.

```mermaid
sequenceDiagram
    autonumber
    participant O as Operator
    participant UI as Console
    participant A as AuthSec
    participant R as Redis
    participant G as Google

    O->>UI: Choose Google Authentication
    UI->>A: Start sign-in
    A->>R: Store CSRF state + PKCE verifier (10 min)
    A-->>UI: Google consent URL
    UI->>G: Popup — operator consents
    G->>A: Redirect with authorization code
    A->>R: Consume state (single use)
    A->>G: Exchange code for an access token
    Note over A,G: access_type=online —<br/>no refresh token is issued
    A->>R: Store access token under an opaque session id (15 min)
    A-->>UI: Opaque session id (never the token)

    UI->>A: List projects
    A->>G: Search accessible projects
    UI->>A: Preflight the chosen scope
    A->>G: testIamPermissions
    alt Permissions missing
        A-->>UI: Which permissions are missing — nothing created
    else Sufficient
        UI->>A: Connect
        A->>G: Provision federation (see below)
        A->>A: Create connector, verify, discard the session
    end
```

The consent screen requests a deliberately narrow scope set — enough to create a
service account, a workload identity pool and provider, and to set IAM policy on
the chosen scope. Full `cloud-platform` access is **not** requested.

Preflight runs before anything is created, so a customer whose account lacks the
necessary permissions is told exactly which ones are missing without any partial
setup being left behind.

### Automatic federation provisioning

```mermaid
flowchart TD
    P0([Preflight passed]) --> P1["Enable required APIs<br/>IAM · IAM Credentials · Resource Manager<br/>STS · Cloud Asset Inventory"]
    P1 --> P2["Create the reader service account<br/>authsec-reader@PROJECT"]
    P2 --> P3["Derive federation identifiers<br/>deterministic per workspace + scope"]
    P3 --> P4["Create the workload identity pool"]
    P4 --> P5["Create the OIDC provider<br/>issuer = AuthSec's sign-in service"]
    P5 --> P6["Look up the project number"]
    P6 --> P7["Grant workloadIdentityUser<br/>to ONE federated subject"]
    P7 --> P8["Grant reader roles at the scope"]
    P8 --> P9["Create the connector and verify it"]
```

Every step is idempotent: each checks for the resource before creating it,
restores a soft-deleted pool or provider rather than recreating it, and repairs a
provider whose issuer has drifted by patching it in place. Re-running a failed
connection is safe and creates nothing twice.

The `workloadIdentityUser` grant names **one specific federated subject** — never
a wildcard over the whole pool. Only AuthSec's own signed assertion for that
workspace and scope can impersonate the reader service account.

Immediately after the resources exist, Google needs a short time to apply the new
IAM binding. AuthSec polls for this rather than failing on the first attempt, so
a first-time connection can take up to about a minute and a half.

---

## Path 2 — Manual Workload Identity Federation

For customers whose policy or permissions do not allow AuthSec to configure their
project directly.

```mermaid
sequenceDiagram
    autonumber
    participant O as Operator
    participant UI as Console
    participant A as AuthSec
    participant G as Google Cloud

    O->>UI: Choose Workload Identity Federation
    O->>UI: Enter scope and reader project
    UI->>A: Request the onboarding package
    A-->>UI: Setup script + the exact pool, provider and<br/>subject identifiers AuthSec will expect
    O->>G: Run the script (Cloud Shell or a local terminal)
    G-->>O: Prints the provider resource name
    O->>UI: Paste the provider resource
    UI->>A: Create connector
    A->>A: Cross-check the pasted value against<br/>what it derives — before any network call
    A->>G: Prove the connection, confirm the scope is readable
    A-->>UI: Connector created
```

The identifiers are **derived deterministically** from the workspace and scope,
so AuthSec knows what they must be before the customer runs anything. A pasted
value from the wrong project or a stale run is rejected locally, with no wasted
round trip to Google.

The script grants the same reader roles and creates the same single-subject
binding as the automatic path. It never uploads anything to AuthSec.

### What the customer runs

The script enables the required APIs, creates the `authsec-reader` service
account, grants the reader roles at the chosen scope, creates the pool and OIDC
provider, and binds exactly one federated subject to the service account. It
prints the provider resource name to paste back.

The rendered script still carries a trailing legacy JSON-key section. The
console shows only the federation part of it, so a customer following the
wizard never runs those commands.

---

## How AuthSec authenticates afterwards

No Google credential is stored for a federated connector. Every call mints a
fresh, short-lived assertion:

```mermaid
sequenceDiagram
    autonumber
    participant A as AuthSec
    participant STS as Google STS
    participant IC as IAM Credentials
    participant API as Google Cloud APIs

    A->>A: Sign a short-lived JWT<br/>subject = the bound federated subject<br/>audience = the provider resource
    A->>STS: Exchange it for a federated token
    STS->>STS: Fetch AuthSec's public keys<br/>and verify the signature
    STS-->>A: Federated token
    A->>IC: Impersonate authsec-reader
    IC-->>A: Short-lived access token
    A->>API: Read-only calls
```

Two consequences worth stating plainly:

- **AuthSec's sign-in service must be reachable over HTTPS from Google.** Google
  fetches the OIDC metadata and public keys directly. A deployment that is not
  publicly reachable over HTTPS cannot use federation at all.
- **Revocation is the customer's.** Removing the binding, the pool or the service
  account in their project immediately and permanently cuts AuthSec's access.
  For a federated connector there is no AuthSec-held secret that could outlive
  it.

### Legacy JSON-key authentication

A service-account key path exists internally and is retained for compatibility,
but **it is not offered in the console**. Where it is used, only the Vault
*handle* is recorded against the connector — never the key itself.

Many organizations set `constraints/iam.disableServiceAccountKeyCreation`, which
blocks key creation outright. Federation is unaffected by that policy, which is
the main reason it is the only path offered for new connectors.

---

## Permissions

### Reader roles

Granted at the scope AuthSec reads:

| Role | Why |
|---|---|
| `roles/iam.serviceAccountViewer` | Enumerate service accounts — the candidate identities |
| `roles/iam.roleViewer` | Read role definitions, to expand a binding into the actions it permits |
| `roles/cloudasset.viewer` | Read IAM policy across the scope in one paginated call |
| `roles/browser` | Resolve the project, folder and organization hierarchy |

All four are read-only. AuthSec never requests write, delete or impersonation
permission on customer resources beyond the single binding that lets it act as
the reader service account it created.

> This set is still marked as a **candidate**: it is what onboarding grants
> today, and is expected to be confirmed or narrowed once discovery is
> implemented and its real permission needs are known.

### Permissions the operator needs to connect

Only for the Google Authentication path, and only during setup — to create the
pool and provider, create the service account, set IAM policy on it, enable the
required APIs, and set IAM policy at the chosen scope. Preflight checks these
before anything is created.

### Cloud Asset Inventory quota project

Cloud Asset Inventory bills each call against a quota project, and the caller
must hold `serviceusage.services.use` there. This is a per-call concern, not a
per-client one — the connector's own reader project is the appropriate quota
project. The value is recorded at onboarding for use when discovery is built.

---

## What AuthSec stores

```mermaid
flowchart LR
    subgraph EPH["Ephemeral · Redis"]
        E1["CSRF state + PKCE verifier<br/>10 minutes, single use"]
        E2["Google access token<br/>15 minutes, discarded on success"]
    end
    subgraph DUR["Durable · PostgreSQL"]
        D1["cloud_connector<br/>scope · status · verified_at<br/>federation resource name<br/>reader service account"]
    end
    subgraph VLT["Vault"]
        V1["Legacy JSON key<br/>handle only, not offered in the console"]
    end
    subgraph CUST["Customer's project"]
        G1["Reader service account"]
        G2["Pool · OIDC provider · IAM bindings"]
    end
    EPH -.discarded.-> X(("gone"))
    DUR --> CUST
```

| Stored | Where | Lifetime |
|---|---|---|
| CSRF state, PKCE verifier | Redis | 10 min, consumed once |
| Google access token | Redis | 15 min, deleted on successful connect |
| Scope, status, federation resource name, reader service account | PostgreSQL | Life of the connector |
| Legacy key handle | Vault | Only for the legacy path |

**Never stored anywhere:** the Google refresh token (none is ever issued — the
consent is online-only), the operator's Google password, or any service-account
private key from the federation paths.

The connector row records a federation **resource name**, which is a
non-sensitive Google identifier, not a credential.

---

## Connector lifecycle

```mermaid
stateDiagram-v2
    [*] --> Active: onboard
    Active --> Active: verify succeeds
    Active --> Error: verify fails
    Error --> Active: verify succeeds
    Active --> Revoked: revoke
    Error --> Revoked: revoke
    Revoked --> Active: re-onboard the same scope
    note right of Revoked
        Verify short-circuits — a revoked
        connector is never re-tested and
        never silently reactivated
    end note
```

**Verify** mints a fresh assertion, impersonates the reader service account and
confirms the scope is still readable. Success records the time; failure records
the reason without discarding the last known-good verification time.

**Reconnect** re-onboards the same scope and updates the row in place. Scan
state is preserved. A revoked connector returning this way becomes active again.

**Revoke** marks the row revoked and keeps it for audit. **AuthSec never deletes
anything in the customer's project** — the service account, pool and provider
remain until the customer removes them, which is the step that truly ends access.

---

## Errors say whose problem it is

Every failure is classified so the console can say who needs to act:

| Fault | Means |
|---|---|
| `customer_account` | Something in the customer's Google Cloud — missing permission, unreadable scope, federation not configured as expected |
| `gcp` | Google rejected the exchange or the request |
| `authsec` | An AuthSec-side deployment problem, such as a sign-in service Google cannot reach |

Error messages are sanitized — they never carry a token, a key, or an
authorization code.

---

## Implementation status

Stated plainly so nothing here is mistaken for a promise.

### Implemented

- Google Authentication onboarding, including automatic federation provisioning
- Manual Workload Identity Federation onboarding
- Federated authentication with service-account impersonation
- Connector create, verify, reconnect and revoke
- Preflight permission checks before anything is created
- One `cloud_connector` row per scope, with fault-classified errors

### Partially implemented

- **Scan coverage and generation tracking** — the columns exist and are
  initialised, but nothing advances them, because no scan exists.
- **Legacy JSON-key path** — functional internally, not offered in the console.

### Planned — not built

- Service-account discovery
- Service-account key metadata
- IAM binding and resource discovery, and role expansion
- Impersonation and federation edges
- Workload and agent signals
- Audit-log activity and usage aggregation

The shared discovery schema exists and is already written by other providers.
GCP discovery is not implemented, so **GCP writes only `cloud_connector`
today** — no `cloud_identity`, `cloud_permission`, `cloud_resource` or
`cloud_secret` row originates from GCP.

### Unverified

- Whether the candidate reader-role set is sufficient once discovery is built
- Organization- and folder-scoped onboarding end to end against a real
  organization
- Behaviour under organization policies that restrict federation or key creation

---

## Future discovery — planned shape

Not implemented. Shown only so the intended direction is clear; dashed elements
do not exist.

```mermaid
flowchart LR
    CC[("cloud_connector<br/>implemented")] --> CRED["Federated credential<br/>implemented"]
    CRED -.-> SA["Enumerate service accounts"]
    CRED -.-> CAI["Read IAM policy across the scope"]
    SA -.-> T1[("cloud_identity")]
    SA -.-> T2[("cloud_secret")]
    CAI -.-> T3[("cloud_permission")]
    CAI -.-> T4[("cloud_resource")]

    classDef planned fill:#f7f7f7,stroke:#999,stroke-dasharray:5 3
    class SA,CAI,T1,T2,T3,T4 planned
```

Provider differences belong in column **values**, not in new tables — GCP adds no
table of its own.
