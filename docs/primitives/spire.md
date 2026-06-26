# SPIFFE / SPIRE — Workload Identity

> Read this before touching anything related to SPIFFE SVIDs, workload entries,
> SPIRE policies, JWT-SVID federation, or the SPIRE OIDC discovery endpoint.
> Files: `controllers/platform/spire_controller.go`,
> `controllers/platform/{spiffe_delegate,delegation_policy}_controller.go`,
> `services/spiffe_key_service.go`, `internal/spire/`.

## What SPIRE provides

| Credential type | How issued | How validated |
|---|---|---|
| **X.509-SVID** | SPIRE agent attests the workload, issues a short-lived X.509 cert with SPIFFE URI SAN | mTLS: peer verifies certificate chain against SPIRE trust bundle |
| **JWT-SVID** | SPIRE agent mints a JWT signed by the SPIRE server's OIDC key | RS256 via SPIRE's JWKS endpoint (or AuthSec's federated JWKS union) |

A workload presents its **JWT-SVID** at `POST /oauth/token` as a `client_assertion`
(or via the SPIFFE delegate flow) to exchange it for a scoped native access token.

## Models (in `spire_controller.go`)

```go
type SpireWorkload struct {
    ID       uint   `gorm:"primaryKey"`
    SpiffeID string `gorm:"uniqueIndex"` // spiffe://trust-domain/workload-id
    Owner    string
}
// TableName: "spire_workloads"

type WorkloadEntry struct {
    ID          uuid.UUID
    WorkspaceID uuid.UUID        // workspace this entry belongs to
    SpiffeID    string           // spiffe://... URI
    ParentID    string           // SPIRE agent node entry
    Selectors   json.RawMessage  // k8s/unix/docker attestation selectors
    TTL         int              // default 3600
    Admin       bool
    Downstream  bool
    SpireEntryID *string         // Hydra-side entry ID after SPIRE registration
}
// TableName: "workload_entries"

type SpireOIDCToken struct {
    JWTID     string `gorm:"uniqueIndex"` // jti
    Subject   string                      // spiffe:// URI
    SPIFFEID  string
    TokenType string
    Audience  string
    Scope     string
    ExpiresAt time.Time
    Revoked   bool
}
// TableName: "spire_oidc_tokens"
```

## `services/spiffe_key_service.go` — `SpiffeKeyService`

Singleton RSA key pair used to sign RS256 JWT-SVIDs that SPIRE validates via AuthSec's
JWKS endpoint. Loaded at boot via `GetSpiffeKeyService()`.

Key environment variables:
- `SPIFFE_OIDC_ISSUER` — must match `OIDCIssuer` in the SPIRE server config (defaults to
  `https://user-flow.authsec.dev`).
- `SPIFFE_JWKS_KEY_ID` — stable `kid` so SPIRE JWKS cache works correctly (defaults to
  `"authsec-spiffe-key-1"`).
- `SPIFFE_RSA_PRIVATE_KEY` — PEM-encoded private key; if set, loaded at boot instead of
  generating a new key.

The SPIFFE key is published in the **JWKS union** at `/oauth/jwks` alongside native and
Hydra keys.

## SPIRE policy tables

The SPIRE policy engine (`spire_policies`, `spire_policy_rules`, `spire_policy_actions`,
`spire_policy_conditions`, `spire_policy_resources`, `spire_policy_subjects`) supports
fine-grained access control on SVID issuance. Managed via
`controllers/platform/spire_controller.go`.

SPIRE role bindings (`spire_role_bindings`) bind SPIFFE identities to roles within a
workspace for RBAC integration.

## Delegation policies

`controllers/platform/delegation_policy_controller.go` + `delegation_policies` table:
an A2A brokering overlay — which workload SPIFFE identities are permitted to delegate
to which resource servers. Read before touching cross-workload SPIFFE delegation.

## SPIFFE delegate controller

`controllers/platform/spiffe_delegate_controller.go`: handles the SPIFFE delegation
exchange — a workload presents its JWT-SVID and a target resource indicator; AuthSec
validates the SVID, checks delegation policies, and mints a native access token with
`act.spiffe_id` set to the presenter's SPIFFE ID.

## Single-node compose wiring

In `deploy/single-node`:
- SPIRE server + agent run from `docker-compose.spire.yml`.
- SPIRE's OIDC discovery provider URL must match `SPIFFE_OIDC_ISSUER`.
- Trust bundle federation: SPIRE publishes its own `jwks.json`; AuthSec pulls it for
  the JWKS union at `/oauth/jwks`.

## When you're building

- **Registering a new workload?** `POST /workspaces/:wsid/workload-entries` — creates
  the `workload_entries` row and syncs to SPIRE via the entry API.
- **JWT-SVID → access token exchange?** Entry point is `/oauth/token` with the SVID as
  `client_assertion`; see `flows/spiffe-workload.md` for the full path.
- **Adding a SPIRE OIDC field?** Edit `SpiffeKeyService` (key management) and the JWKS
  union builder in `oauth_as_controller.go` (`JWKS` handler).
- **SPIRE audit logs** are in `spire_audit_logs` (separate from `audit_events`); served
  by `SpireController`, not `LogsController`.
- **Never** use the SPIFFE key to sign native access tokens — it's a distinct key with
  its own `kid` (`authsec-spiffe-key-1`). Native tokens use `NativeKeyManager`.

## Related

`primitives/token-engine.md` (native key vs SPIFFE key, JWKS union), `flows/spiffe-workload.md`
(full SVID → access token flow), `primitives/identity-principals.md` (workload as a principal).
