# Flow: Federation

> Three federation mechanisms: trusted issuers (external ID-JAG acceptance), workload
> identity providers (OIDC/CI federation for non-SPIRE workloads), and A2A brokering
> policies (cross-app permit/deny). Read `flows/xaa-idjag.md` first.

## 1. Trusted Issuers (external ID-JAG)

**What:** An external identity provider (another AS, a CI system, a partner IdP) mints
an ID-JAG that AuthSec accepts as a jwt-bearer assertion. The `sub` is resolved to a
local user via `oidc_user_identities`.

**Table:** `trusted_issuers`
```sql
iss          text UNIQUE NOT NULL     -- issuer URL that signed the ID-JAG
provider_name text                    -- slug used in JIT provisioning
jwks_uri      text                    -- where to fetch signing keys
status        text NOT NULL           -- 'active' | 'revoked'
allowed_algs  text[]                  -- RS256, ES256, etc.
clock_skew_secs int DEFAULT 30
jit_provisioning boolean DEFAULT false -- auto-create oidc_user_identities on first use
workspace_claim_mapping text          -- claim name that carries the issuance workspace
```

**Validation** (`XAAService.ValidateIDJAG`):
1. Parse `iss` from JWT header (no sig).
2. Look up `trusted_issuers` where `iss = ? AND status = 'active'`.
3. Fetch JWKS from `jwks_uri` (cached in-memory, 5-min TTL).
4. Verify signature, `aud=selfIssuer`, `client_id=authenticatedClient`, `exp`.
5. If `jit_provisioning=true`: look up `oidc_user_identities` by `(iss, sub)`; if not
   found, provision a local user identity atomically.

**CRUD:** `controllers/platform/trusted_issuers_controller.go` → `trusted_issuers` table.
Admin UI: `Authsec-ui/src/features/trusted-issuers/`.

## 2. Workload Identity Providers

**What:** OIDC-based identity for non-SPIRE workloads — GitHub Actions OIDC, GitLab CI,
Azure Managed Identity, AWS IRSA, or any OIDC provider issuing short-lived tokens.

**Table:** `workload_identity_providers`
```sql
workspace_id uuid NOT NULL
name         text
issuer_url   text           -- OIDC issuer URL (for OIDC discovery)
jwks_uri     text           -- explicit JWKS (overrides discovery)
subject_claim text DEFAULT 'sub'
audience     text[]
external_subject_template text  -- claim mapping template
status        text NOT NULL      -- 'active' | 'revoked'
```

**Flow:** The CI/cloud platform tokens are validated at `POST /oauth/token` using the
same `AuthenticateClient` SPIFFE branch or a dedicated `workload-identity-providers`
dispatch. Subject mapping resolves the external `sub` to a local service account.

**CRUD:** `controllers/platform/workload_identity_providers_controller.go`.

## 3. A2A Brokering Policies

**What:** A workspace admin can define which agent client identities (by SPIFFE ID or
`client_id`) are permitted or denied access to which resource servers, independent of
standard RBAC role bindings. An extra permit/deny layer for cross-app agent governance.

**Tables:** `a2a_brokering_policies`, `delegation_policies`

```sql
-- a2a_brokering_policies
workspace_id uuid
name         text
client_selector jsonb    -- matcher: {type: 'spiffe_id'|'client_id', value: '...'}
resource_selector jsonb  -- matcher: {type: 'resource_uri', value: '...'}
effect       text NOT NULL CHECK (effect IN ('allow', 'deny'))
```

**Evaluation:** Called inside `tokenExchangeGrant` / `tokenJWTBearerGrant` before
scope resolution. A `deny` policy blocks token issuance with `access_denied`.

**CRUD:** `controllers/platform/a2a_brokering_controller.go`.

## When you're building

- **New trusted issuer?** `POST /workspaces/:wsid/trusted-issuers` — inserts the row.
  No restart needed; `ValidateIDJAG` does a live DB lookup on every jwt-bearer attempt.
- **Debugging "untrusted_issuer"?** Check `trusted_issuers.status='active'` and that
  `iss` in the JWT exactly matches `trusted_issuers.iss`.
- **Debugging JIT provisioning?** Check `oidc_user_identities` for the (iss, sub) pair.
  `jit_provisioning=true` is required on the `trusted_issuers` row.
- **New brokering policy?** `POST /workspaces/:wsid/a2a-brokering-policies`.

## Related

`flows/xaa-idjag.md` (where trusted issuers are consumed), `primitives/spire.md`
(SPIFFE workload identity), `primitives/identity-principals.md`.
