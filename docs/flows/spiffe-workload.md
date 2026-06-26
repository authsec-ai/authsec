# Flow: SPIFFE Workload (JWT-SVID → access token)

> A k8s workload (pod) presents its SPIRE-issued JWT-SVID to get a scoped native
> access token. No long-lived secrets — the SVID is the credential.
> Read `primitives/spire.md` and `primitives/token-engine.md` first.

## Two onboarding modes (trust has two halves)

A workload authenticates only when BOTH halves are registered:

| Half | What | Where registered |
|---|---|---|
| **Issuer trust** | "I trust SVIDs signed by issuer X" | `workload_identity_providers` (kind=`spiffe`), or legacy `SPIFFE_OIDC_ISSUER` env |
| **Subject mapping** | "`spiffe://td/...` → this service account + role" | `service_accounts.spiffe_id` |

- **AuthSec-managed** — AuthSec runs SPIRE and **mints** the SPIFFE ID under its own
  trust domain. `POST /applications/:id/machine-access/workload` (`CreateWorkloadAccess`).
  The issuer is AuthSec's own SPIRE; no provider row needed.
- **Federated (bring-your-own SPIRE)** — the customer's own SPIRE issues the SVID under
  *their* trust domain. You register (1) the issuer as a `workload_identity_providers`
  row (kind=`spiffe`, with `trust_domain`), and (2) the **exact external SPIFFE ID** as a
  service account via `POST /applications/:id/access/federated-workload`
  (`CreateFederatedWorkloadAccess`). AuthSec never mints — it stores the external ID
  verbatim. `service_accounts.spiffe_match_type` = `exact` (the column is shaped for a
  future `prefix`/pattern mode; only `exact` ships today).

## The path

```
1. SPIRE agent attests the pod → issues X.509-SVID (mTLS) + JWT-SVID.
2. Pod presents JWT-SVID at POST /oauth/token (client_assertion).
3. AuthSec validates SVID → maps to service account → resolves scopes → mints native token.
```

## Step-by-step

### 1. SPIRE attestation

SPIRE server verifies the pod's identity via node attestation + workload attestation
(k8s selectors: namespace, pod label, service account). Issues:
- **X.509-SVID** — short-lived cert with SPIFFE URI SAN (`spiffe://trust-domain/workload-id`)
  for mTLS between workloads.
- **JWT-SVID** — short-lived JWT signed by SPIRE's OIDC key.

The JWT-SVID claims:
```json
{
  "iss": "<SPIFFE_OIDC_ISSUER>",
  "sub": "spiffe://<trust-domain>/<workload-path>",
  "aud": ["<target-audience>"],
  "iat": ..., "exp": ...
}
```

### 2. Token request

```
POST /oauth/token
  grant_type=client_credentials
  client_assertion_type=urn:authsec:params:oauth:client-assertion-type:spiffe-svid
  client_assertion=<jwt-svid>
  resource=<resource_server_uri>
  scope=<requested scopes>
```

Handler: `tokenClientCredentialsGrant` → `AuthenticateClient` (spiffe branch in `services/client_auth.go`).

### 3. SVID validation (`authenticateSPIFFESVID`)

`services/client_auth.go` — `authenticateSPIFFESVID(ctx, db, assertion, tokenEndpoint)`:

1. Parse JWT-SVID header (no sig check yet) → get `iss` + `sub`.
2. Verify issuer: must be a registered, active `workload_identity_providers` entry, or
   match `SPIFFE_OIDC_ISSUER` (legacy single-issuer env). Anything else → `invalid_client:
   no workload identity provider for this issuer`. **Fail-closed.**
3. Fetch JWKS via the provider's `jwks_uri` or OIDC discovery (`<iss>/.well-known/
   openid-configuration` → `jwks_uri`; falls back to `<iss>/.well-known/jwks.json`).
4. Verify signature + `exp` + `aud` (aud must include the provider's allowed audiences,
   else the token endpoint).
5. **Trust-domain binding** — if the matched provider declares a `trust_domain`, the
   SVID's `sub` trust domain MUST equal it. Stops a token from trusted issuer A asserting
   a SPIFFE ID under a different domain B.
6. Look up `service_accounts` by `spiffe_id = sub` (exact match; `spiffe_match_type`),
   active, with a linked confidential `mcp_oauth_clients` row.

### 4. Grant continues as M2M

Once the service account is resolved, the flow is identical to `flows/m2m.md`:
- Resolve RS + scopes.
- `NativeIssuer.Issue(ctx, NativeClaims{Family:"m2m", SubjectType:"service_account", ...})`.
- No `act` claim (the SVID is the direct credential, not a delegation).

Optional: if the SVID carries a `spiffe_id` actor (delegation scenario), `act.spiffe_id`
is set in the minted token for downstream audit.

## mTLS path (X.509-SVID)

For service-to-service calls where mTLS replaces the token entirely:
- The SPIRE agent injects the X.509-SVID into the pod's credential socket.
- The peer validates the cert chain against SPIRE's trust bundle.
- No `/oauth/token` call needed for mTLS-only scenarios.

## SPIRE OIDC discovery

SPIRE publishes its own OIDC discovery endpoint. AuthSec pulls SPIRE's JWKS to include
in the `/oauth/jwks` union. `SpiffeKeyService` (`services/spiffe_key_service.go`) manages
the key pair for JWT-SVIDs that AuthSec itself signs (for the SPIFFE OIDC provider role).

Environment:
- `SPIFFE_OIDC_ISSUER` — must match `OIDCIssuer` in SPIRE server config.
- `SPIFFE_JWKS_KEY_ID` — stable `kid` for SPIRE JWKS cache.
- `SPIFFE_RSA_PRIVATE_KEY` — PEM private key for AuthSec's SPIFFE signing role.

## Workload registration

```
POST /workspaces/:wsid/workload-entries
{
  "spiffe_id": "spiffe://authsec.dev/ns/prod/sa/my-service",
  "parent_id": "spiffe://authsec.dev/ns/spire/sa/spire-agent",
  "selectors": [{"type": "k8s", "value": "ns:prod"}],
  "ttl": 3600
}
```

This creates a `workload_entries` row and syncs to SPIRE via the SPIRE entry API
(`entryv1.EntryClient`, `spire_controller.go`).

## When you're building

- **New workload type?** Register selectors in `workload_entries`. If the attestation
  plugin isn't configured in SPIRE, the workload won't get an SVID.
- **New SVID claim?** Extend `authenticateSPIFFESVID` to extract and validate it.
- **Debugging "invalid_client: SPIFFE ID not found"?** Check `service_accounts.spiffe_id`
  matches the SVID's `sub` exactly.

## Related

`primitives/spire.md` (SPIRE models + key service), `flows/m2m.md` (the grant
continues as M2M after SVID validation), `primitives/token-engine.md`.
