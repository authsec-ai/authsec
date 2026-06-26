# Flow: SPIFFE Workload (JWT-SVID → access token)

> A k8s workload (pod) presents its SPIRE-issued JWT-SVID to get a scoped native
> access token. No long-lived secrets — the SVID is the credential.
> Read `primitives/spire.md` and `primitives/token-engine.md` first.

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

1. Parse JWT-SVID header (no sig check yet) → get `iss`.
2. Verify issuer: must be registered as a `workload_identity_providers` entry or match
   `SPIFFE_OIDC_ISSUER` (the local SPIRE server).
3. Fetch JWKS from the issuer's OIDC discovery or configured JWKS URI.
4. Verify signature + `exp` + `aud`.
5. Extract `sub` (SPIFFE ID).
6. Look up `service_accounts` by `spiffe_id = sub` to get the service account and its
   associated `mcp_oauth_clients` row.

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
