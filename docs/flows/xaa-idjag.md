# Flow: XAA / ID-JAG (cross-app agent delegation)

> An agent acts on behalf of a user at a target Resource Server the agent
> doesn't directly belong to. Two-step native flow: token-exchange → ID-JAG,
> then jwt-bearer → access token.
> Read `primitives/token-engine.md` and `primitives/identity-principals.md` first.

## Big picture

```
Step 1 — XAA (token-exchange):
  Agent presents user's Hydra token → AuthSec mints a 5-min ID-JAG assertion.

Step 2 — jwt-bearer redemption:
  Agent presents ID-JAG at target RS's AS → AuthSec validates + mints native access token.
```

The boundary that gates XAA is the **resource server** (audience), per ID-JAG draft
§4.1 / §7.3 — **not** the workspace. A same-workspace agent→RS call is conformant XAA.

## Step 1: Token exchange → ID-JAG

```
POST /oauth/token
  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
  client_id=<agent_client_id>   + credentials (private_key_jwt / secret)
  subject_token=<user's Hydra access token>
  subject_token_type=urn:ietf:params:oauth:token-type:access_token
  resource=<target_resource_uri>
  scope=<requested delegation scopes>
```

Handler: `tokenExchangeGrant` (`oauth_as_controller.go`).

1. **Authenticate agent client** — `AuthenticateClient`.
2. **Validate subject_token** — Hydra introspect (the user's existing Hydra access token must be active, issued to a client in the same workspace).
3. **Resolve target RS** — by `resource` param.
4. **First-contact gate** — if the agent has never accessed this RS, insert
   `resource_server_client_registrations` row with `status='access_pending'`.
5. **Check approved** — `GetClientRegistration(rs.ID, agentClient.ID)` must be `approved`.
6. **Mint ID-JAG** — `NativeIssuer.IssueIDJAG(ctx, IDJAGClaims{...})`:
   - `typ=oauth-id-jag+jwt`
   - `iss` = OAuthBaseURL, `sub` = user UUID, `aud` = OAuthBaseURL (the AS, not the RS)
   - `client_id` = agent client ID, `resource` = target RS URI, `scope` = delegation scope
   - `issuance_workspace` = workspace ID (audit/provenance only)
   - TTL: **5 minutes** (`IDJAGTLL`); **NOT** stored in `native_tokens`

7. **Response**: `{"access_token": "<id-jag>", "token_type": "urn:ietf:params:oauth:token-type:id-jag", "expires_in": 300}`.

## Step 2: JWT-bearer → access token

```
POST /oauth/token
  grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
  client_id=<agent_client_id>   + credentials
  assertion=<id-jag JWT>
  resource=<target_resource_uri>
  scope=<requested scopes>
```

Handler: `tokenJWTBearerGrant` (`oauth_as_controller.go`) → `services.XAAService`.

1. **Authenticate agent client** — `AuthenticateClient`.
2. **Validate ID-JAG** — `XAAService.ValidateIDJAG(ctx, assertion, clientID, selfIssuer)`:
   - Parse header only (no sig) → get `iss` + `typ`.
   - `typ` must be `"oauth-id-jag+jwt"`.
   - Resolve issuer:
     - **Self-issued** (`iss == OAuthBaseURL`) → trust as `authsec:id-jag`, verify against native JWKS (no HTTP round-trip). `sub` is a local user UUID.
     - **External** → look up `trusted_issuers` (status=active), fetch JWKS from `trusted_issuers.jwks_uri`, verify signature.
   - Verify `aud == selfIssuer`, `client_id == authenticatedClientID`, `exp`, `iat`.
   - **Replay check is deferred to issuance transaction** (not here).

3. **Map subject** — for self-issued: `sub` is already the local user UUID. For external: look up `oidc_user_identities` by `(iss, sub)` → resolve local user UUID; JIT-provision if `trusted_issuers.jit_provisioning=true`.

4. **Resolve RS + check registration** — RS by `resource`; `GetClientRegistration` must be `approved`.

5. **Resolve scopes** — `ScopeResolver.ResolveGrantableScopes` for the local user in the RS's workspace.

6. **Mint + replay guard (atomic)** — `NativeIssuer.Issue(ctx, NativeClaims{Family:"xaa", ...}, inTx...)`:
   - `inTx` hook: insert `id_jag_replay_cache(iss, jti)` — if it already exists the tx aborts with `ErrIDJAGReplayed`.
   - `sub` = local user UUID, `SubjectType="user"`
   - `act` = `{client_id: agentClientID, spiffe_id?: ...}` (the actor)
   - `source_grant_jti` = ID-JAG jti, `source_grant_iss` = ID-JAG iss
   - `tf` = `"xaa"`

7. **Response**: standard OAuth2 token response. No refresh token.

## Token claims (XAA access token)

```json
{
  "iss": "<OAuthBaseURL>",
  "sub": "<user_uuid>",
  "aud": ["<resource_server_uri>"],
  "scope": "tool:invoke",
  "client_id": "<agent_client_id>",
  "jti": "<uuid>",
  "iat": 1234567890,
  "exp": 1234567890,
  "tf": "xaa",
  "act": { "client_id": "<agent_client_id>" },
  "source_grant_jti": "<id-jag-jti>",
  "source_grant_iss": "<id-jag-iss>"
}
```

## First contact / approve-with-role

First time an agent calls a new RS, the registration is `access_pending`:
1. Admin sees the request in `role_assignment_requests`.
2. Admin calls `ApproveWithRole(requestID, roleID)` — atomically:
   - Updates `resource_server_client_registrations.status` → `approved`.
   - Inserts `role_bindings(subject_type="user", subject_id=user.id, role_id, workspace_id, rs_id)`.
3. Subject now has effective scopes; the next XAA attempt succeeds.

## When you're building

- **Adding a new assertion type for XAA?** Add a dispatch branch in `tokenExchangeGrant`
  and a new `IssueXxx` method on `NativeIssuer` if the claim set differs.
- **New trusted issuer?** Insert into `trusted_issuers`; `ValidateIDJAG` picks it up
  via the DB lookup (with JWKS cache, default 5-min TTL).
- **Debugging "untrusted_issuer"?** Check `trusted_issuers` table, `status='active'`.
- **Debugging replay errors?** Check `id_jag_replay_cache` — each (iss, jti) is one-shot.

## Related

`primitives/token-engine.md` (`IssueIDJAG` + `Issue` + `id_jag_replay_cache`),
`flows/oidc-login.md` (step 0 — the user must have a Hydra token to exchange),
`flows/federation.md` (trusted issuers for external ID-JAGs).
