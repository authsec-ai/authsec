# Token engine — NativeSealer vs Hydra

> Read this before touching anything that mints, validates, introspects, revokes, or
> publishes keys for tokens. Package: `internal/tokens` (`package tokens`).

## The one rule

A bearer token belongs to exactly **one family**, decided by its JWT header `kid`:

- **`FamilyNative`** — minted by AuthSec's native issuer (families **M2M / XAA / CIBA**). Header `kid` starts with **`native:`** (`NativeKIDPrefix`).
- **`FamilyHydra`** — interactive OAuth (`authorization_code` / `refresh_token`) and anything opaque / unparseable / non-native → ORY Hydra's introspection path.

**A native `kid` commits to the native path** — a bad signature is *rejected*, never retried on Hydra. (`internal/tokens/classifier.go`, the package doc comment.)

## Pieces (all in `internal/tokens/`)

| Piece | File | What it does |
|---|---|---|
| **Classifier** | `classifier.go` | `Classify(token, nativeKIDs)` parses **only** the JWS header (no signature check, no Hydra call) → `FamilyNative` if `kid ∈ nativeKIDs`, else `FamilyHydra`. `parseHeaderKid` is header-only. |
| **Key manager** | `keys.go` | `NativeKeyManager` — a **global** rotating RS256 keyset (`active` + `next`), no per-workspace keys and no workspace id in the `kid` (§17, can't leak ownership). Loads via a `KVStore` (Vault); **env fallback `NATIVE_RSA_PRIVATE_KEY_B64`** (PKCS8) pins a stable active key across restarts. `Sign()` / `SignWithTyp()`, `NativeKeyIDs()` (feeds the classifier), `PublicJWKS()` (active then next). |
| **Singleton** | `singleton.go` | `InitNativeKeys(kv)` at boot; `NativeKeys()` accessor. Keyset is process-wide. |
| **Issuer** | `issuer.go` | `NativeIssuer` — the **only** thing native grant handlers call to mint. `Issue(ctx, NativeClaims, inTx...)` signs + inserts the authoritative `native_tokens` row; `inTx` hooks run in the **same transaction** (e.g. XAA replay-guard insert → issuance is atomic). `IssueIDJAG(ctx, IDJAGClaims)` mints the 5-min ID-JAG (`typ=oauth-id-jag+jwt`, token-type `urn:ietf:params:oauth:token-type:id-jag`) — signed but **not** stored (tracked via `id_jag_replay_cache` on redemption). |
| **Store / revocation** | `store.go` | `LookupNativeToken`, `IsRevoked(iss,kind,jti)`, `RevokeAccessToken(...)`. `revoked_tokens` is the **source of truth** for native revocation. |
| **Grant seam** | `grant_handler.go` | `GrantHandler` interface (`Handle(c *gin.Context)`) — per-grant orchestration on `/oauth/token`. Authenticate / validate / gate / resolve-scopes stays **in the handler**; only minting goes through `NativeIssuer`. |

## Native access-token claims (`NativeIssuer.Issue`)

`iss` (canonical `OAuthBaseURL`), `sub`, `aud` (= `resource_servers.resource_uri`), `scope`,
`client_id` (authenticating client), `jti`, `iat`, `exp`, **`tf`** (token family),
optional **`act`** (`{client_id, spiffe_id}` — the actor for XAA/workload), optional
`source_grant_jti` / `source_grant_iss` (XAA provenance). Native tokens are **short-lived,
non-refreshable**.

## JWKS

`/oauth/jwks` publishes a **union**: native (`PublicJWKS()`) + Hydra + SPIFFE. Validators
pick the path by `kid`. SPIRE also exposes its own discovery + `jwks.json` for JWT-SVID
federation (see `primitives/spire.md`).

## When you're building

- **Minting a new native token type / grant?** Add a `GrantHandler`, do all the auth/scope
  work there, call `NativeIssuer.Issue` to mint. Never sign tokens elsewhere.
- **New native token family?** It needs a `models.TokenFamily` value, the `tf` claim, and the
  classifier already routes it by `kid`.
- **Anything that must be atomic with minting** (replay guard, usage marking) → pass an `inTx`
  hook to `Issue`, don't do a second write after.
- **Revocation** → `store.RevokeAccessToken` (writes `revoked_tokens`); introspection checks
  `IsRevoked`. Don't invent a second revocation path.
- **Never** route a `native:`-kid token to Hydra, and never put a workspace id in a `kid`.

## Flows that use this
`flows/m2m.md` (client_credentials → native M2M), `flows/xaa-idjag.md` (token-exchange →
`IssueIDJAG` → jwt-bearer → `Issue`), `primitives/oauth-as.md` (the `/oauth/token` dispatch),
`primitives/hydra.md` (the Hydra side).
