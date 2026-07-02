# Flow: Connectors — identity-aware outbound action broker

> AuthSec is an outbound **action broker** for AI agents. A caller authenticates,
> names a connector + a typed action, and AuthSec — after authorizing on
> Principal + Actor + assignments — injects the credential server-side, performs
> the allowlisted provider call, and returns only the redacted result. **The
> caller never receives the credential.**
> Read `primitives/token-engine.md` and `flows/xaa-idjag.md` first.

## The model

| Noun | What it is | Table |
|---|---|---|
| **Provider** | catalog entry (Google, HubSpot, Mixpanel) | `connector_providers` |
| **Connector** | a workspace's configured instance of a Provider | `connectors` |
| **Connection** | a credential binding (workspace- or user-scoped) + lifecycle | `connector_connections` |
| **Action** | the only invocable unit; a typed provider call | `connector_actions` (P2) |
| **Assignment** | which client may use which connector + action | `connector_assignments` |

## Two planes

- **Control plane** `/authsec/connectors/*` — interactive admin session
  (`AuthMiddleware` + `Require("connector", …)`). CRUD, non-secret `/config`,
  connection management, assignments. **No credential-vending route.**
- **Data plane** `/broker/connectors/*` — runtime. The caller presents a native
  AuthSec access token whose audience is the **workspace Connector Broker RS**.
  The broker controller verifies the token itself (no standard auth middleware)
  via the shared `services.VerifyProtectedResourceToken` and runs the policy
  chain.

## The Connector Broker Resource Server

One AuthSec-managed RS **per workspace** (`EnsureBrokerResourceServer`):
`application_type='connector_broker'`, `managed=true`, resource_uri
`authsec://broker/connectors/{workspace_id}`. It is the **audience** for every
runtime token (RFC 8707). Connectors are resources *beneath* the broker — they
are not individual `resource_servers`.

## Runtime authorization chain (data plane)

```
native AuthSec token (aud = workspace Connector Broker RS)
  → tokens.Classify → native kid (HMAC authsec-api / Hydra-opaque rejected)
  → load candidate RS by token aud; require managed + connector_broker type
  → services.VerifyProtectedResourceToken(token, kid, rs) → AuthContext
        signature → native_tokens row → revocation → AUDIENCE (re-checked)
        → client→RS registration approved → live RBAC scope re-resolution
  → connector enabled AND agent_accessible            (else 404, obscured)
  → connector_assignments allows (ClientID, connector, action)   (else 403)
  → matching Connection (user-bound by token.sub when delegated; else workspace)
  → [P2] refresh-under-lock → typed adapter injects credential → provider call
  → redacted result + action-audit
```

Authorization is on **Principal + Actor + assignments + resource binding** —
never on token provenance (`tf`) and never on a single auth method. `tf`/`act`
only tell the audit log how the caller arrived.

## Threat model

| Threat | Control |
|---|---|
| Credential exfiltration | No vending endpoint/SDK. `vault_path` is `json:"-"` — never serialized. Secrets live only in Vault + broker-side. |
| Confused deputy / token redirect | Runtime tokens must be `aud`-bound to the broker RS (RFC 8707); the verifier re-checks `native_tokens.aud == rs.resource_uri`. A token minted for another resource is rejected. |
| SSRF / arbitrary egress | Typed actions only (P2) — fixed provider base URL + method; no caller-supplied URL; egress allowlist. |
| Over-privilege | Per-(client, connector, action) assignments + action-required scopes + RBAC. |
| Replay | Existing ID-JAG one-shot replay cache preserved; the broker is a consumer, not an issuer. |
| Disabled/revoked still works | Policy chain checks `enabled` + Connection status; disabled connector / revoked connection → fail closed. `/config` 404s when disabled. |
| Vault path / secret leakage | `vault_path` stripped from all JSON; no `Credentials()` method on the manager. |
| Audit gaps | Every action execution (allow + deny) writes an audit event (P2). |

## When you're building

- **New consumer of a native token?** Call `services.VerifyProtectedResourceToken`
  — never re-implement the chain, never route a native kid to Hydra.
- **New connector runtime path?** It must accept only broker-audience tokens and
  run the full policy chain; fail closed (404/403, obscured) on any gap.
- **Never** add an endpoint or SDK method that returns a provider credential.

## Related

`primitives/token-engine.md` (native families, kid, the one rule),
`flows/xaa-idjag.md` (P4: agent-on-behalf-of-user token to the broker),
`internal/tokens/principal.go` (Principal + Actor), RFC 8707 (resource
indicators / audience binding).
