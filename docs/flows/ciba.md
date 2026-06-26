# Flow: CIBA (Client-Initiated Backchannel Authentication)

> Headless / server-to-server initiated login. The client initiates authentication
> on behalf of a user (by `login_hint` / email); the user approves via push notification
> or TOTP out-of-band; the client polls for the token.
> Enabled by `XAA_CIBA=true` env var.

## When to use

CIBA is for scenarios where the client cannot redirect a browser — voice assistants,
CLI tools, server processes that need to authenticate a user without a browser redirect.

## Two implementations

AuthSec has two CIBA implementations:

| | `TenantCIBAAuthService` (workspace-plane) | `CIBAAuthService` (legacy) |
|---|---|---|
| Table | `workspace_ciba_auth_requests` | `ciba_auth_requests` |
| Token issued | Native (from `NativeIssuer.Issue`) | Hydra-backed |
| Activated by | `XAA_CIBA=true` in config | older path |
| BC-authorize endpoint | `POST /oauth/bc-authorize` | `POST /auth/workspace/ciba/initiate` |

The workspace-plane (`TenantCIBAAuthService`) is the current, native path.

## Step 1: Backchannel authorization request

```
POST /oauth/bc-authorize
  client_id=<client_id>   + credentials
  login_hint=<user_email>
  scope=<requested scopes>
  binding_message=<human-readable context>    (optional)
  resource=<resource_server_uri>
```

Handler: `OAuthASController.BCAuthorize` (`controllers/platform/oauth_as_controller.go`).

Processing:
1. Authenticate client (`AuthenticateClient`).
2. Validate `login_hint` → look up user by email.
3. Validate RS + client registration.
4. Generate `auth_req_id` (random 32-byte base64 URL).
5. Insert `workspace_ciba_auth_requests` row (`status='pending'`, `expires_at = now+5m`).
6. Send push notification to user's device (via `PushNotificationService`).
7. Return:
   ```json
   { "auth_req_id": "<token>", "expires_in": 300, "interval": 5 }
   ```

## Step 2: User approves

User receives push notification, opens the AuthSec mobile/web app, approves the request.
This updates `workspace_ciba_auth_requests.status = 'approved'`.

(Alternatively, TOTP-based approval: user enters a code at `/auth/workspace/ciba/confirm`.)

## Step 3: Client polls for token

```
POST /oauth/token
  grant_type=urn:openid:params:grant-type:ciba
  client_id=<client_id>   + credentials
  auth_req_id=<auth_req_id>
```

Handler: `tokenCIBAGrant`.

1. Authenticate client.
2. Look up `workspace_ciba_auth_requests` by `auth_req_id`:
   - `status='pending'` → return `authorization_pending` (poll again after `interval` seconds).
   - `status='denied'` → return `access_denied`.
   - `status='expired'` → return `expired_token`.
   - `status='approved'` → continue.
3. Resolve user + workspace from the request row.
4. Resolve RS + scopes.
5. Mint native token: `NativeIssuer.Issue(ctx, NativeClaims{Family:"ciba", SubjectType:"user", ...})`:
   - `sub` = user UUID
   - `act` = `{client_id: client.ClientID}` (client is the actor)
   - `tf` = `"ciba"`
   - Optional `rar_id` for RFC 9396 Rich Authorization Requests.
6. Mark request `consumed`.
7. Return token response.

## Token claims (CIBA access token)

```json
{
  "iss": "<OAuthBaseURL>",
  "sub": "<user_uuid>",
  "aud": ["<resource_server_uri>"],
  "scope": "tool:invoke",
  "client_id": "<client_id>",
  "jti": "<uuid>",
  "iat": 1234567890,
  "exp": 1234567890,
  "tf": "ciba",
  "act": { "client_id": "<client_id>" }
}
```

## When you're building

- **Enabling CIBA?** Set `XAA_CIBA=true` in the environment. `NewOAuthASController`
  wires `TenantCIBAAuthService` and `PushNotificationService` automatically.
- **Push notification integration?** `services/push_notification_service.go` wraps the
  FCM/APNs client. Configure via `PUSH_*` env vars.
- **Polling interval?** `pollingInterval` defaults to 5 seconds (`workspace_ciba_auth_service.go`).
  Clients that poll faster get `slow_down`.
- **RAR (Rich Authorization)?** `workspace_ciba_auth_requests.rar_id` links to a RAR
  object; propagated to `native_tokens.rar_id`.

## Related

`primitives/token-engine.md` (native CIBA token issuance), `primitives/identity-principals.md`
(actor + subject model), `flows/xaa-idjag.md` (XAA is the cross-app extension of CIBA).
