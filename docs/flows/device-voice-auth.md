# Flow: Device Auth & Voice Auth

> Device flow: for devices without a browser (OAuth 2.0 Device Authorization Grant,
> RFC 8628). Voice auth: biometric voice verification for user identity confirmation.

## Device Flow (RFC 8628)

### Step 1: Device authorization request

```
POST /oauth/device/code     (or /auth/workspace/device/initiate)
  client_id=<client_id>
  scope=<requested scopes>
  resource=<resource_uri>
```

Returns:
```json
{
  "device_code": "<opaque>",
  "user_code": "XKCD-4321",
  "verification_uri": "https://app.authsec.ai/activate",
  "verification_uri_complete": "https://app.authsec.ai/activate?user_code=XKCD-4321",
  "expires_in": 900,
  "interval": 5
}
```

State stored in `device_codes` table.

### Step 2: User activation

User opens `verification_uri` in a browser, enters the `user_code` (or scans QR), and
completes the normal OIDC login + consent flow. The device code is linked to the user
session and marked `status='approved'`.

Tables: `device_codes` (device authorization state), `workspace_device_tokens`
(workspace-plane scoped tokens), `device_tokens` (legacy).

### Step 3: Client polls

```
POST /oauth/token
  grant_type=urn:ietf:params:oauth:grant-type:device_code
  client_id=<client_id>
  device_code=<device_code>
```

Polling responses:
- `authorization_pending` — user hasn't completed yet; retry after `interval`.
- `slow_down` — client is polling too fast.
- `access_denied` — user denied.
- `expired_token` — device code expired (15-min default).
- 200 + token — user approved.

Handler: `services/device_auth_service.go` → `DeviceAuthService`.

## Voice Authentication

Voice auth (`services/voice_auth_service.go`) supports biometric identity verification:

1. **Enrollment**: user records a voice passphrase (stored as `voice_identity_links` row
   linking user + voice model ID).
2. **Verification**: during login or a step-up, a voice verification challenge is issued.
   User speaks the phrase; `voice_sessions` tracks the challenge state.
3. **Outcome**: `VoiceAuthService.VerifyVoice(ctx, userID, audioData)` returns a
   confidence score. Above threshold → `voice_sessions.status='verified'`; used as a
   second factor in the `hmgr_controller` login flow.

Tables: `voice_sessions` (active voice challenges), `voice_identity_links` (user ↔ voice model).

## Related

`flows/oidc-login.md` (device flow user activation uses the standard OIDC login),
`primitives/oauth-as.md` (POST /oauth/token dispatch).
