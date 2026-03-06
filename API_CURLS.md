# AuthSec API — cURL Reference

**Base URL:** `http://localhost:7468`

```bash
BASE="http://localhost:7468"
TOKEN="<your-jwt-token>"
TENANT_ID="<tenant-uuid>"
USER_ID="<user-uuid>"
```

---

## Well-Known / OIDC Discovery

```bash
# OpenID Configuration
curl "$BASE/.well-known/openid-configuration"

# JWKS (public keys)
curl "$BASE/.well-known/jwks.json"
```

---

## Debug

```bash
# Reveal JWT secret (development only)
curl -X POST "$BASE/authsec/debug/jwt-secret"
```

---

## Health

```bash
# Global health check
curl "$BASE/authsec/health"

# Tenant DB health
curl "$BASE/authsec/health/tenant/$TENANT_ID"

# All tenant DBs health
curl "$BASE/authsec/health/tenants"
```

---

## Admin Authentication  `/authsec/auth/admin`

```bash
# Get auth challenge
curl "$BASE/authsec/auth/admin/challenge"

# Pre-check before login (check if user exists, get MFA hint)
curl -X POST "$BASE/authsec/auth/admin/login/precheck" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Bootstrap first admin (initial setup)
curl -X POST "$BASE/authsec/auth/admin/login/bootstrap" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"changeme","tenant_id":"'"$TENANT_ID"'"}'

# Login
curl -X POST "$BASE/authsec/auth/admin/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"changeme","tenant_id":"'"$TENANT_ID"'"}'

# Login hybrid (password + MFA in one call)
curl -X POST "$BASE/authsec/auth/admin/login-hybrid" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"changeme","tenant_id":"'"$TENANT_ID"'","totp_code":"123456"}'

# Register admin
curl -X POST "$BASE/authsec/auth/admin/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"changeme","tenant_id":"'"$TENANT_ID"'","first_name":"Alice","last_name":"Admin"}'

# Complete registration (from invite link)
curl -X POST "$BASE/authsec/auth/admin/complete-registration" \
  -H "Content-Type: application/json" \
  -d '{"token":"<registration-token>","password":"changeme"}'

# Forgot password — send OTP
curl -X POST "$BASE/authsec/auth/admin/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Forgot password — verify OTP
curl -X POST "$BASE/authsec/auth/admin/forgot-password/verify-otp" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","tenant_id":"'"$TENANT_ID"'","otp":"123456"}'

# Forgot password — reset
curl -X POST "$BASE/authsec/auth/admin/forgot-password/reset" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","tenant_id":"'"$TENANT_ID"'","token":"<reset-token>","new_password":"newpass123"}'
```

---

## End-User Authentication  `/authsec/auth/enduser`

```bash
# Get auth challenge
curl "$BASE/authsec/auth/enduser/challenge"

# Initiate end-user registration (sends OTP)
curl -X POST "$BASE/authsec/auth/enduser/initiate-registration" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'"}'

# Verify OTP and complete registration
curl -X POST "$BASE/authsec/auth/enduser/verify-otp" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","otp":"123456"}'

# Login pre-check
curl -X POST "$BASE/authsec/auth/enduser/login/precheck" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# WebAuthn callback (after passkey assertion)
curl -X POST "$BASE/authsec/auth/enduser/webauthn-callback" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","credential":{...}}'

# SPIFFE SVID delegation
curl -X POST "$BASE/authsec/auth/enduser/delegate-svid" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"workload_id":"spiffe://example.org/workload"}'
```

---

## End-User Self-Service  `/authsec/user`

```bash
# Login (custom password login)
curl -X POST "$BASE/authsec/user/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"pass","tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'"}'

# Login status (poll for async logins)
curl -X POST "$BASE/authsec/user/login/status" \
  -H "Content-Type: application/json" \
  -d '{"request_id":"<request-id>"}'

# SAML login
curl -X POST "$BASE/authsec/user/saml/login" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'","relay_state":"<state>"}'

# OIDC login
curl -X POST "$BASE/authsec/user/oidc/login" \
  -H "Content-Type: application/json" \
  -d '{"provider":"google","tenant_id":"'"$TENANT_ID"'"}'

# Initiate registration
curl -X POST "$BASE/authsec/user/register/initiate" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'"}'

# Complete registration
curl -X POST "$BASE/authsec/user/register/complete" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","otp":"123456","password":"pass"}'

# Register (combined)
curl -X POST "$BASE/authsec/user/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"pass","tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'"}'

# Forgot password — send OTP
curl -X POST "$BASE/authsec/user/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Forgot password — verify OTP
curl -X POST "$BASE/authsec/user/forgot-password/verify-otp" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","otp":"123456"}'

# Forgot password — reset
curl -X POST "$BASE/authsec/user/forgot-password/reset" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","token":"<reset-token>","new_password":"newpass"}'

# ── Authenticated below ──────────────────────────────────────────────────────

# Register client (device/app)
curl -X POST "$BASE/authsec/user/clients/register" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"client_name":"My App","tenant_id":"'"$TENANT_ID"'"}'

# Get clients
curl "$BASE/authsec/user/clients" \
  -H "Authorization: Bearer $TOKEN"

# Get specific end-user
curl "$BASE/authsec/user/enduser/$TENANT_ID/$USER_ID" \
  -H "Authorization: Bearer $TOKEN"

# List end-users
curl -X POST "$BASE/authsec/user/enduser/list" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'","page":1,"limit":20}'

# Update end-user
curl -X PUT "$BASE/authsec/user/enduser/$TENANT_ID/$USER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"first_name":"Bob","last_name":"Smith"}'

# Update end-user status
curl -X PUT "$BASE/authsec/user/enduser/$TENANT_ID/$USER_ID/status" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"active":true}'

# Delete end-user
curl -X DELETE "$BASE/authsec/user/enduser/$TENANT_ID/$USER_ID" \
  -H "Authorization: Bearer $TOKEN"

# Admin change user password
curl -X POST "$BASE/authsec/user/admin/change-password" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"'"$USER_ID"'","new_password":"newpass","tenant_id":"'"$TENANT_ID"'"}'

# Admin reset user password (sends reset email)
curl -X POST "$BASE/authsec/user/admin/reset-password" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"'"$USER_ID"'","tenant_id":"'"$TENANT_ID"'"}'
```

---

## TOTP (User-flow)  `/authsec/auth/totp`

```bash
# Login with TOTP code
curl -X POST "$BASE/authsec/auth/totp/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","code":"123456"}'

# Approve device code with TOTP
curl -X POST "$BASE/authsec/auth/totp/device-approve" \
  -H "Content-Type: application/json" \
  -d '{"device_code":"<code>","totp_code":"123456"}'

# Register TOTP device (returns QR code)
curl -X POST "$BASE/authsec/auth/totp/register" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_name":"My Authenticator","tenant_id":"'"$TENANT_ID"'"}'

# Confirm TOTP registration
curl -X POST "$BASE/authsec/auth/totp/confirm" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"secret":"<base32-secret>","code":"123456","tenant_id":"'"$TENANT_ID"'"}'

# Verify TOTP (for actions requiring step-up)
curl -X POST "$BASE/authsec/auth/totp/verify" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"123456","tenant_id":"'"$TENANT_ID"'"}'

# List TOTP devices
curl "$BASE/authsec/auth/totp/devices" \
  -H "Authorization: Bearer $TOKEN"

# Delete TOTP device
curl -X POST "$BASE/authsec/auth/totp/device/delete" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_id":"<device-uuid>","tenant_id":"'"$TENANT_ID"'"}'

# Set primary TOTP device
curl -X POST "$BASE/authsec/auth/totp/device/primary" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_id":"<device-uuid>","tenant_id":"'"$TENANT_ID"'"}'

# Regenerate backup codes
curl -X POST "$BASE/authsec/auth/totp/backup/regenerate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'"}'
```

---

## Tenant TOTP  `/authsec/auth/tenant/totp`

```bash
# Login with tenant TOTP
curl -X POST "$BASE/authsec/auth/tenant/totp/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","code":"123456"}'

# Register tenant TOTP device
curl -X POST "$BASE/authsec/auth/tenant/totp/register" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_name":"Work Authenticator","tenant_id":"'"$TENANT_ID"'"}'

# Confirm tenant TOTP device
curl -X POST "$BASE/authsec/auth/tenant/totp/confirm" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"secret":"<secret>","code":"123456","tenant_id":"'"$TENANT_ID"'"}'

# List tenant TOTP devices
curl "$BASE/authsec/auth/tenant/totp/devices" \
  -H "Authorization: Bearer $TOKEN"

# Delete tenant TOTP device
curl -X POST "$BASE/authsec/auth/tenant/totp/devices/delete" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_id":"<device-uuid>","tenant_id":"'"$TENANT_ID"'"}'

# Set primary tenant TOTP device
curl -X POST "$BASE/authsec/auth/tenant/totp/devices/primary" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_id":"<device-uuid>","tenant_id":"'"$TENANT_ID"'"}'
```

---

## CIBA  `/authsec/auth/ciba`

```bash
# Initiate CIBA authentication
curl -X POST "$BASE/authsec/auth/ciba/initiate" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"'"$CLIENT_ID"'","login_hint":"user@example.com","scope":"openid profile","binding_message":"Login to App"}'

# Poll for CIBA token
curl -X POST "$BASE/authsec/auth/ciba/token" \
  -H "Content-Type: application/json" \
  -d '{"auth_req_id":"<auth-req-id>","client_id":"'"$CLIENT_ID"'"}'

# Respond to CIBA request (approve/deny on device)
curl -X POST "$BASE/authsec/auth/ciba/respond" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"auth_req_id":"<auth-req-id>","approved":true}'

# Register push device for CIBA
curl -X POST "$BASE/authsec/auth/ciba/register-device" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_token":"<fcm-token>","device_name":"iPhone 15"}'

# List CIBA devices
curl "$BASE/authsec/auth/ciba/devices" \
  -H "Authorization: Bearer $TOKEN"

# Delete CIBA device
curl -X DELETE "$BASE/authsec/auth/ciba/devices/<device_id>" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Tenant CIBA  `/authsec/auth/tenant/ciba`

```bash
# Initiate tenant CIBA
curl -X POST "$BASE/authsec/auth/tenant/ciba/initiate" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"'"$CLIENT_ID"'","login_hint":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Poll tenant CIBA token
curl -X POST "$BASE/authsec/auth/tenant/ciba/token" \
  -H "Content-Type: application/json" \
  -d '{"auth_req_id":"<auth-req-id>","client_id":"'"$CLIENT_ID"'"}'

# Respond to tenant CIBA
curl -X POST "$BASE/authsec/auth/tenant/ciba/respond" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"auth_req_id":"<auth-req-id>","approved":true}'

# Register tenant CIBA device
curl -X POST "$BASE/authsec/auth/tenant/ciba/register-device" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_token":"<fcm-token>","device_name":"My Phone"}'

# List tenant CIBA requests
curl "$BASE/authsec/auth/tenant/ciba/requests" \
  -H "Authorization: Bearer $TOKEN"

# List tenant CIBA devices
curl "$BASE/authsec/auth/tenant/ciba/devices" \
  -H "Authorization: Bearer $TOKEN"

# Delete tenant CIBA device
curl -X DELETE "$BASE/authsec/auth/tenant/ciba/devices/<device_id>" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Device Authorization  `/authsec/auth/device`

```bash
# Request device code (for TV / CLI flows)
curl -X POST "$BASE/authsec/auth/device/code" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"'"$CLIENT_ID"'","scope":"openid profile"}'

# Poll for device token
curl -X POST "$BASE/authsec/auth/device/token" \
  -H "Content-Type: application/json" \
  -d '{"device_code":"<device-code>","client_id":"'"$CLIENT_ID"'"}'

# Get activation info (from device browser page)
curl "$BASE/authsec/auth/device/activate/info?user_code=ABCD-1234"

# Device activation page (HTML)
curl "$BASE/authsec/activate?user_code=ABCD-1234"

# Verify device code (user approves on phone)
curl -X POST "$BASE/authsec/auth/device/verify" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_code":"ABCD-1234"}'
```

---

## Voice Authentication  `/authsec/auth/voice`

```bash
# Initiate voice auth
curl -X POST "$BASE/authsec/auth/voice/initiate" \
  -H "Content-Type: application/json" \
  -d '{"phone_number":"+15551234567","tenant_id":"'"$TENANT_ID"'"}'

# Verify voice OTP
curl -X POST "$BASE/authsec/auth/voice/verify" \
  -H "Content-Type: application/json" \
  -d '{"phone_number":"+15551234567","code":"123456","tenant_id":"'"$TENANT_ID"'"}'

# Get token with voice credentials
curl -X POST "$BASE/authsec/auth/voice/token" \
  -H "Content-Type: application/json" \
  -d '{"phone_number":"+15551234567","code":"123456","tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'"}'

# Link voice assistant
curl -X POST "$BASE/authsec/auth/voice/link" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"assistant_type":"alexa","device_id":"<device-id>"}'

# Unlink voice assistant
curl -X POST "$BASE/authsec/auth/voice/unlink" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"assistant_type":"alexa"}'

# List voice links
curl "$BASE/authsec/auth/voice/links" \
  -H "Authorization: Bearer $TOKEN"

# Get pending device codes
curl "$BASE/authsec/auth/voice/device-pending" \
  -H "Authorization: Bearer $TOKEN"

# Approve device code via voice
curl -X POST "$BASE/authsec/auth/voice/device-approve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_code":"<device-code>"}'
```

---

## OIDC  `/authsec/oidc`

```bash
# List OIDC providers
curl "$BASE/authsec/oidc/providers"

# Initiate OIDC flow
curl -X POST "$BASE/authsec/oidc/initiate" \
  -H "Content-Type: application/json" \
  -d '{"provider":"google","tenant_id":"'"$TENANT_ID"'","redirect_uri":"https://app.example.com/callback"}'

# Initiate OIDC registration
curl -X POST "$BASE/authsec/oidc/register/initiate" \
  -H "Content-Type: application/json" \
  -d '{"provider":"google","tenant_id":"'"$TENANT_ID"'"}'

# Initiate OIDC login
curl -X POST "$BASE/authsec/oidc/login/initiate" \
  -H "Content-Type: application/json" \
  -d '{"provider":"google","tenant_id":"'"$TENANT_ID"'"}'

# OIDC callback (GET, called by provider)
curl "$BASE/authsec/oidc/callback?code=<code>&state=<state>"

# Exchange authorization code for tokens
curl -X POST "$BASE/authsec/oidc/exchange-code" \
  -H "Content-Type: application/json" \
  -d '{"code":"<auth-code>","state":"<state>","tenant_id":"'"$TENANT_ID"'"}'

# Complete OIDC registration
curl -X POST "$BASE/authsec/oidc/complete-registration" \
  -H "Content-Type: application/json" \
  -d '{"token":"<oidc-token>","tenant_id":"'"$TENANT_ID"'"}'

# Check if tenant exists for domain
curl "$BASE/authsec/oidc/check-tenant?domain=example.com"

# Get auth URL for provider
curl -X POST "$BASE/authsec/oidc/auth-url" \
  -H "Content-Type: application/json" \
  -d '{"provider":"google","tenant_id":"'"$TENANT_ID"'","redirect_uri":"https://app.example.com/callback"}'

# Link OIDC identity (authenticated)
curl -X POST "$BASE/authsec/oidc/link" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider":"github","code":"<auth-code>"}'

# Get linked identities
curl "$BASE/authsec/oidc/identities" \
  -H "Authorization: Bearer $TOKEN"

# Unlink OIDC provider
curl -X DELETE "$BASE/authsec/oidc/unlink/google" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Admin Management  `/authsec/admin`

### Tenants

```bash
# List tenants
curl "$BASE/authsec/admin/tenants" \
  -H "Authorization: Bearer $TOKEN"

# Create tenant
curl -X POST "$BASE/authsec/admin/tenants" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Corp","slug":"acme","domain":"acme.app.authsec.dev"}'

# Update tenant
curl -X PUT "$BASE/authsec/admin/tenants/$TENANT_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Corp Updated"}'

# Delete tenant
curl -X DELETE "$BASE/authsec/admin/tenants/$TENANT_ID" \
  -H "Authorization: Bearer $TOKEN"

# List users in tenant
curl "$BASE/authsec/admin/tenants/$TENANT_ID/users" \
  -H "Authorization: Bearer $TOKEN"
```

### Tenant Domains

```bash
# Add domain to tenant
curl -X POST "$BASE/authsec/admin/tenants/$TENANT_ID/domains" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"custom.example.com"}'

# List tenant domains
curl "$BASE/authsec/admin/tenants/$TENANT_ID/domains" \
  -H "Authorization: Bearer $TOKEN"

# Verify domain ownership
curl -X POST "$BASE/authsec/admin/tenants/$TENANT_ID/domains/<domain_id>/verify" \
  -H "Authorization: Bearer $TOKEN"

# Set primary domain
curl -X POST "$BASE/authsec/admin/tenants/$TENANT_ID/domains/<domain_id>/set-primary" \
  -H "Authorization: Bearer $TOKEN"

# Get domain by ID
curl "$BASE/authsec/admin/tenants/$TENANT_ID/domains/<domain_id>" \
  -H "Authorization: Bearer $TOKEN"

# Delete domain
curl -X DELETE "$BASE/authsec/admin/tenants/$TENANT_ID/domains/<domain_id>" \
  -H "Authorization: Bearer $TOKEN"
```

### Admin Users

```bash
# List admin users
curl -X POST "$BASE/authsec/admin/users/list" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"page":1,"limit":20}'

# Delete admin user
curl -X DELETE "$BASE/authsec/admin/users/$USER_ID" \
  -H "Authorization: Bearer $TOKEN"

# Toggle admin user active/inactive
curl -X POST "$BASE/authsec/admin/users/active" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"'"$USER_ID"'","active":true}'

# List end-users by tenant
curl -X POST "$BASE/authsec/admin/enduser/list" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'","page":1,"limit":20}'

# Toggle end-user active/inactive
curl -X POST "$BASE/authsec/admin/enduser/active" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"'"$USER_ID"'","tenant_id":"'"$TENANT_ID"'","active":false}'
```

### Admin Invites

```bash
# Invite admin
curl -X POST "$BASE/authsec/admin/invite" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"newadmin@example.com","tenant_id":"'"$TENANT_ID"'","role":"admin"}'

# Cancel invite
curl -X POST "$BASE/authsec/admin/invite/cancel" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"invite_id":"<invite-uuid>"}'

# Resend invite
curl -X POST "$BASE/authsec/admin/invite/resend" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"invite_id":"<invite-uuid>"}'

# List pending invites
curl "$BASE/authsec/admin/invite/pending" \
  -H "Authorization: Bearer $TOKEN"
```

### Projects

```bash
# Create project
curl -X POST "$BASE/authsec/admin/projects" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My Project","tenant_id":"'"$TENANT_ID"'"}'

# List projects
curl "$BASE/authsec/admin/projects" \
  -H "Authorization: Bearer $TOKEN"
```

### Groups

```bash
# Create user-defined group
curl -X POST "$BASE/authsec/admin/groups" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Engineering","tenant_id":"'"$TENANT_ID"'"}'

# List groups for tenant (admin)
curl -X POST "$BASE/authsec/admin/groups/list" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'"}'

# Get groups for tenant
curl "$BASE/authsec/admin/groups/$TENANT_ID" \
  -H "Authorization: Bearer $TOKEN"

# Update group
curl -X PUT "$BASE/authsec/admin/groups/<group_id>" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Platform Engineering"}'

# Delete group
curl -X DELETE "$BASE/authsec/admin/groups" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"group_id":"<group-uuid>"}'

# Bulk add users to group
curl -X POST "$BASE/authsec/admin/groups/$TENANT_ID/users/bulk" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"group_id":"<group-uuid>","user_ids":["<uid1>","<uid2>"]}'

# Bulk remove users from group
curl -X DELETE "$BASE/authsec/admin/groups/$TENANT_ID/users/bulk" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"group_id":"<group-uuid>","user_ids":["<uid1>"]}'

# Map groups to client
curl -X POST "$BASE/authsec/admin/groups/map" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"'"$CLIENT_ID"'","group_ids":["<gid1>"]}'

# Remove groups from client
curl -X DELETE "$BASE/authsec/admin/groups/map" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"'"$CLIENT_ID"'","group_ids":["<gid1>"]}'
```

---

## RBAC  `/authsec/admin` and `/authsec/user`

### Roles

```bash
# Create role (admin)
curl -X POST "$BASE/authsec/admin/roles" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"viewer","permissions":["read:users"],"tenant_id":"'"$TENANT_ID"'"}'

# List roles (admin)
curl "$BASE/authsec/admin/roles" \
  -H "Authorization: Bearer $TOKEN"

# Update role (admin)
curl -X PUT "$BASE/authsec/admin/roles/<role_id>" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"viewer-updated"}'

# Delete role (admin)
curl -X DELETE "$BASE/authsec/admin/roles/<role_id>" \
  -H "Authorization: Bearer $TOKEN"

# Create role (end-user context)
curl -X POST "$BASE/authsec/user/rbac/roles" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"app-admin","tenant_id":"'"$TENANT_ID"'"}'

# List roles (end-user context)
curl "$BASE/authsec/user/rbac/roles" \
  -H "Authorization: Bearer $TOKEN"
```

### Role Bindings

```bash
# Assign role (admin)
curl -X POST "$BASE/authsec/admin/bindings" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"'"$USER_ID"'","role_id":"<role-uuid>","tenant_id":"'"$TENANT_ID"'"}'

# List role bindings (admin)
curl "$BASE/authsec/admin/bindings" \
  -H "Authorization: Bearer $TOKEN"

# Assign role (end-user context)
curl -X POST "$BASE/authsec/user/rbac/bindings" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"'"$USER_ID"'","role_id":"<role-uuid>","tenant_id":"'"$TENANT_ID"'"}'
```

### Permissions

```bash
# Register permission (admin)
curl -X POST "$BASE/authsec/admin/permissions" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"resource":"documents","action":"read","tenant_id":"'"$TENANT_ID"'"}'

# List permissions (admin)
curl "$BASE/authsec/admin/permissions" \
  -H "Authorization: Bearer $TOKEN"

# Delete permission
curl -X DELETE "$BASE/authsec/admin/permissions/<permission_id>" \
  -H "Authorization: Bearer $TOKEN"

# Policy check (admin)
curl -X POST "$BASE/authsec/admin/policy/check" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"'"$USER_ID"'","resource":"documents","action":"read","tenant_id":"'"$TENANT_ID"'"}'

# Get my permissions
curl "$BASE/authsec/user/permissions" \
  -H "Authorization: Bearer $TOKEN"

# Get my effective permissions
curl "$BASE/authsec/user/permissions/effective" \
  -H "Authorization: Bearer $TOKEN"

# Check single permission
curl "$BASE/authsec/user/permissions/check?resource=documents&action=read" \
  -H "Authorization: Bearer $TOKEN"

# Policy check (end-user)
curl -X POST "$BASE/authsec/user/rbac/policy/check" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"resource":"documents","action":"write"}'
```

### Scopes & API Scopes

```bash
# List scopes (admin)
curl "$BASE/authsec/admin/scopes" \
  -H "Authorization: Bearer $TOKEN"

# Add scope (admin)
curl -X POST "$BASE/authsec/admin/scopes" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"read:reports","description":"Read access to reports","tenant_id":"'"$TENANT_ID"'"}'

# Create API scope (admin)
curl -X POST "$BASE/authsec/admin/api_scopes" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"api:read","resource":"GET /api/data","tenant_id":"'"$TENANT_ID"'"}'

# List API scopes (admin)
curl "$BASE/authsec/admin/api_scopes" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Active Directory / Entra ID Sync  `/authsec/admin`

```bash
# Sync AD users
curl -X POST "$BASE/authsec/admin/ad/sync" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'","ldap_url":"ldap://dc.corp.local","base_dn":"DC=corp,DC=local","username":"svc@corp.local","password":"pass"}'

# Test AD connection
curl -X POST "$BASE/authsec/admin/ad/test-connection" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ldap_url":"ldap://dc.corp.local","base_dn":"DC=corp,DC=local","username":"svc@corp.local","password":"pass"}'

# Test network connectivity
curl -X POST "$BASE/authsec/admin/ad/test-network" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"host":"dc.corp.local","port":389}'

# Agent-based AD sync
curl -X POST "$BASE/authsec/admin/ad/agent-sync" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'","agent_id":"<agent-uuid>"}'

# Sync Entra ID (Azure AD) users
curl -X POST "$BASE/authsec/admin/entra/sync" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'","azure_tenant_id":"<azure-tid>","client_id":"<app-id>","client_secret":"<secret>"}'

# Test Entra ID connection
curl -X POST "$BASE/authsec/admin/entra/test-connection" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"azure_tenant_id":"<azure-tid>","client_id":"<app-id>","client_secret":"<secret>"}'

# Sync AD admin users
curl -X POST "$BASE/authsec/admin/admin-users/ad/sync" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'"}'

# Sync Entra admin users
curl -X POST "$BASE/authsec/admin/admin-users/entra/sync" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'"}'
```

---

## SCIM 2.0  `/authsec/scim/v2`

```bash
# Discovery (public)
curl "$BASE/authsec/scim/v2/ServiceProviderConfig"
curl "$BASE/authsec/scim/v2/Schemas"
curl "$BASE/authsec/scim/v2/ResourceTypes"

# End-user provisioning (Bearer = SCIM token)
SCIM_TOKEN="<scim-token>"
CLIENT_ID="<client-uuid>"
PROJECT_ID="<project-uuid>"

# List users
curl "$BASE/authsec/scim/v2/$CLIENT_ID/$PROJECT_ID/Users" \
  -H "Authorization: Bearer $SCIM_TOKEN"

# Get user
curl "$BASE/authsec/scim/v2/$CLIENT_ID/$PROJECT_ID/Users/<scim-user-id>" \
  -H "Authorization: Bearer $SCIM_TOKEN"

# Create user
curl -X POST "$BASE/authsec/scim/v2/$CLIENT_ID/$PROJECT_ID/Users" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"user@example.com","emails":[{"value":"user@example.com","primary":true}]}'

# Replace user
curl -X PUT "$BASE/authsec/scim/v2/$CLIENT_ID/$PROJECT_ID/Users/<scim-user-id>" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"user@example.com","active":true}'

# Patch user (activate/deactivate)
curl -X PATCH "$BASE/authsec/scim/v2/$CLIENT_ID/$PROJECT_ID/Users/<scim-user-id>" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}'

# Delete user
curl -X DELETE "$BASE/authsec/scim/v2/$CLIENT_ID/$PROJECT_ID/Users/<scim-user-id>" \
  -H "Authorization: Bearer $SCIM_TOKEN"

# List groups
curl "$BASE/authsec/scim/v2/$CLIENT_ID/$PROJECT_ID/Groups" \
  -H "Authorization: Bearer $SCIM_TOKEN"

# Generate SCIM token
curl -X POST "$BASE/authsec/admin/scim/generate-token" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'"}'
```

---

## Legacy Login  `/authsec`

```bash
# Login (legacy path)
curl -X POST "$BASE/authsec/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"pass","tenant_id":"'"$TENANT_ID"'"}'

# Verify OTP and complete registration (legacy)
curl -X POST "$BASE/authsec/register/verify" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","otp":"123456","tenant_id":"'"$TENANT_ID"'"}'

# WebAuthn callback (legacy)
curl -X POST "$BASE/authsec/login/webauthn-callback" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","credential":{...}}'
```

---

## WebAuthn / Passkeys  `/webauthn`

### Health

```bash
curl "$BASE/authsec/health"
```

### MFA Status

```bash
# WebAuthn MFA login status (root-level)
curl -X POST "$BASE/authsec/mfa/loginStatus" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Legacy flat endpoints
curl -X POST "$BASE/authsec/mfa/status" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

curl -X POST "$BASE/authsec/mfa/loginStatus" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

curl "$BASE/authsec/mfa/loginStatus?email=user@example.com&tenant_id=$TENANT_ID"
```

### Legacy WebAuthn Registration & Authentication

```bash
# Begin registration
curl -X POST "$BASE/authsec/beginRegistration" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Begin WebAuthn registration (alternate path)
curl -X POST "$BASE/authsec/beginAuthRegistration" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Finish registration
curl -X POST "$BASE/authsec/finishRegistration" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","credential":{...}}'

# Begin authentication
curl -X POST "$BASE/authsec/beginAuthentication" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Finish authentication
curl -X POST "$BASE/authsec/finishAuthentication" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","credential":{...}}'
```

### Biometric (Passkey Setup)

```bash
# Begin biometric setup (new passkey for MFA)
curl -X POST "$BASE/authsec/biometric/beginSetup" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Confirm biometric setup
curl -X POST "$BASE/authsec/biometric/confirmSetup" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","credential":{...}}'

# Begin biometric login setup
curl -X POST "$BASE/authsec/biometric/beginLoginSetup" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Confirm biometric login setup
curl -X POST "$BASE/authsec/biometric/confirmLoginSetup" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","credential":{...}}'

# Begin biometric verify (MFA challenge)
curl -X POST "$BASE/authsec/biometric/verifyBegin" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Finish biometric verify
curl -X POST "$BASE/authsec/biometric/verifyFinish" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","credential":{...}}'

# Begin biometric login verify
curl -X POST "$BASE/authsec/biometric/verifyLoginBegin" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Finish biometric login verify
curl -X POST "$BASE/authsec/biometric/verifyLoginFinish" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","credential":{...}}'
```

### Admin WebAuthn  `/webauthn/admin`

```bash
# MFA status (admin user)
curl -X POST "$BASE/authsec/admin/mfa/status" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Begin registration (admin)
curl -X POST "$BASE/authsec/admin/beginRegistration" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"admin@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Finish registration (admin)
curl -X POST "$BASE/authsec/admin/finishRegistration" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"admin@example.com","tenant_id":"'"$TENANT_ID"'","credential":{...}}'

# Begin authentication (admin)
curl -X POST "$BASE/authsec/admin/beginAuthentication" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"admin@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Finish authentication (admin)
curl -X POST "$BASE/authsec/admin/finishAuthentication" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"admin@example.com","tenant_id":"'"$TENANT_ID"'","credential":{...}}'
```

### End-User WebAuthn  `/webauthn/enduser`

```bash
# MFA status (end-user, uses tenant DB)
curl -X POST "$BASE/authsec/enduser/mfa/status" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Begin registration (end-user)
curl -X POST "$BASE/authsec/enduser/beginRegistration" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Finish registration (end-user)
curl -X POST "$BASE/authsec/enduser/finishRegistration" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","credential":{...}}'

# Begin authentication (end-user)
curl -X POST "$BASE/authsec/enduser/beginAuthentication" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Finish authentication (end-user)
curl -X POST "$BASE/authsec/enduser/finishAuthentication" \
  -H "Content-Type: application/json" \
  -H "Origin: https://app.authsec.dev" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","credential":{...}}'
```

### TOTP (WebAuthn service)  `/webauthn/totp`

```bash
# Begin login TOTP setup
curl -X POST "$BASE/authsec/totp/beginLoginSetup" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'

# Begin TOTP setup
curl -X POST "$BASE/authsec/totp/beginSetup" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'"}'

# Confirm login TOTP setup
curl -X POST "$BASE/authsec/totp/confirmLoginSetup" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","secret":"<base32>","code":"123456"}'

# Confirm TOTP setup
curl -X POST "$BASE/authsec/totp/confirmSetup" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'","secret":"<base32>","code":"123456"}'

# Verify login TOTP
curl -X POST "$BASE/authsec/totp/verifyLogin" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","code":"123456"}'

# Verify TOTP
curl -X POST "$BASE/authsec/totp/verify" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'","code":"123456"}'
```

### SMS MFA  `/webauthn/sms`

```bash
# Begin SMS setup (send code to phone)
curl -X POST "$BASE/authsec/sms/beginSetup" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'","phone_number":"+15551234567"}'

# Confirm SMS setup
curl -X POST "$BASE/authsec/sms/confirmSetup" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'","phone_number":"+15551234567","code":"123456"}'

# Request SMS code (for login)
curl -X POST "$BASE/authsec/sms/requestCode" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'"}'

# Verify SMS code
curl -X POST "$BASE/authsec/sms/verify" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'","code":"123456"}'
```

---

## HubSpot Integration

```bash
curl -X POST "$BASE/authsec/hubspot/contacts/sync" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","tenant_id":"'"$TENANT_ID"'"}'
```

---

## API Documentation

```bash
# Swagger UI
open "$BASE/authsec/swagger/index.html"

# ReDoc UI
open "$BASE/authsec/docs"

# API info
curl "$BASE/authsec/apidocs"
```

---

## External Services  `/authsec/services`

Manages external service registrations with credentials stored in HashiCorp Vault.
Requires `external-service` RBAC permissions seeded per tenant on first access.

```bash
# Create a service (stores secret_data in Vault)
curl -X POST "$BASE/authsec/services" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "GitHub API",
    "type": "api",
    "url": "https://api.github.com",
    "description": "GitHub REST API integration",
    "tags": ["git", "ci"],
    "resource_id": "'"$RESOURCE_UUID"'",
    "auth_type": "api_key",
    "agent_accessible": true,
    "secret_data": {
      "api_key": "ghp_xxxxxxxxxxxx"
    }
  }'

# List services (for authenticated client)
curl "$BASE/authsec/services" \
  -H "Authorization: Bearer $TOKEN"

# Get service by ID
curl "$BASE/authsec/services/$SERVICE_ID" \
  -H "Authorization: Bearer $TOKEN"

# Update a service
curl -X PUT "$BASE/authsec/services/$SERVICE_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "GitHub API v2",
    "url": "https://api.github.com/v2",
    "secret_data": {
      "api_key": "ghp_yyyyyyyyyyyyyy"
    }
  }'

# Delete a service (also removes Vault secret)
curl -X DELETE "$BASE/authsec/services/$SERVICE_ID" \
  -H "Authorization: Bearer $TOKEN"

# Get service credentials (reads from Vault)
curl "$BASE/authsec/services/$SERVICE_ID/credentials" \
  -H "Authorization: Bearer $TOKEN"

# Debug: dump JWT claims
curl "$BASE/authsec/debug/extsvc/auth" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Client Management  `/clientms`

Manages multi-tenant client registrations. Formerly the standalone `clients-microservice`, now merged into authsec.
Requires `clients` RBAC permissions (seeded automatically per-tenant on first client creation).

```bash
CLIENT_MS="http://localhost:7468"
CLIENT_ID="<client-uuid>"
```

### Health

```bash
curl "$CLIENT_MS/clientms/health"
```

### List Clients  `GET /clientms/tenants/:tenantId/clients/getClients`

```bash
# List all clients for a tenant (paginated)
curl "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/getClients" \
  -H "Authorization: Bearer $TOKEN"

# With filters
curl "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/getClients?status=Active&page=1&limit=20" \
  -H "Authorization: Bearer $TOKEN"

# Filter by active only
curl "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/getClients?active_only=true" \
  -H "Authorization: Bearer $TOKEN"

# Include soft-deleted clients
curl "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/getClients?deleted=true" \
  -H "Authorization: Bearer $TOKEN"

# Legacy POST route (body-based tenant filter)
curl -X POST "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/getClients" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'","active_only":false}'
```

### Get Client  `GET /clientms/tenants/:tenantId/clients/:id`

```bash
curl "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/$CLIENT_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### Create Client  `POST /clientms/tenants/:tenantId/clients/create`

```bash
curl -X POST "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/create" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "email": "myapp@example.com",
    "active": true,
    "status": "Active",
    "tags": ["web", "production"],
    "oidc_enabled": false
  }'
```

### Register Client (full registration with Hydra + Vault)  `POST /clientms/tenants/:tenantId/clients/register`

> Note: Uses the legacy RegisterClient route which also creates a Vault secret and registers with Hydra.

```bash
# The RegisterClient endpoint is wired via the route group;
# use CreateClient above for standard creation without Hydra/Vault.
```

### Update Client  `PUT /clientms/tenants/:tenantId/clients/:id`

```bash
curl -X PUT "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/$CLIENT_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated App Name",
    "status": "Active",
    "tags": ["web", "v2"]
  }'
```

### Edit Client (partial update)  `PATCH /clientms/tenants/:tenantId/clients/:id`

```bash
curl -X PATCH "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/$CLIENT_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Patched Name"}'
```

### Soft Delete Client  `PATCH /clientms/tenants/:tenantId/clients/:id/soft-delete`

```bash
curl -X PATCH "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/$CLIENT_ID/soft-delete" \
  -H "Authorization: Bearer $TOKEN"
```

### Delete Client (soft delete via DELETE)  `DELETE /clientms/tenants/:tenantId/clients/:id`

```bash
curl -X DELETE "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/$CLIENT_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### Hard Delete Client  `POST /clientms/tenants/:tenantId/clients/delete-complete`

Permanently removes the client from both tenant DB and main DB, and cleans up Hydra via OOC Manager.

```bash
curl -X POST "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/delete-complete" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'"}'
```

### Activate Client  `PATCH /clientms/tenants/:tenantId/clients/:id/activate`

```bash
curl -X PATCH "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/$CLIENT_ID/activate" \
  -H "Authorization: Bearer $TOKEN"
```

### Deactivate Client  `PATCH /clientms/tenants/:tenantId/clients/:id/deactivate`

```bash
curl -X PATCH "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/$CLIENT_ID/deactivate" \
  -H "Authorization: Bearer $TOKEN"
```

### Set Client Status  `POST /clientms/tenants/:tenantId/clients/set-status`

```bash
curl -X POST "$CLIENT_MS/clientms/tenants/$TENANT_ID/clients/set-status" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'","active":true}'
```

### Admin — List All Clients  `GET /clientms/admin/clients/`

Requires `clients:admin` permission.

```bash
curl "$CLIENT_MS/clientms/admin/clients/" \
  -H "Authorization: Bearer $TOKEN"
```

### OOC Manager Integration  `POST /clientms/oocmgr/tenant/delete-complete`

Internal service-to-service route for OOC Manager callbacks.

```bash
curl -X POST "$CLIENT_MS/clientms/oocmgr/tenant/delete-complete" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"'"$TENANT_ID"'","client_id":"'"$CLIENT_ID"'"}'
```

### API Documentation

```bash
# Swagger/Redoc docs (no auth required)
curl "$CLIENT_MS/clientms/swagger"
```
