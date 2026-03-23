# Runtime QA Curls

Use these against a real running environment. They are written to be easy to import into Postman one by one.

## Variables

Set these first in your shell:

```bash
export BASE_URL="http://localhost:7468"
export ADMIN_TOKEN="<admin-jwt>"
export USER_TOKEN="<enduser-jwt>"
export TENANT_ID="<tenant-uuid>"
export CLIENT_ID="<client-uuid>"
export PROJECT_ID="<project-uuid>"
export ADMIN_EMAIL="<admin@example.com>"
export USER_EMAIL="<user@example.com>"
```

For the local compose seed, these concrete values work:

```bash
export TENANT_ID="11111111-1111-1111-1111-111111111111"
export ADMIN_EMAIL="admin@test.com"
```

## Admin Login

Use the seeded local admin account to get a real JWT before running the admin
checks below.

```bash
curl -sS -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com","password":"test@Admin1234","tenant_domain":"test.authsec.dev"}' \
  "$BASE_URL/authsec/uflow/auth/admin/login"
```

## Migration API

These endpoints are now admin-gated.

```bash
curl -i \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/authsec/migration/migrations/master/status"
```

```bash
curl -i -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/authsec/migration/migrations/master/run"
```

```bash
curl -i \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/authsec/migration/tenants"
```

```bash
curl -i \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/authsec/migration/tenants/template-status"
```

Negative check:

```bash
curl -i "$BASE_URL/authsec/migration/migrations/master/status"
```

## Admin MFA Status

```bash
curl -i -X POST \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$ADMIN_EMAIL\"}" \
  "$BASE_URL/authsec/webauthn/admin/mfa/status"
```

```bash
curl -i -X POST \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$ADMIN_EMAIL\"}" \
  "$BASE_URL/authsec/webauthn/admin/mfa/loginStatus"
```

```bash
curl -i \
  "$BASE_URL/authsec/webauthn/admin/mfa/loginStatus?email=$ADMIN_EMAIL"
```

What to verify:

- If WebAuthn is configured on the current domain, response should show MFA required without `requires_registration=true`.
- If credentials only exist on another RP ID, response should show the re-registration signal.

## End-User MFA Status

```bash
curl -i -X POST \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$USER_EMAIL\",\"tenant_id\":\"$TENANT_ID\"}" \
  "$BASE_URL/authsec/webauthn/enduser/mfa/status"
```

```bash
curl -i -X POST \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$USER_EMAIL\",\"tenant_id\":\"$TENANT_ID\"}" \
  "$BASE_URL/authsec/webauthn/enduser/mfa/loginStatus"
```

```bash
curl -i \
  -H "Authorization: Bearer $USER_TOKEN" \
  "$BASE_URL/authsec/uflow/auth/tenant/totp/devices"
```

What to verify:

- WebAuthn detection should follow the current host RP ID.
- Users with TOTP should not be forced into WebAuthn re-registration just because legacy MFA metadata is missing.

## Auth Manager RBAC

These are the direct permission-first checks for the seeded admin role.

```bash
curl -i \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/authsec/authmgr/admin/permissions"
```

```bash
curl -i \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/authsec/authmgr/admin/check/permission?resource=admin&scope=manage"
```

```bash
curl -i \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/authsec/authmgr/admin/validate/scope"
```

What to verify:

- `/authmgr/admin/permissions` returns the seeded direct permission set.
- `/authmgr/admin/check/permission` succeeds from direct `role_permissions` without any named scopes.
- `/authmgr/admin/validate/scope` is diagnostic only and does not block the request.

## Unified Scopes

These confirm the V3 unified scope model:

```bash
curl -i \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/authsec/uflow/admin/scopes"
```

```bash
curl -i \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/authsec/uflow/admin/scopes/mappings"
```

```bash
curl -i \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/authsec/uflow/admin/api_scopes"
```

What to verify:

- `/scopes` lists only internal or `both` scopes.
- `/api_scopes` lists only OAuth or `both` scopes.
- `/scopes/mappings` is computed from `scopes -> scope_permissions -> permissions`; there is no physical mapping table.

## External Service RBAC

These validate the narrowed seeded permission surface.

```bash
curl -i \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/authsec/exsvc/services"
```

```bash
curl -i -X POST \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"qa-service","type":"http","base_url":"https://example.com"}' \
  "$BASE_URL/authsec/exsvc/services"
```

## Client Admin RBAC

```bash
curl -i \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/clientms/admin/clients/"
```

## SCIM / Project Path Sanity

`project_id` is still part of the live path surface. Do not remove it blindly until these are redesigned.

```bash
curl -i \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/authsec/uflow/scim/v2/$CLIENT_ID/$PROJECT_ID/Users"
```

```bash
curl -i \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/authsec/uflow/scim/v2/$CLIENT_ID/$PROJECT_ID/Groups"
```

## Cleanup Verification

After applying the new credential ownership migration, verify the schema directly:

```bash
psql "$DATABASE_URL" -c "\d+ credentials"
```

What to verify:

- `credentials.user_id` exists.
- `credentials.rp_id` exists.
- New credential writes populate `user_id`.
- Legacy credential rows were backfilled where ownership could be inferred.
