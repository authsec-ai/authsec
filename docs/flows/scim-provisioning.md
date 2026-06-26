# Flow: SCIM Provisioning

> SCIM 2.0 user and group provisioning from an enterprise IdP (Okta, Azure AD, etc.)
> into an AuthSec workspace. Users and groups are pushed by the IdP; AuthSec syncs them.

## What SCIM does here

SCIM is **not** used for authentication — it's the provisioning channel. An enterprise
IdP uses SCIM to keep AuthSec's `users` and `groups` tables in sync with the corporate
directory. This means:
- New employees are auto-provisioned as workspace members.
- Departing employees are deprovisioned (their workspace memberships and sessions revoked).
- Group memberships stay in sync (for group-based RBAC role bindings).

## Tables

| Table | Purpose |
|---|---|
| `scim_connections` | One per workspace: the SCIM endpoint config (`bearer_token`, `enabled`, `idp_type`) |
| `scim_events` | Log of every SCIM operation (create/update/delete user/group) |
| `sync_configurations` | Sync settings per connection (field mappings, filters) |
| `sync_runs` | Audit of each full sync run (status, count, errors) |

## Endpoints (`controllers/platform/scim_controller.go`)

AuthSec exposes the SCIM 2.0 server-side endpoints at `/scim/v2/`:

| Endpoint | Operation |
|---|---|
| `GET /scim/v2/Users` | List users |
| `POST /scim/v2/Users` | Provision user |
| `GET /scim/v2/Users/:id` | Get user |
| `PUT /scim/v2/Users/:id` | Replace user |
| `PATCH /scim/v2/Users/:id` | Update user |
| `DELETE /scim/v2/Users/:id` | Deprovision user |
| `GET /scim/v2/Groups` | List groups |
| `POST /scim/v2/Groups` | Create group |
| `GET /scim/v2/Groups/:id` | Get group |
| `PUT /scim/v2/Groups/:id` | Replace group |
| `PATCH /scim/v2/Groups/:id` | Update group (members) |
| `DELETE /scim/v2/Groups/:id` | Delete group |

Authentication: the IdP presents a `Bearer <token>` — matched against
`scim_connections.bearer_token` (hashed) for the workspace.

## User provisioning lifecycle

1. IdP `POST /scim/v2/Users` → AuthSec creates `users` row + `workspace_memberships` row.
2. `oidc_user_identities` row linked if `externalId` maps to an OIDC sub.
3. IdP `DELETE /scim/v2/Users/:id` → user deprovisioned, `workspace_memberships` deleted,
   active sessions revoked.

## Group → RBAC integration

SCIM groups sync into `groups` and `user_groups`. These groups can then be used in
`role_bindings` (`subject_type='group'`). When a user's group memberships change via
SCIM, their effective RBAC scopes change automatically on next scope resolution.

## When you're building

- **New SCIM attribute mapping?** Edit `sync_configurations` field mapping + the
  `ScimController` attribute parser.
- **New IdP integration?** SCIM is IdP-agnostic; test with the standard SCIM 2.0 test suite.
- **Debugging a missed sync?** Check `scim_events` (per-operation log) + `sync_runs`
  (per-run status). SCIM operations are logged even when AuthSec side-effects fail.

## Related

`primitives/rbac-scopes.md` (groups in role_bindings), `primitives/identity-principals.md`
(user identity lifecycle), `primitives/schema.md` (scim_* tables).
