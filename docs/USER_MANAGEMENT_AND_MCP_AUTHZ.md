# User Management and MCP Authorization

> Audience: AuthSec product/engineering.
> Scope: how solo developers, small teams, public MCP providers, and enterprises should manage users, roles, scopes, groups, and MCP tool authorization in AuthSec.
> Decision: in AuthSec v2, `tenant` is the canonical account/workspace/operator boundary. All user management, role assignment, MCP resource-server registration, consent, policy, and audit are scoped to a tenant.

---

## 1. V2 Decision

AuthSec v2 uses `tenant` as the only top-level administrative and security boundary.

Everything below is tenant-scoped:

- users and service accounts
- memberships
- groups
- roles
- permissions
- role bindings
- resource servers
- OAuth scopes
- OAuth clients
- consent grants
- MCP tools
- policy decisions
- audit events

Therefore:

- Use `tenant_id` as the canonical boundary in code, APIs, tokens, and docs.
- Add a membership model under tenant for lifecycle and multi-account flexibility.
- Add group-based role bindings for bulk user management.
- Keep OAuth scopes separate from roles.
- Enforce MCP access at both token/scope resolution time and tool invocation time.
- Treat SCIM, SAML, Entra, Okta, and Active Directory as optional provisioning/login integrations, not as required architecture.

The target model is:

```text
tenant
  users / service accounts
  memberships
  groups
  roles
  permissions
  role bindings
  resource servers
  OAuth scopes
  MCP tools
  consent grants
  audit events
```

The main missing model is `membership`.

This document uses "tenant" for every adoption size:

```text
Solo developer tenant: one operator/admin, optional collaborators, and any number of external users.
Small team tenant: multiple operators/admins, collaborators, and optional external users.
Public MCP provider tenant: provider operates internet-facing MCP servers for external users and clients.
Enterprise tenant: thousands of users, SCIM/SSO/groups/admin delegation.
```

SCIM, Active Directory, Entra, and Okta are optional enterprise integrations. They are not required for the core AuthSec model.

---

## 2. Canonical Tenant Model

### 2.1 What a Tenant Represents

A tenant is the AuthSec account/workspace/operator boundary.

The same tenant model covers different adoption sizes:

```text
Solo developer:
  tenant = alex-tools
  operators/admins = one owner, optional collaborators
  end users = any number of public users consuming the MCP server
  MCP servers = public or private servers owned by the developer
  OAuth clients = known clients and third-party AI clients

Small team:
  tenant = indie-agent-labs
  operators/admins = owner plus collaborators
  end users = internal users, beta users, or public users depending on product
  MCP servers = internal or public team servers
  roles = Owner, Developer, Viewer

Public MCP provider:
  tenant = public-weather-mcp-provider
  operators/admins = provider admins and app reviewers
  end users = external users consuming the public MCP servers
  MCP servers = internet-facing resource servers
  OAuth clients = first-party app, known clients, third-party client registrations

Large company:
  tenant = acme-corp
  operators/admins = security, platform, user, auditor admins
  end users = employees, contractors, service accounts
  MCP servers = internal and public-facing MCP servers
  groups = Engineering, Finance, Security, Support
```

Operator size and user count are separate. A solo developer can operate a public MCP server used by thousands of external users, the same way a small Firebase or Clerk-backed app can have one maintainer and many customers.

### 2.2 Tenant-Owned Objects

Every object that can affect access must carry `tenant_id` or be reachable from a tenant-scoped parent.

```text
tenant
  members
  groups
  roles
  permissions
  role_bindings
  resource_servers
  oauth_scopes
  mcp_tools
  oauth_clients
  consent_grants
  audit_events
```

Access checks should always start by resolving:

```text
tenant_id
subject_id
subject_type
resource_server_id
client_id
requested_scope
requested_tool
requested_action
```

### 2.3 Tenant Membership

Today, AuthSec users carry `tenant_id` directly. That works when a user belongs to exactly one tenant. A separate membership table gives cleaner lifecycle and audit for every adoption size, not just enterprise.

Recommended table:

```sql
CREATE TABLE tenant_memberships (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  user_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'active',
  membership_type text NOT NULL DEFAULT 'human',
  source text NOT NULL DEFAULT 'manual',
  external_id text,
  invited_by uuid,
  joined_at timestamptz,
  suspended_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, user_id)
);
```

This lets AuthSec answer:

- Is this user active in this tenant?
- Was this user created by signup, OAuth/OIDC login, SAML JIT, API, manual invite, or SCIM?
- Who invited or suspended the user?
- Can the same human identity belong to multiple tenants later?
- Can we suspend tenant access without deleting the login identity?
- Is this an internal admin, external end user, service operator, contractor, or service account owner?

Initial migration can be simple:

```text
for each users row with tenant_id:
  insert tenant_memberships(tenant_id, user_id, status='active', source='migration')
```

Recommended membership types:

```text
owner
admin
member
external_user
contractor
service_operator
readonly_auditor
```

Membership type is not a replacement for RBAC. It is lifecycle metadata. Authorization still comes from roles and policy.

### 2.4 Identity and Per-Tenant Login Providers

Users need a login identity before they can receive tenant membership and role bindings. AuthSec v2 should separate global identity from tenant membership.

Recommended model:

```text
identities:
  stable human/service identity across tenants.

identity_providers:
  Google, GitHub, SAML, OIDC, or AuthSec local identity.

authsec_local_credentials:
  password, passkey/WebAuthn, magic-link.

identity_links:
  identity_id + provider + provider_subject.

users:
  tenant-local user profile linked to global identity_id.

tenant_memberships:
  tenant-local user belongs to a tenant with lifecycle state.
```

Per-tenant IdP configuration:

```text
tenant_id
provider_type = google | github | oidc | saml | authsec_local
issuer
client_id
encrypted_client_secret
allowed_domains
jit_provisioning_enabled
default_role_id
default_membership_type
attribute_mapping
enabled

authsec_local_credentials = password | passkey | magic_link
```

Solo developer flow:

```text
1. Alex enables "Sign in with Google" for tenant alex-tools.
2. Alex chooses default role Free User for newly created external users.
3. Public user signs in with Google.
4. AuthSec creates or finds global identity by provider subject.
5. AuthSec creates or finds tenant-local users row linked to identity_id.
6. AuthSec creates tenant_membership in alex-tools for that user_id.
7. AuthSec applies default role binding and continues OAuth consent.
```

Cross-tenant identity:

```text
Same human can have one global identity and multiple tenant_memberships.
Each tenant controls that user's roles, consent grants, activity visibility, and lifecycle inside the tenant.
Deleting membership from one tenant does not delete the global identity if the user belongs to other tenants.
In v2, tenant_memberships.user_id references the tenant-local users row; users.identity_id links back to global identities.
```

Account merge:

```text
1. User proves control of both identities.
2. AuthSec merges identity_links.
3. Tenant memberships, consents, and audit history are re-associated or linked by merge record.
4. Old identity is tombstoned, not silently deleted.
```

Merge conflict rules:

```text
Same tenant, two memberships:
  require manual review if statuses or high-risk roles differ.
  active beats invited/pending, but suspended/disabled is never silently overridden.

Role bindings:
  default to union for low-risk roles.
  admin/security roles require explicit admin approval during merge.

Consent grants:
  deduplicate exact same client + resource + scope grants.
  keep broader grant only if still valid and not revoked.

Audit:
  pre-merge events keep original identity_id and add merged_into_identity_id.
  do not rewrite historical actor fields.

Reversibility:
  allow undo within short grace window if no high-risk action occurred after merge.
```

Identity tombstone retention:

```text
If the last tenant membership is deleted, identity enters tombstoned state.
Default tombstone retention is tenant/legal-policy dependent, for example 30-90 days.
New login with the same provider_subject during tombstone window can restore identity if policy allows it.
After purge, the same provider_subject creates a new identity with no old grants.
```

Custom token claims:

```text
Tenant admins may map selected user/profile attributes into access tokens.
Only allowlisted claims are emitted.
AuthSec reserves standard/OIDC/AuthSec claim names.
Large or sensitive claims should stay behind introspection/PDP lookup, not be copied into every JWT.
```

Per-resource-server claim policy:

```text
resource_server_id
claim_name
source = identity_attribute | membership_attribute | group | static | external_lookup
source_path
include_in_access_token = true | false
include_in_introspection = true | false
sensitivity = low | medium | high
required_scope_or_permission
```

Rules:

```text
Claims are configured per tenant and resource server.
Claims must be namespaced unless they are registered standards claims.
High-sensitivity claims require introspection/PDP lookup instead of JWT embedding.
Claim changes apply to newly issued tokens; emergency removal requires token revocation if old tokens include the claim.
JWT custom claims have a size budget; token issuance fails with token_claims_too_large if projected token size exceeds policy.
Duplicate claim names are rejected unless an explicit precedence rule is configured.
external_lookup claims must have timeout, cache TTL, and failure behavior: fail issuance or omit optional claim.
Audit, webhook, and decision traces redact claim values according to per-claim sensitivity.
```

---

## 3. Roles, Permissions, Scopes, and Groups

These concepts overlap visually in admin UIs, but they serve different layers.

### 3.1 Permission

A permission is the internal enforcement atom. It is what the AuthSec PDP checks.

Good permission names:

```text
resource_server.read
resource_server.manage
mcp.tool.list
mcp.tool.call
mcp.tool.admin
oauth_client.approve
audit_log.read
user.invite
user.suspend
role_binding.create
github.pr.read
github.pr.write
slack.message.send
snowflake.query.read
```

Permissions should be stable and product-domain oriented. Avoid UI-shaped permissions like:

```text
settings_page.open
button_approve_client.click
left_nav.billing.visible
```

### 3.2 Role

A role is an admin-facing bundle of permissions.

Example roles:

```text
Owner
Security Admin
User Admin
MCP Admin
MCP Viewer
GitHub MCP Writer
Slack MCP Sender
Snowflake Readonly Analyst
```

Admins should assign roles, not 100 individual scopes.

Example:

```text
Role: GitHub MCP Writer
Permissions:
  mcp.tool.list
  mcp.tool.call
  github.repo.read
  github.pr.read
  github.pr.write
```

### 3.3 OAuth Scope

An OAuth scope is the external token contract between an OAuth client and a resource server.

Scopes should be coarse enough to be understandable and stable:

```text
mcp:tools:list
mcp:tools:read
mcp:tools:write
mcp:tools:admin
github.repo:read
github.pr:write
slack.message:send
snowflake.query:read
```

Do not create one OAuth scope per database row, Jira issue, Slack channel, or GitHub repository. That creates scope explosion.

Object-specific restrictions belong in policy conditions or tool argument policy, not in OAuth scope names.

Bad:

```text
github.repo.authsec-api.read
github.repo.authsec-api.pr.123.write
slack.channel.C123456.send
```

Better:

```text
Scope: github.pr:write
Condition:
  allowed_repos = ["authsec-api", "authsec-web"]
  max_risk = "medium"
```

### 3.4 Group

A group is a collection of users. It should not be a permission by itself.

Enterprise practice:

```text
IdP group -> AuthSec group -> role binding -> permissions -> OAuth scopes
```

Example:

```text
Okta group: Acme Engineering MCP Writers
AuthSec group: engineering-mcp-writers
Role binding:
  group_id = engineering-mcp-writers
  role = GitHub MCP Writer
  scope_type = resource_server
  scope_id = github-mcp
```

This is how thousands of users become manageable. The admin manages 20-100 groups and roles, not 12,000 users individually.

Vestigial group-role paths should be ignored or removed. The future path should be group support in `role_bindings`.

---

## 4. Standards and Industry Practice

### 4.1 RBAC: Roles Bundle Permissions

NIST RBAC defines the core idea: users are assigned to roles, roles are assigned permissions, and users get permissions through roles. RBAC is still the normal enterprise admin model because it is understandable and auditable.

AuthSec mapping:

```text
NIST RBAC user       -> AuthSec user
NIST RBAC role       -> AuthSec roles
NIST RBAC permission -> AuthSec permissions(resource, action)
NIST user-role       -> AuthSec role_bindings
NIST role-permission -> AuthSec role_permissions
```

AuthSec already has most of this.

Required v2 improvement:

```text
role_bindings supports user_id, group_id, or service_account_id as the principal.
Exactly one principal column must be non-null.
```

Today, bindings are effectively user/service-account oriented. Enterprise scale needs group bindings.

Reference:

- NIST RBAC FAQ: https://csrc.nist.gov/projects/role-based-access-control/faqs

### 4.2 ABAC: Conditions and Guardrails

ABAC makes decisions using attributes of:

- subject: user, group, department, MFA state
- object: MCP tool, resource server, data classification
- action: read, write, delete, approve
- environment: IP, device, time, risk level

AuthSec should not expose arbitrary ABAC expressions as the primary admin UX. Use ABAC as conditions under role bindings and tool policy.

Example:

```json
{
  "mfa_required": true,
  "allowed_ip_cidrs": ["10.0.0.0/8"],
  "allowed_repos": ["authsec-api", "authsec-web"],
  "max_risk_level": "medium"
}
```

Reference:

- NIST SP 800-162 ABAC: https://csrc.nist.gov/pubs/sp/800/162/upd2/final

### 4.3 SCIM: Optional Provisioning for Larger Customers

SCIM is the standard provisioning protocol for users and groups in larger tenants. It should be optional. A solo developer, small team, or public MCP provider may use normal signup, invitations, OIDC login, API-created users, or marketplace onboarding instead.

SCIM practice:

```text
Entra / Okta / OneLogin
  -> SCIM Users
  -> SCIM Groups
  -> AuthSec users and groups
  -> AuthSec group role bindings
```

SCIM should create/update/suspend users and groups. SCIM should not automatically grant powerful AuthSec roles just because a group name exists. Admins should map imported groups to roles.

Non-SCIM practice:

```text
Email/password signup
Google/GitHub/OIDC login
Manual team invites
API-created users
Public OAuth consent
Plan/subscription-based membership
```

Reference:

- SCIM Protocol RFC 7644: https://www.rfc-editor.org/rfc/rfc7644
- SCIM Schema RFC 7643: https://www.rfc-editor.org/rfc/rfc7643

### 4.4 OAuth Resource Indicators: Token Audience

For MCP, each MCP server is an OAuth protected resource. Tokens must be audience-bound to that MCP server.

AuthSec mapping:

```text
MCP server URL -> resource_servers.resource_uri
OAuth resource parameter -> resource_servers.resource_uri
Access token aud -> same resource URI
```

Example:

```text
resource = https://mcp.acme.internal/github
scope = mcp:tools:write github.pr:write
```

The token must not be accepted by:

```text
https://mcp.acme.internal/slack
```

Reference:

- RFC 8707 Resource Indicators: https://www.rfc-editor.org/rfc/rfc8707

### 4.5 Protected Resource Metadata

MCP authorization depends on resource server metadata discovery. MCP servers publish where their authorization server is and what scopes are relevant.

AuthSec mapping:

```text
resource_servers
  resource_uri
  authorization_servers
  scopes_supported
  jwks/introspection config
```

Reference:

- RFC 9728 Protected Resource Metadata: https://www.rfc-editor.org/rfc/rfc9728
- MCP Authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

### 4.6 MCP Authorization

The MCP spec models:

```text
MCP client          -> OAuth client
MCP server          -> OAuth resource server
Authorization server -> AuthSec / Hydra-backed AS
User/resource owner -> tenant user or external end user
```

AuthSec should enforce:

```text
requested scopes
∩ resource server supported scopes
∩ user/group-derived effective scopes
∩ client approval
∩ consent/admin grant
∩ tool policy
```

AuthSec already does part of this in `ScopeResolver`:

```text
requested_scopes ∩ RS.scopes_supported ∩ user_effective_scopes
```

The missing part is richer group-derived effective scopes and runtime tool policy.

Reference:

- MCP Authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- MCP Tools: https://modelcontextprotocol.io/specification/2025-11-25/server/tools

### 4.7 Rich Authorization Requests

OAuth scopes are strings. They are not good for fine-grained details like repo allowlists, transaction limits, tool arguments, or data classifications.

RFC 9396 Rich Authorization Requests add structured `authorization_details`.

AuthSec does not need this immediately, but it is a good future model for tool-specific requests.

Example future authorization detail:

```json
{
  "type": "mcp_tool_call",
  "resource": "https://mcp.acme.internal/github",
  "tool": "create_pull_request",
  "actions": ["write"],
  "locations": ["repo:authsec-api", "repo:authsec-web"],
  "max_risk": "medium"
}
```

Reference:

- RFC 9396 Rich Authorization Requests: https://www.rfc-editor.org/rfc/rfc9396

### 4.8 OAuth Lifecycle Standards AuthSec Must Expose

Public MCP providers and AI clients need more than authorization-code issuance. AuthSec v2 should document and expose the full OAuth lifecycle surface.

Required standards:

```text
RFC 7591 Dynamic Client Registration:
  third-party AI clients can register programmatically when tenant policy allows it.

RFC 7592 Dynamic Client Registration Management:
  registered clients can rotate metadata, redirect URIs, and keys under policy.

RFC 7662 Token Introspection:
  MCP resource servers can validate opaque tokens or ask AuthSec for active token metadata.

RFC 7009 Token Revocation:
  users and admins can revoke refresh/access tokens and client grants.

RFC 9470 Step-Up Authentication Challenge:
  resource servers can ask clients to re-authorize with stronger auth.

RFC 8693 Token Exchange:
  agent and MCP-to-MCP delegation can exchange a user-bound token for a downstream audience.

RFC 9449 DPoP:
  public clients and MCP servers can reduce replay risk with sender-constrained tokens.
```

Reference:

- RFC 7591 Dynamic Client Registration: https://www.rfc-editor.org/rfc/rfc7591
- RFC 7592 Dynamic Client Registration Management: https://www.rfc-editor.org/rfc/rfc7592
- RFC 7662 Token Introspection: https://www.rfc-editor.org/rfc/rfc7662
- RFC 7009 Token Revocation: https://www.rfc-editor.org/rfc/rfc7009
- RFC 9470 Step-Up Authentication Challenge: https://www.rfc-editor.org/rfc/rfc9470
- RFC 8693 Token Exchange: https://www.rfc-editor.org/rfc/rfc8693
- RFC 9449 DPoP: https://www.rfc-editor.org/rfc/rfc9449
- RFC 7636 PKCE: https://www.rfc-editor.org/rfc/rfc7636
- WebAuthn: https://www.w3.org/TR/webauthn-3/

---

## 5. Architecture Decisions

These decisions remove ambiguity for implementers. They are v2 defaults unless a tenant/resource-server policy explicitly chooses a stricter path.

### 5.1 PDP Shape and API Contract

AuthSec's PDP is a control-plane API exposed by AuthSec and wrapped by SDKs. It is not only an in-process library in the MCP server.

Default:

```text
AuthSec AS/control plane owns policy evaluation.
MCP server SDK calls AuthSec PDP for tools/call authorization.
SDK may cache low-risk allow decisions only when policy permits it.
Write/admin/destructive/data-export tools call PDP or introspection every time.
```

PDP request:

```json
{
  "tenant_id": "tenant-uuid",
  "subject": {
    "type": "user",
    "id": "user-uuid"
  },
  "client_id": "client-id",
  "resource_server_id": "rs-uuid",
  "resource": "https://mcp.example.com/github",
  "tool": {
    "id": "tool-uuid",
    "name": "create_pull_request",
    "version": "2026-05-01"
  },
  "action": "call",
  "scopes": ["mcp:tools:write", "github.pr:write"],
  "arguments_digest": "sha256:...",
  "context": {
    "ip": "203.0.113.10",
    "user_agent": "Claude Desktop",
    "mfa_age_seconds": 120,
    "correlation_id": "corr-uuid"
  },
  "dry_run": false
}
```

PDP response:

```json
{
  "decision_id": "dec-uuid",
  "allowed": false,
  "reason": "policy_denied",
  "message_key": "policy.repo_not_allowed",
  "required": {
    "scope": "github.pr:write",
    "acr_values": "urn:authsec:mfa",
    "step_up": false
  },
  "matched_bindings": ["binding-uuid"],
  "failed_conditions": ["allowed_repos"],
  "cache": {
    "cacheable": false,
    "max_age_seconds": 0
  }
}
```

Every denial returned to an AI client should include `decision_id`, `reason`, and `error_uri` or documentation URL.

PDP authentication:

```text
MCP server authenticates to PDP with resource-server service credential.
Credential may be mTLS, signed client assertion, or DPoP-bound service credential.
The user's access token is included as the subject token, not as the sole authentication mechanism for the MCP server.
AuthSec verifies both the RS credential and the user token/audience before evaluating policy.
```

PDP API operations:

```text
POST /v1/pdp/decide:
  one tool/action decision.

POST /v1/pdp/batch-decide:
  batch pre-flight for multiple tools/actions.

Headers:
  Authorization: Bearer <resource-server credential or assertion>
  AuthSec-Api-Version: 2026-05-01
  Idempotency-Key: optional for retries

Timeout:
  SDK default timeout should be low, for example 500-1000ms, tenant/resource configurable.
```

Latency model:

```text
Default deployment:
  regional AuthSec PDP endpoint near MCP server region.

Hot path:
  gRPC or HTTP keep-alive supported by SDK.

p99 target:
  document a concrete SLO before GA; high-risk synchronous decisions must be engineered to that SLO.

Fallback:
  fail closed for high-risk calls when PDP timeout occurs.
```

### 5.2 Activity Record Writer

Default:

```text
AuthSec writes decision records when PDP is called.
MCP servers write signed completion events after tool execution.
```

This creates two event classes:

```text
decision event:
  written by AuthSec, authoritative for allow/deny.

completion event:
  written by MCP server SDK, includes execution status, latency, output digest, redaction markers.
```

Low-risk tools may run with local SDK pre-check and asynchronous event submission. High-risk tools must use synchronous PDP.

Completion event transport:

```text
POST /v1/activity/completions:
  MCP server SDK submits completion event.

Required fields:
  decision_id
  tenant_id
  resource_server_id
  tool_id
  execution_status
  latency_ms
  output_digest
  redaction_markers
  completed_at

Reliability:
  SDK uses bounded local buffer and retry with backoff.
  dropped events emit local metric/log and can trigger health warning.
  completion event references the original PDP decision_id.
```

### 5.3 Control-Plane and Global Tables

Tenant data remains tenant-scoped, but AuthSec needs a control-plane store for cross-tenant objects.

Control-plane/global tables:

```text
identities
identity_links
global_client_registry
tenant_client_approvals
signing_keys / jwks metadata
revocation_index
token_exchange_records
webhook_delivery_log
support_impersonation_sessions
custom_domain_verifications
```

Tenant-scoped tables:

```text
tenant_memberships
groups
user_groups
roles
permissions
role_bindings
resource_servers
oauth_scopes
mcp_tools
consent_grants
tool_call_audit_events
quota_policies
quota_counters
```

Known public clients can have one global client identity and per-tenant/resource approvals. Tenant-owned first-party clients stay tenant-scoped.

Revocation distribution:

```text
Push:
  control plane publishes revocation/kill-switch changes to regional caches.

Pull:
  SDKs/resource servers poll revocation metadata when using JWT mode.

Introspection:
  always reads current revocation/emergency state or a strongly fresh regional cache.

Freshness:
  cache age is exposed in introspection/PDP metadata for debugging.
```

### 5.4 Notification Subsystem

AuthSec v2 requires a notification subsystem because invites, approvals, ownership transfer, break-glass, consent receipts, replay detection, and credential-expiry alerts all depend on it.

Default channels:

```text
email:
  AuthSec-managed transactional email through a provider such as SES/Postmark/SendGrid.

in-product:
  notification inbox for tenant admins and end users.

webhook:
  tenant-configured outbound events for automation/SIEM/billing.
```

Optional tenant channels:

```text
Slack / Teams:
  approval and security notifications.

BYO SMTP:
  v3 unless required by launch customers.

SMS:
  only for MFA/recovery where supported by tenant policy.
```

Email operations:

```text
Templates:
  AuthSec owns default templates and message keys.
  Tenant branding can override logo, product name, links, and approved localized copy.

Reputation:
  AuthSec-managed pool by default.
  high-volume tenants may require dedicated sending domain.

Bounce/complaint handling:
  suppress failed recipients and surface delivery status in admin UI.

Preferences:
  security/transactional notices are mandatory where legally permitted.
  marketing/product notices require opt-in/unsubscribe.
```

End-user security notifications:

```text
client connected
client disconnected
new high-risk consent
step-up requested
password/passkey changed
account merge requested/completed
token or consent revoked for security
```

### 5.5 Custom Domain and TLS Flow

Custom domain flow:

```text
1. Tenant admin requests auth.alextools.dev.
2. AuthSec creates domain verification challenge.
3. Tenant adds DNS TXT record for verification.
4. Tenant adds CNAME to AuthSec edge hostname.
5. AuthSec verifies DNS.
6. AuthSec provisions managed TLS certificate through ACME/managed CA.
7. AuthSec marks domain active only after certificate issuance and callback URL validation.
8. AuthSec renews certificate automatically and alerts before failures.
```

Apex domains are not the default. Use subdomains such as `auth.example.com`.

Custom-domain issuer migration:

```text
Discovery:
  custom domain serves /.well-known/oauth-authorization-server and OIDC discovery.

Issuer:
  new tokens use custom-domain issuer after activation.

Grace:
  resource servers accept old and new issuer during configured migration window.

Cookies:
  browser cookies are scoped to the custom auth domain; cross-domain dashboard sessions use standard OAuth redirects, not shared cookies.
```

---

## 6. Concrete Tenant Flows

The same data model should serve small and large users. What changes is which features are enabled.

```text
Solo developer:
  tenant, one operator, public/private resource servers, external users, OAuth clients, consent, audit

Small team:
  tenant, multiple operators, collaborators, direct role bindings, optional groups

Public MCP provider:
  tenant, public client policy, end-user consent, app review, plan roles, rate limits, abuse controls

Large company:
  tenant, SSO/SCIM, groups, delegated admins, group role bindings, advanced audit
```

### Case 0: Solo Developer With a Public MCP Server

Goal:

A solo developer publishes a public MCP server and wants OAuth, client registration, user accounts, consent, plan/rate-limit policy, and audit without running a full IAM stack.

Tenant:

```text
tenant = alex-tools
operator/admin = alex@example.com
end users = public users who connect through MCP clients
resource_server = https://mcp.alextools.dev/browser
MCP tools = read_page, click_link, fill_form, screenshot
OAuth clients = alex-web-console, Claude Desktop, Cursor, third-party agents
roles = Owner, Free User, Pro User, Suspended User
```

Admin setup flow:

```text
1. Alex signs up.
2. AuthSec creates tenant alex-tools.
3. AuthSec creates tenant_membership for Alex:
     user_id = alex
     tenant_id = alex-tools
     status = active
     membership_type = owner
     source = signup
4. AuthSec grants Alex Owner role at tenant scope.
5. Alex registers resource server https://mcp.alextools.dev/browser.
6. AuthSec stores resource server, supported scopes, and metadata endpoint config.
7. Alex scans/imports MCP tools.
8. AuthSec creates tool records and suggests scope mappings.
9. Alex marks tools public, scoped, paid, or admin-only.
10. Alex defines default external-user access:
      new users receive Free User role
      paid users receive Pro User role
      abusive users receive Suspended User role or disabled membership
11. Alex configures OAuth client policy:
      first-party clients: auto-approved
      known MCP clients: allow with user consent
      unknown clients: require review or deny
```

Role assignment:

```text
Owner:
  tenant.manage
  resource_server.manage
  oauth_client.approve
  oauth_scope.manage
  mcp.tool.admin
  audit_log.read

Free User:
  mcp.tool.list
  mcp.tool.call
  browser.page.read

Pro User:
  mcp.tool.list
  mcp.tool.call
  browser.page.read
  browser.page.write

Suspended User:
  no active permissions
```

Scope mapping:

```text
mcp:tools:list    -> mcp.tool.list
mcp:tools:read    -> browser.page.read
mcp:tools:write   -> browser.page.write
```

User flow:

```text
1. External user opens Claude Desktop or another MCP client.
2. Client connects to https://mcp.alextools.dev/browser.
3. MCP server returns 401 with protected resource metadata.
4. Client discovers AuthSec authorization server.
5. Client requests authorization:
     resource = https://mcp.alextools.dev/browser
     scope = mcp:tools:list mcp:tools:read
6. User signs in or creates an account.
7. AuthSec creates tenant_membership:
     membership_type = external_user
     source = oauth_signup
8. AuthSec assigns default Free User role if Alex enabled public signup.
9. User sees consent screen for the client and scopes.
10. AuthSec issues audience-bound token for the browser MCP server.
11. MCP server validates token and enforces tool policy.
```

Upgrade flow:

```text
1. User upgrades from free to paid in Alex's billing system.
2. Alex's billing system calls AuthSec's role-binding or entitlement API using a tenant-scoped service credential.
3. AuthSec removes or supersedes Free User binding.
4. AuthSec adds Pro User binding.
5. New tokens can receive Pro User scopes.
6. Existing tokens expire naturally or are revoked if immediate enforcement is required.
```

Fulfillment path:

```text
requested scope -> resource server supported scope -> user effective scope -> consent grant -> token scope -> tool policy
```

Edge cases:

```text
Unknown OAuth client:
  deny or put into app-review queue.

User requests write scope:
  grant only if user has Pro User role or another role that maps to write permission.

Tool becomes risky after update:
  mark tool unreviewed; block activation or require admin review.

Token stolen:
  audience binding limits use to this MCP server; short TTL limits impact.

User abuses public tool:
  suspend tenant_membership or apply per-user rate limit.

Alex wants invite-only beta:
  disable public signup; only invited memberships receive Free User or Pro User role.

Alex has 100,000 users:
  still one tenant; use indexes, pagination, audit retention, rate-limit tables, and async analytics.
```

### Case 0.1: Small Team Building Internal Agents

Goal:

A 12-person AI agent team has a few private MCP servers and wants to avoid shared admin accounts.

Tenant:

```text
tenant = orbital-agents
members = alice, bob, cara, dev team
resource_servers = github-mcp, browser-mcp, deploy-mcp
roles = Owner, Developer, Viewer, Deploy Operator
groups = optional
```

Admin setup flow:

```text
1. Alice creates tenant orbital-agents.
2. AuthSec grants Alice Owner role.
3. Alice registers private MCP servers:
     github-mcp
     browser-mcp
     deploy-mcp
4. Alice defines roles:
     Developer can use github/browser read-write tools.
     Viewer can list tools and perform read-only calls.
     Deploy Operator can invoke deploy tools with MFA.
5. Alice invites Bob and Cara.
6. Invited users accept and become active tenant members.
```

Direct role assignment:

```text
alice -> Owner on tenant
bob   -> Developer on github-mcp and browser-mcp
cara  -> Viewer on all MCP servers
dina  -> Deploy Operator on deploy-mcp, conditions require MFA
```

Optional group flow:

```text
1. Alice creates group backend-devs.
2. Alice adds Bob, Dina, and two other users.
3. Alice binds backend-devs -> Developer on github-mcp.
4. New backend developers only need group membership, not individual role bindings.
```

User flow:

```text
1. Bob logs into AuthSec through email/OIDC.
2. Bob's token/session carries tenant context orbital-agents.
3. Bob opens internal MCP client.
4. Client asks for github-mcp scopes.
5. AuthSec resolves Bob's effective scopes from direct and group bindings.
6. Bob receives token for github-mcp.
7. github-mcp accepts read/write tool calls within policy.
```

Edge cases:

```text
Bob leaves the team:
  set tenant_membership.status = suspended; all tenant access fails before role checks.

Cara is promoted:
  add Developer role binding; no user table mutation required.

Dina tries deploy without MFA:
  PDP returns step-up required.

Shared local MCP client asks for too many scopes:
  ScopeResolver grants only intersection of requested, RS-supported, and user-effective scopes.
```

### Case 0.2: Public MCP Provider With External Users

Goal:

A company operates public MCP servers for external AI clients and users. It does not use directory sync. It cares about public OAuth clients, consent, app review, abuse prevention, and paid-plan limits.

Tenant:

```text
tenant = data-tools-cloud
resource_servers:
  https://mcp.datatools.cloud/search
  https://mcp.datatools.cloud/reports
users:
  provider admins
  external end users from signup/OIDC
OAuth clients:
  first-party web app
  known AI clients
  third-party registered clients
roles:
  Provider Admin
  App Reviewer
  Free User
  Pro User
  Suspended User
```

Admin flow:

```text
1. Provider admin registers search and reports MCP resource servers.
2. Provider admin defines scopes:
     search.query:read
     reports.generate
     reports.export
3. Provider admin maps scopes to permissions.
4. Provider admin defines roles by plan:
     Free User -> search.query.read
     Pro User -> search.query.read + reports.generate
5. Provider admin configures public client policy:
     first-party clients auto-approved
     known clients allowed with consent
     unknown clients require app review
6. App Reviewer role can approve/deny third-party OAuth clients.
```

External user flow:

```text
1. User connects from an AI client.
2. Client requests resource https://mcp.datatools.cloud/search.
3. User signs up through email, Google, GitHub, or OIDC.
4. AuthSec creates external_user membership in data-tools-cloud.
5. Billing/plan service sets role:
     Free User or Pro User
6. User consents to the client and requested scopes.
7. AuthSec issues token with only plan-allowed scopes.
8. MCP server enforces per-tool and rate-limit policy.
```

Plan-based role fulfillment:

```text
Free User:
  permissions:
    mcp.tool.list
    search.query.read
  scopes:
    mcp:tools:list
    search.query:read
  policy:
    max_result_rows = 100
    rate_limit = 100/day

Pro User:
  permissions:
    mcp.tool.list
    search.query.read
    reports.generate
  scopes:
    mcp:tools:list
    search.query:read
    reports.generate
  policy:
    max_result_rows = 10000
    rate_limit = 5000/day
```

Edge cases:

```text
Third-party client asks for reports.export:
  require app review and user consent; optionally require Pro User role.

Free user tries reports.generate:
  deny because user effective scopes do not include reports.generate.

Known client becomes malicious:
  revoke client approval; future token requests fail.

User upgrades plan:
  replace Free User binding with Pro User binding; existing tokens expire naturally or are revoked.

Abuse detected:
  set user membership to suspended or add deny policy before RBAC allow.
```

### Case 1: Large Company With 12,000 Employees, 18 Admins, 30 MCP Servers

Goal:

Only the right teams can use write-capable MCP tools. Admins must delegate management without making everyone an Owner.

Tenant:

```text
tenant = acme-corp
users = employees, contractors, service accounts
admins = security/platform/user/auditor admins
resource_servers = github-mcp, slack-mcp, jira-mcp, snowflake-mcp
groups = Engineering, Finance, Security, Support, Contractors
roles = Owner, Security Admin, User Admin, MCP Admin, MCP Viewer, GitHub PR Writer
```

Admin setup flow:

```text
1. Primary admin creates tenant acme-corp.
2. AuthSec grants primary admin Owner.
3. Security Admin configures OIDC/SAML login.
4. User Admin configures optional SCIM import.
5. SCIM or API creates users and groups:
     Engineering
     Finance
     Security
     Support
     Contractors
6. MCP Admin registers resource servers:
     github-mcp
     slack-mcp
     jira-mcp
     snowflake-mcp
7. MCP Admin imports tool inventory and approves tool-scope mappings.
8. Security Admin reviews high-risk tools and client policies.
```

Group and role assignment:

```text
Engineering -> GitHub PR Writer on github-mcp
Finance     -> Snowflake Readonly on snowflake-mcp
Support     -> Slack Sender on slack-mcp
Security    -> MCP Admin on all MCP resource servers
Contractors -> MCP Viewer on github-mcp, expires_at set
```

Admin delegation:

```text
Owner:
  full tenant management

Security Admin:
  SSO/SCIM/client approval/audit/security policy

User Admin:
  invite/suspend users, manage groups, cannot approve OAuth clients

MCP Admin:
  manage resource servers, tools, scopes, role templates

Auditor:
  read audit logs and effective-access reports only
```

Employee user flow:

```text
1. Engineer logs in through company SSO.
2. AuthSec checks tenant_membership.status = active.
3. Engineer launches MCP client.
4. Client requests github-mcp scopes:
     mcp:tools:write github.pr:write snowflake.query:read
5. AuthSec resolves effective access:
     direct user bindings
     group bindings through Engineering
     unexpired role bindings
     role permissions
     OAuth scope mappings
6. AuthSec grants:
     mcp:tools:write github.pr:write
7. AuthSec blocks:
     snowflake.query:read
8. Engineer consents if required by policy.
9. Token is issued for github-mcp only.
10. Tool call is checked again against tool policy and conditions.
```

Token result:

```text
requested: mcp:tools:write github.pr:write snowflake.query:read
RS supported for github-mcp: mcp:tools:write github.pr:write
user effective: mcp:tools:write github.pr:write
grantable: mcp:tools:write github.pr:write
blocked: snowflake.query:read
```

Edge cases:

```text
Employee changes department:
  SCIM removes Engineering group and adds Finance group; effective access changes without editing user role rows.

Contractor access expires:
  role_bindings.expires_at causes access to fail automatically.

Last Owner removal:
  deny operation; tenant must always have at least one active Owner.

High-risk tool invocation:
  require MFA, human confirmation, or admin-approved JIT elevation.

SCIM sync deletes a group:
  mark group inactive and suspend grants; preserve audit history.

Admin tries to approve their own high-risk client:
  require separation-of-duty policy if configured.
```

### Case 2: Multiple Admin Types

Tenant admins should not all be full owners.

Roles:

```text
Owner:
  tenant.manage
  role_binding.create
  role_binding.delete
  user.invite
  user.suspend
  resource_server.manage
  oauth_client.approve
  audit_log.read

Security Admin:
  sso.manage
  scim.manage
  oauth_client.approve
  resource_server.manage
  audit_log.read

User Admin:
  user.invite
  user.suspend
  group.manage

MCP Admin:
  resource_server.manage
  mcp.tool.admin
  oauth_scope.manage

Auditor:
  audit_log.read
```

Guardrails:

```text
Cannot remove last Owner.
Cannot self-remove final Owner role.
Changing SSO/SCIM/client approval requires MFA step-up.
Break-glass/support roles must expire and require reason.
```

### Case 3: Tool-Level Restrictions Beyond Scopes

`github.pr:write` should not mean write to every repo.

Role binding:

```text
group = engineering
role = GitHub PR Writer
scope_type = resource_server
scope_id = github-mcp
conditions = {
  "allowed_repos": ["authsec-api", "authsec-web"],
  "mfa_required": true
}
```

Runtime tool call:

```json
{
  "tool": "create_pull_request",
  "arguments": {
    "repo": "payroll-private",
    "branch": "test"
  }
}
```

Decision:

```text
deny: repo not in allowed_repos
```

This should be a PDP/tool-policy decision, not a new OAuth scope.

### Case 4: High-Risk Tool Requires Step-Up

Tool:

```text
delete_github_repository
```

Tool policy:

```json
{
  "risk_level": "critical",
  "required_permission": "github.repo.delete",
  "required_scope": "github.repo:admin",
  "requires_mfa": true,
  "requires_human_confirmation": true
}
```

If the user has `github.repo:read` but not `github.repo:admin`, MCP should respond with insufficient scope / step-up guidance. AuthSec should require fresh consent or admin-approved elevation.

### Case 5: Service Account Automation

Nightly automation should not use a human delegated token.

Model:

```text
subject_type = service_account
role = Snowflake Readonly Exporter
scope_type = resource_server
scope_id = snowflake-mcp
conditions = {
  "allowed_tools": ["run_readonly_query"],
  "allowed_time_utc": ["00:00-03:00"],
  "max_rows": 100000
}
```

OAuth flow:

```text
client_credentials
aud = snowflake-mcp
scope = snowflake.query:read
```

Audit must show:

```text
service account
OAuth client
resource server
tool
arguments digest
policy decision
```

### Case 6: End User Lifecycle

Goal:

An end user needs control and visibility after they connect an AI client to an MCP server.

Personas:

```text
External end user:
  connected Claude Desktop to a public MCP server and later wants to disconnect it.

Company employee:
  used an internal agent and wants to see what it did on their behalf.

Privacy/compliance user:
  wants export/delete controls for their account and activity.
```

Required end-user surfaces:

```text
Connected AI clients:
  list every OAuth client the user authorized in this tenant.

Consent detail:
  show resource server, scopes, grant time, expiry, last used, client identity, and risk labels.

Revoke access:
  revoke one client grant, one resource-server grant, or all grants for the user.

Activity timeline:
  show tool calls performed on behalf of the user.

Data export:
  export profile, memberships, consents, and user-visible activity events.

Account deletion:
  delete or anonymize user-owned data according to tenant policy and legal retention.
  if user is the last Owner, require ownership transfer or break-glass recovery before deletion.
  revoke refresh tokens and remembered consents before deletion completes.

Active sessions:
  show browser/dashboard sessions separately from connected OAuth clients.
  allow remote sign-out for user-owned sessions.
```

Consent management flow:

```text
1. User opens "Connected AI Clients".
2. AuthSec queries active consent grants for user_id + tenant_id.
3. UI groups grants by OAuth client and resource server.
4. User selects "Disconnect Claude Desktop from browser-mcp".
5. AuthSec revokes the remembered consent grant.
6. AuthSec revokes refresh tokens for that client/resource/user.
7. AuthSec optionally revokes active access tokens or makes introspection fail.
8. Future token requests require consent again.
9. Audit records user-initiated revocation.
```

Activity timeline flow:

```text
1. MCP server or AuthSec PEP records every tools/call decision.
2. Event includes user_id, client_id, resource_server_id, tool_id, arguments digest, result status, policy decision, timestamp.
3. Sensitive arguments and outputs are redacted or hashed by policy.
4. User sees a readable timeline:
     "Claude Desktop called create_pull_request on github-mcp at 10:31 UTC."
5. Admin/auditor sees a richer version if permitted.
```

Activity visibility:

```text
Self:
  user sees their own tool-call timeline with sensitive args/outputs redacted.

Tenant admin:
  sees tenant-scoped activity needed for support/security, subject to role permissions.

Resource-server operator:
  sees calls against resource servers they operate.

Auditor:
  sees immutable decision metadata and redaction markers.

Peers:
  no access by default.
```

Retention:

```text
Recent user activity:
  visible to user for tenant-configured window, for example 30/90/365 days.

Security audit:
  retained by tenant retention policy.

Privacy deletion:
  deletes or anonymizes user-facing records unless legal hold/audit-retention policy applies.
```

Consent granularity:

```text
Read scopes:
  user can approve without granting write scopes.

Write/admin scopes:
  shown separately with risk label and may require step-up.

Scope changes:
  if client later asks for broader scopes, AuthSec requires fresh consent.
  if client later asks for a strict subset of already granted scopes, AuthSec can skip consent.

Ephemeral consent:
  user may approve one session, one workflow, or an expiring grant instead of a remembered grant.
```

Minimum records:

```text
oauth_consent_grants
oauth_refresh_tokens / token families
tool_call_audit_events
consent_receipts
user_privacy_requests
```

V2 requirement:

```text
User can list grants, revoke grants, see recent tool activity, and export/delete account data.
```

V3/future:

```text
Email consent receipts, DSAR automation, tenant-configurable legal hold, and advanced activity search.
```

### Case 7: AI Client and MCP Server Runtime Integration

Goal:

AI client developers and MCP server operators need a precise implementation contract.

Personas:

```text
AI client developer:
  wants to register a new client and handle AuthSec errors correctly.

MCP server operator:
  wants to validate tokens and call policy checks correctly.

Agent runtime developer:
  wants refresh tokens, step-up retries, and machine-readable denial reasons.
```

Dynamic client registration flow:

```text
1. Tenant policy says whether DCR is open, allowlisted, or disabled.
2. AI client POSTs registration metadata to AuthSec.
3. AuthSec validates redirect URIs, software statement or client metadata, publisher domain, and requested resources.
4. AuthSec creates client with status:
     approved
     pending_review
     denied
5. If pending, App Reviewer approves or denies.
6. Client receives client_id and registration management URI if policy allows RFC 7592 management.
```

DCR anti-abuse:

```text
Rate limit:
  per IP, domain, tenant, and software_id.

Redirect URI checks:
  exact HTTPS redirect match, loopback exception for native apps, typo-squatting checks for known brands.

Publisher trust:
  verified domain, software statement, or manual review depending on tenant policy.

Review triggers:
  broad scopes, admin scopes, unknown publisher, suspicious redirect domain, high-risk resource server.
```

MCP server token validation contract:

```text
Option A: JWT validation
  1. MCP server reads issuer and JWKS URL from AuthSec metadata.
  2. MCP server validates signature, issuer, audience, expiry, tenant_id, client_id, subject, and scopes.
  3. MCP server checks local cache for key rotation.
  4. MCP server calls AuthSec PDP for tool/argument policy when required.

Option B: Introspection
  1. MCP server calls RFC 7662 introspection endpoint.
  2. AuthSec returns active=false for revoked, expired, suspended, disabled-client, or disabled-resource-server tokens.
  3. AuthSec returns tenant_id, subject, client_id, aud/resource, scopes, token age, and policy hints.
  4. MCP server enforces response and optionally calls PDP for tool-specific checks.
```

Validation mode decision:

```text
Per resource server:
  operator chooses JWT, introspection, or hybrid.

JWT mode:
  lower latency; revocation is limited by token TTL plus revocation-cache freshness.

Introspection mode:
  stronger revocation and kill-switch guarantees; higher latency and control-plane dependency.

Hybrid mode:
  local JWT validation for low-risk read tools, introspection/PDP for write/admin/destructive tools.
```

SDK expectation:

```text
AuthSec v2 should ship first-party TS and Python middleware, and document Go middleware until a first-party Go SDK exists, for:
  protected resource metadata
  token validation
  introspection
  PDP tool checks
  step-up challenge handling
  standardized denial responses
```

Step-up protocol:

```text
1. User asks agent to invoke high-risk tool.
2. MCP server or AuthSec PDP denies with step-up required.
3. Response includes machine-readable reason and OAuth challenge.
4. AI client opens AuthSec authorization URL with requested acr_values/max_age/scope.
5. User completes MFA or stronger auth.
6. AuthSec creates a short-lived step-up grant bound to:
     user_id
     client_id
     resource_server_id
     tool_id
     arguments digest
     expiry
7. AI client retries the original tools/call.
8. MCP server verifies step-up grant and executes if policy still passes.
```

Step-up bundles:

```text
Single-call step-up:
  bind to one tool_id + arguments digest.

Workflow step-up:
  bind to workflow_id, allowed tool set, resource server, max risk, and short TTL.

Example:
  create_branch -> push_commit -> merge_pr can use one workflow step-up grant if all steps match the approved bundle.
```

Refresh token flow:

```text
1. Client requests offline_access only when tenant/client policy allows it.
2. AuthSec issues rotating refresh token family.
3. Each refresh rotates the token and invalidates the previous token.
4. Reuse of an old refresh token invalidates the token family.
5. Role changes can either:
     affect only new access tokens
     trigger immediate token revocation for sensitive roles
6. High-risk roles should have shorter max session lifetime than read-only roles.
```

Denial taxonomy:

```text
All denial responses include:
  decision_id
  reason
  message_key
  error_uri

consent_required:
  user has permission but has not consented to this client/resource/scope.

insufficient_scope:
  client requested a scope user does not have.

step_up_required:
  stronger authentication or fresh auth required.

client_not_approved:
  OAuth client is pending, denied, or disabled for this tenant/resource.

dcr_required:
  unknown client must register before authorization.

resource_disabled:
  resource server disabled by admin or incident response.

membership_inactive:
  user is suspended or removed from tenant.

email_verification_required:
  user must verify email before grant.

terms_acceptance_required:
  user must accept tenant/provider terms before grant.

payment_required:
  plan does not allow requested tool/scope.

policy_denied:
  role exists, but conditions/tool policy failed.

rate_limited:
  quota exceeded.

tenant_quota_exceeded:
  tenant-level quota exhausted.

key_rotation_in_progress:
  client/resource key transition requires retry or metadata refresh.

token_revoked:
  token, token family, or grant was revoked.
```

Native and mobile clients:

```text
PKCE:
  required for public/native clients.

Redirects:
  custom URI schemes or claimed HTTPS app links must be registered exactly.

Step-up:
  use browser-based authorization with passkey/WebAuthn, TOTP, or configured tenant MFA.

Device-bound tokens:
  prefer DPoP or platform-bound credentials when client platform supports it.
```

V2 requirement:

```text
DCR policy, token validation contract, introspection, refresh rotation, step-up challenge, denial taxonomy.
```

V3/future:

```text
DPoP everywhere, software statements, client attestation, app marketplace, and advanced client certification.
```

### Case 8: Agent Composition and MCP-to-MCP Delegation

Goal:

One agent workflow may need multiple MCP servers without leaking broad tokens or making users consent repeatedly.

Example:

```text
User asks:
  "Create a GitHub issue and announce it in Slack."

Agent uses:
  github-mcp
  slack-mcp
```

Wrong model:

```text
Give github-mcp the user's Slack token.
Give the agent one broad token for every MCP server.
Ask user to consent separately in the middle of every chained call.
```

Recommended model:

```text
1. Agent receives user-authorized token for first resource server.
2. Agent or MCP server requests token exchange for downstream resource.
3. AuthSec checks:
     original subject
     original client
     tenant policy
     source audience
     target audience
     requested scopes
     user effective access
     consent/admin grant
4. AuthSec issues a downscoped token for the target MCP server.
5. Audit links source call and downstream call with correlation_id.
```

RFC 8693 mapping:

```text
subject_token:
  token representing the end user and original authorization.

actor_token:
  optional token representing the calling agent, MCP server, or service account.

requested_token_type:
  access token for target MCP resource server.

audience/resource:
  target MCP resource URI.
```

Token exchange record:

```text
actor_user_id
requesting_client_id
source_resource_server_id
target_resource_server_id
requested_scopes
granted_scopes
reason
correlation_id
expires_at
```

Correlation propagation:

```text
Preferred:
  AuthSec-issued exchanged token includes correlation_id claim.

HTTP/MCP metadata:
  clients and servers propagate X-AuthSec-Correlation-ID or MCP metadata field.

Audit fallback:
  AuthSec links by token_exchange_id when headers are absent.
```

Cross-tenant exchange:

```text
V2:
  deny by default unless both tenants have explicit federation/trust policy.

Required checks:
  source tenant allows outbound delegation.
  target tenant accepts source issuer/client/tenant.
  end user has target-tenant membership or target policy allows external delegated users.

Audit:
  both tenants receive correlated audit events when policy allows disclosure.
```

Depth and loop controls:

```text
max_exchange_depth:
  tenant/resource-server policy, default 1.

loop detection:
  deny if target audience already appears in delegation chain.

service-account chains:
  require explicit allowlist and short TTL.
```

Token passthrough enforcement:

```text
Detection:
  introspection can detect token use from an unexpected resource server/client.
  audience mismatch is always denied.

Prevention:
  SDKs should never expose upstream bearer tokens to tool code unless explicitly required.

Audit:
  suspected passthrough emits security event and can disable client/resource server.
```

Output policy:

```text
Tool input policy:
  validates arguments before call.

Tool output policy:
  redacts secrets, access tokens, PII, keys, or tenant-blocked data before returning to agent.

Audit policy:
  stores output digest and redaction decision, not necessarily full output.
```

V2 requirement:

```text
Document token exchange and audit correlation; block token passthrough.
```

V3/future:

```text
Full multi-hop delegation graph, output DLP, workflow-level approvals, and delegated consent bundles.
```

### Cross-Cutting Runtime and Incident Operations

Runtime operators and security responders need blast-radius controls that are faster than waiting for access tokens to expire.

Kill switch requirements:

```text
Disable user:
  all future introspection fails for user_id.

Disable client:
  all future authorization, refresh, and introspection fails for client_id.

Disable resource server:
  no new tokens for aud/resource; introspection fails for matching audience if emergency mode is enabled.

Disable tenant:
  all tenant-scoped authorization, refresh, and introspection fails.

Force re-consent:
  revoke remembered consent grants and require user approval on next authorization.
```

Kill-switch propagation:

```text
Introspection path:
  effective immediately on next introspection request.

JWT path:
  effective within revocation-cache freshness SLO or access-token expiry, whichever comes first.

Recommended SLO:
  high-risk resources use introspection or cache freshness <= 60 seconds.
  low-risk resources may use short-lived JWTs with <= 5 minute TTL.
```

Token revocation model:

```text
Token revocation table:
  token_id / jti
  token_family_id
  user_id
  client_id
  resource_server_id
  tenant_id
  reason
  revoked_by
  revoked_at

Validation:
  JWT validators check revocation cache for sensitive flows.
  Introspection always checks revocation and emergency disable state.
```

Sensitive-flow definition:

```text
Sensitive means any tool/scope marked write, admin, destructive, money-moving, data-exporting, or tenant-configured high risk.
Sensitive flows should introspect or check revocation cache before execution.
```

Force re-consent vs revocation:

```text
Force re-consent:
  deletes remembered consent; next authorization prompts again.
  does not necessarily invalidate existing access tokens.

Token revocation:
  invalidates active token or token family.
  should be used for incidents, user disconnect, client compromise, and role-risk changes.
```

Replay detection:

```text
Signals:
  same token from impossible IP/geography
  same token from multiple user agents
  DPoP proof mismatch
  refresh token reuse
  unusually high tool-call rate

Actions:
  revoke token family
  suspend membership
  disable client
  require fresh auth
  alert tenant admins/webhook/SIEM
```

Replay response policy:

```text
Detect-only:
  write security event and notify admin.

Challenge:
  require fresh auth or MFA.

Contain:
  revoke token family or disable client.

Auto-containment must be tenant-configurable and reversible by authorized security admins.
```

Service account credential rotation:

```text
1. Create new credential while old credential remains active.
2. Operator deploys new credential.
3. AuthSec observes use of new credential.
4. Operator disables old credential.
5. AuthSec alerts before credential expiry.
```

Rotation API/CLI:

```text
authsec service-accounts credentials create --service-account nightly-exporter
authsec service-accounts credentials list --service-account nightly-exporter
authsec service-accounts credentials disable --credential-id ...
authsec service-accounts credentials rotate --overlap 7d
```

Outbound webhooks:

```text
user.created
user.suspended
consent.granted
consent.revoked
client.pending_review
client.approved
token.revoked
tool_call.high_risk
role_binding.created
role_binding.deleted
incident.kill_switch_enabled
```

Webhook reliability:

```text
Signing:
  HMAC or JWS signature over timestamp + body.

Idempotency:
  event_id is globally unique and stable across retries.

Retries:
  exponential backoff with max retry window.

Ordering:
  order guaranteed per tenant + event stream only if explicitly documented.

Replay window:
  receiver rejects old timestamps.

Dead letter:
  failed events visible in admin UI and replayable.

Schema versioning:
  every event includes event_type, event_version, event_id, created_at, tenant_id.
  additive fields may be added within a version.
  breaking payload changes require new event_version.
```

Hydra/control-plane degradation:

```text
Token issuance unavailable:
  new authorization and refresh fail gracefully.

Introspection unavailable:
  MCP servers fail closed for high-risk tools.
  MCP servers may use cached positive validation only for low-risk tools if tenant policy allows it.

JWKS unavailable:
  MCP servers use cached keys until key cache expiry.

PDP unavailable:
  fail closed for write/admin/destructive tools.
  optional fail-open only for explicitly configured low-risk read tools.
```

Data residency and compliance:

```text
V2:
  retention policy, audit export, privacy export/delete, and region label on tenant.
  region label is informational unless deployment enforces storage/processing region.

V3:
  hard regional pinning, WORM audit storage, SIEM export packs, compliance reports.
```

Retention vs residency:

```text
Retention:
  how long AuthSec keeps audit/activity/privacy data.

Residency:
  where AuthSec stores and processes data.

Compliance:
  what evidence AuthSec can produce: audit export, immutable log, access review records, and attestations.
```

### Case 9: Tenant Identity and Lifecycle

Goal:

Tenant operators need to configure how users sign in, transfer ownership safely, recover from lost owners, and delete a tenant cleanly.

Per-tenant IdP setup:

```text
1. Tenant Owner opens Login Providers.
2. Owner enables Google, GitHub, email/password, passkeys, OIDC, or SAML.
3. Owner configures allowed domains and default role.
4. AuthSec tests provider metadata and callback URL.
5. New users signing in through that provider receive tenant_membership and default role if JIT provisioning is enabled.
```

JIT matching key:

```text
Default:
  provider_subject is authoritative for identity matching.

Verified email:
  can suggest account linking but must not silently merge identities unless tenant policy explicitly allows it.

Reason:
  emails can change or be reassigned; provider_subject is the stable security identifier.
```

IdP precedence and deprovisioning:

```text
Provider precedence:
  tenant config orders providers for account linking and JIT provisioning.

Matching:
  provider subject is authoritative.
  verified email can suggest a link but should not silently merge accounts unless tenant policy allows it.

SCIM deprovision:
  suspend tenant_membership and revoke refresh tokens.

OIDC/SAML group claims:
  may map claims to AuthSec groups during login.
  SCIM remains preferred for large group lifecycle because it handles removals outside login.
```

Ownership transfer:

```text
1. Current Owner nominates new Owner.
2. Nomination expires after tenant-configured window, default 7 days.
3. New Owner accepts and completes MFA/step-up.
4. AuthSec creates Owner role binding for new Owner.
5. Current Owner may remove their own Owner role only after another active Owner exists.
6. Audit records before/after owners.
```

Concurrent nominations:

```text
Multiple pending nominations may exist.
Owner removal is blocked until at least one accepted active Owner remains.
Conflicting nominations are resolved by accepted timestamp and final active-owner invariant.
```

Break-glass recovery:

```text
1. Recovery requester proves tenant control through configured recovery method.
2. AuthSec support or automated recovery flow creates time-limited recovery Owner binding.
3. Recovery binding requires reason and expires automatically.
4. Every action is audit-highlighted and optionally notifies existing admins.
```

Supported recovery methods:

```text
DNS TXT challenge:
  proves control of verified custom domain.

Pre-registered backup email:
  must be configured before incident.

Billing owner verification:
  proves control of billing account/customer record.

Vendor support:
  requires ticket evidence and second AuthSec approver.
```

Tenant deletion:

```text
1. Owner requests deletion.
2. AuthSec shows affected users, resource servers, OAuth clients, consents, tokens, and audit retention.
3. Owner confirms with step-up auth.
4. AuthSec disables new token issuance immediately.
5. AuthSec revokes refresh tokens and remembered consents.
6. AuthSec deletes/anonymizes data according to retention/legal policy.
7. Audit tombstone remains if required by compliance policy.
```

### Case 10: Admin Productivity, Diagnostics, and Recertification

Goal:

Admins and support teams need to explain decisions, approve temporary access, and periodically review access.

Effective-access explorer:

```text
Inputs:
  user/group/service account
  tenant
  resource server
  tool/action
  optional arguments

Output:
  allowed/denied
  matching role bindings
  inherited group bindings
  granted permissions
  mapped OAuth scopes
  failed conditions
  required step-up or consent
```

PDP decision trace:

```text
Trace is stored with decision_id.
End users see friendly reason.
Admins see role/policy details.
Developers receive machine-readable denial code.
Sensitive policy internals can be hidden from end users.
```

Trace storage and lookup:

```text
decision_traces:
  decision_id
  tenant_id
  subject_id
  client_id
  resource_server_id
  tool_id
  decision
  reason
  matched_bindings
  failed_conditions
  created_at
  retention_class

Denial responses:
  include decision_id, reason, message_key, and error_uri.

Lookup:
  end user can look up their own decision_id.
  admins/auditors can look up tenant decisions by permission.
```

Approval workflow:

```text
1. User requests elevated role/scope/tool access.
2. AuthSec routes request by policy:
     manager
     resource owner
     security admin
     two-person approval
3. Approver receives email/Slack/webhook notification.
4. Approved grant creates role_binding with expires_at.
5. Grant auto-revokes on expiry or external ticket closure.
6. Audit links request, approval, grant, and revocation.
```

External ticket closure:

```text
V2:
  inbound signed webhook updates approval request state.

Fallback:
  scheduled connector/polling job for Jira/Linear/ServiceNow.

Safety:
  role_binding.expires_at is still mandatory for elevated grants even when ticket sync exists.
```

Access review / recertification:

```text
1. Compliance owner starts quarterly review.
2. AuthSec groups access by manager, group, role, or resource server.
3. Reviewer approves, removes, or marks exception.
4. Removals update role bindings.
5. Evidence export shows reviewer, decision, timestamp, and changes.
```

Impersonation:

```text
Tenant admin impersonation:
  allowed only with explicit permission, reason, expiry, and visible audit banner.

AuthSec support impersonation:
  disabled by default; tenant opt-in required.
  requires ticket ID, support role, time-box, and immutable audit.

User privacy:
  impersonation should never reveal secrets such as passwords, private keys, or full tokens.
```

API/programmatic impersonation:

```text
Tokens issued during impersonation include an actor claim:
  sub = target user
  act.sub = impersonating admin/support user
  act.reason = ticket/reason
  act.expires_at = timestamp

Audit:
  every call records both sub and act.sub.

Restrictions:
  impersonation tokens cannot export secrets, rotate credentials, or disable audit.
```

### Case 11: Adoption, Branding, Migration, and Tool Authoring

Goal:

Operators need AuthSec to feel like part of their product, migrate from existing providers, and keep tool policy close to code.

Branding and custom domain:

```text
Tenant branding:
  logo
  product name
  support URL
  privacy/terms URLs
  consent-screen copy

Custom domain:
  auth.alextools.dev
  verified DNS
  managed TLS certificate
  provider-specific callback URLs
```

Migration from Auth0/Clerk/custom auth:

```text
1. Import users and external identities.
2. Import OAuth clients if compatible.
3. Map old roles/scopes to AuthSec roles/permissions/oauth_scopes.
4. Run dual-stack mode:
     old provider handles existing sessions
     AuthSec handles new grants
5. Prompt re-consent only when required by scope/client/resource change.
6. Cut over token issuance after validation.
```

Dual-stack token validation:

```text
During migration, MCP resource server trusts two issuers:
  old issuer
  AuthSec issuer

Routing:
  validate by iss claim and issuer-specific JWKS.

Cutover:
  resource server removes old issuer after old refresh/session TTL ends.

Safety:
  old-provider tokens should not be accepted for newly registered AuthSec-only clients/resources.
```

Sandbox tenant:

```text
Purpose:
  safe client/server integration without touching production users.

Properties:
  separate issuer or environment marker
  short token TTLs
  test users and sample resource servers
  synthetic audit data
  reset/delete button
```

Sandbox isolation:

```text
Sandbox has separate issuer/environment marker and separate signing keys.
Sandbox API keys are issued from developer dashboard with explicit test label.
Sandbox webhooks are disabled by default or delivered to sandbox-only endpoints.
Sandbox data never writes to production tenant tables except control-plane account metadata.
Free sandbox creation is rate-limited to prevent abuse.
```

Tool author code-time contract:

```text
Tool annotations:
  required_permission
  suggested_scope
  risk_level
  requires_mfa
  argument_schema
  output_data_classification

Registration:
  SDK sends annotations during manifest registration or tool scan.
  AuthSec stores them as suggested policy.
  Admin approval is required before suggestions become effective for high-risk tools.
```

Annotation review default:

```text
Unreviewed new high-risk tool:
  blocked; is_public=false; no runtime-effective scope mapping.

Unreviewed low-risk tool:
  may remain disabled until admin review unless tenant explicitly enables auto-accept low-risk suggestions.

Existing tool with changed annotation:
  previous approved policy remains effective until admin approves new version or deprecation expires.
```

Tool versioning and drift:

```text
mcp_tools:
  name
  version
  schema_hash
  policy_version
  deprecated_at
  sunset_at

Signature drift:
  input schema or annotations changed since last scan.

Behavior:
  mark tool as needs_review.
  keep previous policy for compatible changes.
  require approval for new arguments, broader output class, higher risk, or new required scope.

Deprecation:
  support aliases and grace periods for renamed scopes/tools.
```

Marketplace/discovery:

```text
V2:
  not required for core authorization.

V3:
  verified MCP provider directory, trust badges, app/client review history, and user discovery.
```

### Additional V2 Commitments

Agent pre-flight check:

```text
AI clients can call PDP with dry_run=true before invoking a tool.
Response uses the same decision schema and includes decision_id.
No tool execution or quota decrement occurs during dry run.
```

Anonymous/pre-auth public access:

```text
Tenant may mark selected tools anonymous_allowed=true.
Anonymous calls receive anonymous subject with strict rate limit and no remembered consent.
Anonymous access is only for low-risk read tools.
Upgrade path prompts user to sign in when quota, scope, or risk threshold is exceeded.
```

Anonymous audit subject:

```text
Use anonymous_session_id as subject_id.
Derive it from signed short-lived anonymous token, not raw IP.
Store IP/user-agent only under privacy policy and retention limits.
Abuse controls can aggregate by anonymous_session_id, IP prefix, and client fingerprint where legally allowed.
```

Tenant export / portability:

```text
Owner can export:
  tenant metadata
  users/memberships
  groups
  roles/permissions/bindings
  resource servers
  OAuth scopes
  client approvals
  consent grant metadata
  audit export, subject to retention policy

Format:
  versioned JSONL/CSV bundle with schema manifest.
```

Tenant import:

```text
Import accepts the same versioned bundle format.
Validation runs before write: tenant_id rewrite, dependency checks, schema version compatibility, and conflict report.
Sandbox-to-production promotion is an import with explicit environment rewrite.
```

Soft-delete and undo:

```text
Soft-delete by default for:
  resource servers
  groups
  roles
  OAuth clients
  MCP tools

Default undo window:
  30 days unless tenant retention policy is shorter.

Hard delete:
  requires Owner/admin step-up and dependency check.
```

Dependency rules:

```text
Role with active bindings:
  block hard delete; soft-delete disables new grants and requires binding cleanup.

OAuth scope mapped to tools or permissions:
  block hard delete until mappings are removed or replacement scope is chosen.

Resource server with active clients/tokens:
  disable first, revoke tokens, then delete after grace window.

Group with active role bindings:
  block hard delete; require transfer/removal of bindings.
```

Sub-tenant/project hierarchy:

```text
V2 decision:
  no separate sub-tenant model.

Reason:
  tenant remains the hard isolation boundary.
  use groups, scoped role_bindings, projects/resource_server scopes, and conditions for team-level isolation.

Revisit:
  only if customers need separate billing, legal ownership, or hard data residency boundaries inside one account.
```

i18n and accessibility:

```text
User-facing errors and consent text use message_key + variables, not hardcoded prose.
Tenant branding may provide localized consent copy.
Locale chosen from user preference, browser Accept-Language, then tenant default.
Consent and admin surfaces must meet WCAG AA before public launch.
Catalog ownership:
  AuthSec owns base message catalog.
  tenant overrides only approved branding/consent strings.
  missing keys fall back to tenant default locale, then en-US, never raw key text in production.
```

Deferred v3 / explicit non-v2 items:

```text
AI-client token introspection:
  RFC 7662 remains RS-facing. Client-facing "access status" endpoint is v3.

PDP shadow/explain mode for proposed policies:
  v3 admin productivity feature.

Customer-managed signing-key backup/recovery:
  v3 enterprise resilience feature; v2 uses AuthSec-managed encrypted backups and rotation.
```

---

## 7. Recommended AuthSec Implementation

### Phase 1: Clarify and Document the Model

Use these product terms:

```text
Tenant = account/workspace/operator boundary
Member = user active inside tenant
Group = collection of members
Role = admin-facing permission bundle
Permission = internal enforcement atom
OAuth scope = token-facing resource-server contract
Tool policy = runtime MCP enforcement
```

For product copy, avoid making the model sound enterprise-only:

```text
Tenant = account/workspace/operator boundary
Member = user active inside that tenant
```

### Phase 2: Add Tenant Memberships

Add `tenant_memberships`.

Use it in auth checks before role/scope resolution:

```text
1. user exists
2. tenant_membership exists and status = active
3. role bindings are evaluated
4. scopes are resolved
```

### Phase 3: Add Group Role Bindings

AuthSec already has nullable principal columns for users and service accounts. Do not add a duplicate `subject_type + subject_id` pair in v2. Extend the existing shape with a nullable `group_id`.

```sql
ALTER TABLE role_bindings
  ADD COLUMN group_id uuid;
```

Principal rule:

```text
Exactly one of user_id, group_id, service_account_id must be non-null.
```

Logical subject type is derived:

```text
user_id present            -> subject_type = user
group_id present           -> subject_type = group
service_account_id present -> subject_type = service_account
```

Then update effective permission resolution:

```text
direct user bindings
UNION
group bindings through user_groups
UNION
service account bindings, when subject is service account
```

Do not revive vestigial `group_roles` logic. Keep one path: `role_bindings`.

For solo developer and small team usage, direct user role bindings are enough. Group role bindings become important when users are managed in bulk.

### Phase 4: Enforce Conditions

`role_bindings.conditions` currently stores useful future data. The PDP should enforce it using a typed v2 schema, not arbitrary unvalidated JSON.

V2 condition schema:

```json
{
  "mfa_required": true,
  "allowed_resource_servers": [],
  "allowed_tools": [],
  "denied_tools": [],
  "allowed_repos": [],
  "allowed_ip_cidrs": [],
  "max_risk_level": "medium"
}
```

Rules:

```text
Allow lists narrow access.
Deny lists override allow lists.
Binding expiry uses role_bindings.expires_at, not a duplicate condition field.
Unsupported condition keys fail validation at write time.
Complex policy languages such as CEL/Rego can be evaluated later, but v2 should use typed conditions first.
```

Evaluation order:

```text
1. deny if user inactive
2. deny if tenant membership inactive
3. deny if resource server tenant mismatch
4. deny if no role permission
5. deny if OAuth scope not grantable
6. deny if condition fails
7. deny or step-up if tool policy requires stronger auth
8. allow and audit
```

### Phase 5: Add MCP Tool Policy

Add or extend tool metadata:

```text
mcp_tools:
  risk_level
  required_permission
  required_scope
  requires_mfa
  requires_confirmation
  argument_policy jsonb
```

Runtime check for `tools/call`:

```text
token valid?
audience matches resource server?
scope contains required scope?
subject has required permission?
client approved for tenant and resource server?
tool is reviewed/active?
conditions pass?
argument policy passes?
audit decision
```

### Phase 6: Reduce Scope Confusion

Use `oauth_scopes` as the source of truth for MCP/OAuth authorization.

Legacy concepts should be actively deprecated:

```text
scopes
scope_permissions
api_scopes
api_scope_permissions
```

Deprecation plan:

```text
1. Stop creating new legacy scopes.
2. Migrate legacy scope mappings into oauth_scopes and oauth_scope_permissions.
3. Emit both old and new claims during compatibility window if needed.
4. Stop emitting legacy claims.
5. Stop reading legacy claims.
6. Drop legacy tables only after migration validation.
```

The target chain should be:

```text
role_bindings
  -> roles
  -> role_permissions
  -> permissions
  -> oauth_scope_permissions
  -> oauth_scopes
  -> mcp_tool_scope_map
  -> mcp_tools
```

This already matches the direction of `services/scope_resolver.go`.

OAuth client scoping:

```text
Known public clients such as Claude Desktop may have a global client identity.
Tenant approval remains tenant/resource-scoped through client registration/approval records.
Tenant-owned first-party clients are tenant-scoped.
Tokens must still be resource/audience-scoped.
```

### Phase 7: Add End-User Control Surfaces

AuthSec v2 must expose user-facing lifecycle pages, not only admin pages.

Required surfaces:

```text
Connected AI Clients:
  list clients and resource servers authorized by the user.

Consent Detail:
  show scopes, risk labels, grant time, expiry, and last-used timestamp.

Disconnect:
  revoke consent and refresh tokens for one client/resource.

Activity:
  show recent tool calls made on behalf of the user.

Privacy:
  export and delete user data according to tenant policy.
```

Implementation targets:

```text
oauth_consent_grants:
  query by tenant_id + user_id.

token revocation:
  support RFC 7009 and refresh-token-family revocation.

tool_call_audit_events:
  write user-visible activity records with argument/output redaction.

privacy_requests:
  track export/delete requests and completion state.
```

### Phase 8: Add Client and Server Runtime Contracts

AuthSec should document exactly how AI clients and MCP servers integrate.

Required contracts:

```text
DCR:
  tenant-configurable dynamic client registration.

Token validation:
  JWT/JWKS path and RFC 7662 introspection path.

SDKs:
  TS/Python/Go helpers for token validation, introspection, PDP calls, and challenge handling.

Refresh:
  rotating refresh tokens, reuse detection, max session lifetime, offline_access policy.

Step-up:
  RFC 9470-compatible challenge and retry flow.

Denials:
  stable machine-readable error taxonomy.
```

Token lifetime policy:

```text
Configured by tenant, resource server, client, and role risk.

Examples:
  read-only user token: 1 hour access token, 30 day refresh family.
  admin token: 15 minute access token, no offline_access by default.
  service account token: short access token, credential rotation policy.
  high-risk tool step-up: 5-15 minute grant.

Most restrictive matching policy wins.
```

### Phase 9: Add Delegation and Token Exchange

Agent composition requires downscoped delegation.

Required model:

```text
source token:
  issued to client for source resource server.

token exchange:
  AuthSec checks original subject, client, consent, target audience, and requested scopes.

target token:
  short-lived token scoped to downstream MCP server.

audit:
  correlation_id links source and downstream tool calls.
```

Block token passthrough. MCP servers must not forward upstream access tokens to downstream MCP servers or SaaS APIs.

### Phase 10: Add Runtime Operations and Incident Controls

Security responders need immediate controls.

Required controls:

```text
kill switches:
  disable user, client, resource server, or tenant.

revocation:
  revoke token, token family, consent grant, or resource-server grants.

forced re-consent:
  clear remembered grants after breach or scope/tool policy change.

replay detection:
  detect impossible token use, refresh reuse, and DPoP mismatch.

service-account rotation:
  dual credential overlap, expiry alerts, and no-downtime rotation.

service-account credential lifetime:
  default maximum lifetime 365 days.
  tenant may require shorter lifetime.
  longer lifetime requires explicit Owner/Security Admin exception and audit reason.

webhooks:
  outbound security, billing, consent, and role-change events.

control-plane degradation:
  clear fail-open/fail-closed rules for token issuance, introspection, JWKS, and PDP outages.

AuthSec API self-protection:
  rate-limit admin APIs, DCR, token, introspection, PDP, webhook replay, and export endpoints.
  return machine-readable rate_limited with retry_after when possible.
```

### Phase 11: Add Quotas and Rate Limits

Public MCP providers need rate limits as a first-class policy subsystem, not just JSON examples.

Model:

```text
quota_policies:
  tenant_id
  subject_type = user | group | role | client | tenant
  resource_server_id
  tool_id
  window = minute | hour | day | month
  limit
  overage_behavior = deny | step_up | bill_overage | queue

quota_counters:
  tenant_id
  subject_id
  client_id
  resource_server_id
  tool_id
  window_start
  count
```

Enforcement point:

```text
AuthSec PDP:
  authoritative decision and audit.

MCP server SDK:
  optional local pre-check/cache for low-latency limits.

Overage:
  return machine-readable tenant_quota_exceeded or rate_limited denial.
```

Policy precedence:

```text
All matching quota policies are evaluated.
Most restrictive remaining allowance wins.
Specificity breaks ties:
  user > group > role > client > tenant.
Tenant hard caps always apply even when user/client policy is higher.
```

Operational model:

```text
Windowing:
  v2 uses fixed windows for predictable enforcement.
  sliding windows can be added later for smoother user experience.

Storage:
  partition counters by tenant_id and window_start.
  archive or aggregate old counters after billing/audit window.

Concurrency:
  central PDP/quota service is authoritative.
  SDK local cache is advisory and must tolerate correction by PDP.

Refund/rollback:
  failed tool execution may refund quota only if tool policy marks the action refundable.
  destructive/write calls should generally consume quota once admitted.

Alerts:
  emit quota.usage_threshold at configurable thresholds such as 80%, 95%, 100%.
```

---

## 8. Admin UX Implications

Do not show users a giant "assign 100 scopes to this user" screen as the primary workflow.

Primary workflows:

```text
Invite/import users
Create/sync groups
Assign group to role
Scope role to MCP server/project/tool class
Review effective access
Audit changes
```

Advanced workflows:

```text
Create custom role
Map role permissions
Map permissions to OAuth scopes
Override MCP tool-scope mapping
Add conditional policy
Approve high-risk client/tool
```

Solo developer UX should be smaller:

```text
Create MCP resource server
Choose public/private access
Create default roles
Review OAuth clients
Review tool scopes
View consent and tool-call audit
```

Public MCP provider UX should emphasize:

```text
Client registration policy
User consent screens
App/client review
Plan-based roles
Rate limits
Abuse controls
Tool-call audit
```

End-user UX should emphasize:

```text
Connected AI clients
Per-client consent details
Disconnect/revoke
Activity timeline
Data export/delete
```

AI client developer UX should emphasize:

```text
Dynamic client registration
Sandbox tenant
Machine-readable denial reasons
Step-up retry guidance
Refresh-token behavior
```

MCP server operator UX should emphasize:

```text
Protected resource metadata
JWKS and introspection instructions
SDK snippets
PDP/tool-policy examples
Incident kill switches
```

Security responder UX should emphasize:

```text
Revoke all tokens for user/client/resource
Disable resource server
Force re-consent
Replay detection timeline
Webhook/SIEM delivery status
```

Tenant lifecycle UX should emphasize:

```text
Login provider setup
Custom domain and branding
Ownership transfer
Break-glass recovery
Tenant deletion
Migration import checklist
```

Admin productivity UX should emphasize:

```text
Effective-access explorer
Why denied traces
Approval request queue
Access review campaigns
Impersonation with audit
```

Good enterprise UI example:

```text
Group: Engineering MCP Writers
Role: GitHub PR Writer
Applies to: GitHub MCP server
Conditions:
  Repositories: authsec-api, authsec-web
  MFA: required
  Tool risk: medium or lower
Users affected: 1,842
OAuth scopes granted:
  mcp:tools:write
  github.pr:write
```

The admin understands the role and group. The system handles scopes.

---

## 9. Product Positioning

AuthSec should not position itself as "OAuth scopes for MCP".

Better positioning:

```text
AuthSec lets MCP server operators decide which AI clients and users can invoke which MCP tools,
against which resources, with which arguments, under which approvals or consent, and with a full audit trail.
```

OAuth scopes are interoperability plumbing. Enterprise value is:

- user and group lifecycle
- tenant isolation
- admin delegation
- role-based access
- client approval
- least-privilege token issuance
- MCP tool policy
- step-up approval
- audit and explainability

For solo developers and public MCP providers, the value is:

- OAuth without building an authorization server
- public MCP resource-server registration
- client registration and trust policy
- user consent
- end-user connected-client management
- end-user activity visibility
- scope issuance
- tool-level policy
- abuse/rate-limit controls
- revocation and incident controls
- audit and debugging

---

## 10. Summary

AuthSec v2 uses `tenant` as the account/workspace/operator boundary.

AuthSec needs:

1. `tenant_memberships` for user lifecycle.
2. group subjects in `role_bindings`.
3. one RBAC path for user/group/service-account authorization.
4. `conditions` enforcement in the PDP.
5. MCP tool-level policy beyond OAuth scopes.
6. end-user consent management, revocation, activity, export, and deletion.
7. dynamic client registration and registration management policy.
8. a precise MCP token validation contract: JWKS, introspection, SDKs, and PDP boundaries.
9. step-up challenge, refresh-token, and denial-reason protocols for AI clients.
10. token exchange for agent composition without token passthrough.
11. runtime kill switches, replay detection, credential rotation, outbound webhooks, and outage behavior.
12. per-tenant login providers, identity linking, ownership transfer, break-glass recovery, and tenant deletion.
13. effective-access explorer, approval workflows, access recertification, and audited impersonation.
14. branding/custom domains, migration tooling, sandbox tenants, and tool-author annotations.
15. quotas/rate limits as enforceable PDP policy.
16. a clear admin UX where roles are assigned and scopes are derived.

The correct separation is:

```text
Tenant: who owns or operates the environment.
Membership: who belongs to it.
Group: how users are managed at scale.
Role: what admins assign.
Permission: what AuthSec enforces.
OAuth scope: what tokens carry.
Tool policy: what MCP runtime checks.
Audit: why the decision happened.
Consent: what the user allowed a client to do.
Revocation: how access is removed before token expiry.
Token exchange: how agent workflows cross MCP server boundaries safely.
Identity provider: how users prove who they are.
Approval: how temporary elevated access is requested and reviewed.
Quota: how usage limits are enforced.
```
