-- application_xaa_policies: per-Application allowlist for Cross-App Access.
--
-- When an XAA client app (xaa_client_apps row) presents an ID-JAG at this
-- Application's Resource AS, the verifier looks up
-- (resource_server_id, requesting_client_id, trusted_issuer) and rejects with
-- access_denied if no enabled row matches. Default-deny.
--
-- allowed_scopes is the upper bound on what the access token may carry;
-- the final scope set is allowed_scopes ∩ ID-JAG.scope ∩ user_effective.
--
-- trusted_issuer distinguishes which IdP signed the ID-JAG:
--   * '' (empty) — AuthSec is the IdP (internal-internal case).
--   * 'https://<okta-or-other>' — an external trusted IdP. JWKS for that
--     issuer is configured at deploy time (or via a future trusted_issuers
--     table when external IdPs become first-class).

CREATE TABLE IF NOT EXISTS application_xaa_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    resource_server_id UUID NOT NULL,
    requesting_client_id TEXT NOT NULL,
    trusted_issuer TEXT NOT NULL DEFAULT '',
    allowed_scopes TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, resource_server_id, requesting_client_id, trusted_issuer)
);

CREATE INDEX IF NOT EXISTS idx_application_xaa_policies_resource
    ON application_xaa_policies (resource_server_id, enabled);
CREATE INDEX IF NOT EXISTS idx_application_xaa_policies_lookup
    ON application_xaa_policies (tenant_id, resource_server_id, requesting_client_id, trusted_issuer);
