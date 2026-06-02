-- resource_server_tenant_index: master-side lookup mapping resource_uri to
-- tenant_id. Written in lockstep with the tenant-DB resource_servers row.
--
-- Rationale: the /oauth/v2/register (DCR) handler receives a `resource` URI
-- but no tenant context on the wire. To know which tenant DB to query for the
-- resource_servers row, AuthSec first consults this master-side index.
--
-- This table is index-only: the authoritative resource_servers row lives in
-- the tenant DB. Drift between this index and the tenant row is repaired by a
-- background reconciler (TODO phase 5).

CREATE TABLE IF NOT EXISTS resource_server_tenant_index (
    resource_uri TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL,
    resource_server_id UUID NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rs_tenant_index_tenant_id ON resource_server_tenant_index(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rs_tenant_index_active ON resource_server_tenant_index(active);
