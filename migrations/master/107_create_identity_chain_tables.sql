-- Identity-chaining v2 tables.
-- Used only by the new /authsec/oauth2/* endpoints.
-- The legacy /authsec/spire/oidc/* endpoints do not read or write these tables.

CREATE TABLE IF NOT EXISTS trusted_issuers (
    id            SERIAL PRIMARY KEY,
    tenant_id     VARCHAR(64),
    issuer        VARCHAR(512) NOT NULL,
    jwks_uri      VARCHAR(512) NOT NULL,
    audience      VARCHAR(512),
    max_chain_hop INTEGER NOT NULL DEFAULT 4,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    description   VARCHAR(1024),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT idx_trusted_issuer_per_tenant UNIQUE (tenant_id, issuer)
);

CREATE INDEX IF NOT EXISTS idx_trusted_issuers_tenant ON trusted_issuers(tenant_id);

CREATE TABLE IF NOT EXISTS act_chain_audit (
    id             SERIAL PRIMARY KEY,
    jti            VARCHAR(64) NOT NULL UNIQUE,
    tenant_id      VARCHAR(64),
    subject_sub    VARCHAR(256),
    subject_iss    VARCHAR(512),
    actor_sub      VARCHAR(256),
    actor_iss      VARCHAR(512),
    chain_depth    INTEGER NOT NULL DEFAULT 0,
    resource       VARCHAR(512),
    audience       VARCHAR(512),
    scope          VARCHAR(1024),
    issued_at      TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_act_chain_audit_tenant   ON act_chain_audit(tenant_id);
CREATE INDEX IF NOT EXISTS idx_act_chain_audit_subject  ON act_chain_audit(subject_sub);
CREATE INDEX IF NOT EXISTS idx_act_chain_audit_issued   ON act_chain_audit(issued_at);
