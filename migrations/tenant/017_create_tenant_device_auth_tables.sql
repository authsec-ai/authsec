-- Add tenant-scoped device auth tables used by local CIBA and tenant TOTP.

CREATE TABLE IF NOT EXISTS tenant_device_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    device_token VARCHAR(500) NOT NULL,
    platform VARCHAR(20) NOT NULL,
    device_name VARCHAR(100),
    device_model VARCHAR(100),
    app_version VARCHAR(20),
    os_version VARCHAR(20),
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    last_used BIGINT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    CONSTRAINT fk_tenant_device_user FOREIGN KEY (user_id, tenant_id)
        REFERENCES users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_device_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_device_token_per_tenant
    ON tenant_device_tokens(device_token, tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_device_id_per_tenant
    ON tenant_device_tokens(id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_device_token_user
    ON tenant_device_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_tenant_device_token_tenant
    ON tenant_device_tokens(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_device_token_active
    ON tenant_device_tokens(is_active);

CREATE TABLE IF NOT EXISTS tenant_ciba_auth_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_req_id VARCHAR(255) NOT NULL UNIQUE,
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    user_email VARCHAR(255) NOT NULL,
    client_id UUID,
    device_token_id UUID NOT NULL,
    binding_message VARCHAR(255),
    scopes JSONB DEFAULT '[]',
    status VARCHAR(50) DEFAULT 'pending' NOT NULL,
    biometric_verified BOOLEAN DEFAULT FALSE,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    responded_at BIGINT,
    last_polled_at BIGINT,
    CONSTRAINT fk_tenant_ciba_user FOREIGN KEY (user_id, tenant_id)
        REFERENCES users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_ciba_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_ciba_device FOREIGN KEY (device_token_id, tenant_id)
        REFERENCES tenant_device_tokens(id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tenant_ciba_user
    ON tenant_ciba_auth_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_tenant_ciba_tenant
    ON tenant_ciba_auth_requests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_ciba_status
    ON tenant_ciba_auth_requests(status);
CREATE INDEX IF NOT EXISTS idx_tenant_ciba_expires_at
    ON tenant_ciba_auth_requests(expires_at);
CREATE INDEX IF NOT EXISTS idx_tenant_ciba_user_status
    ON tenant_ciba_auth_requests(user_id, status);

CREATE TABLE IF NOT EXISTS tenant_totp_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    secret VARCHAR(64) NOT NULL,
    device_name VARCHAR(100),
    device_type VARCHAR(50) DEFAULT 'generic',
    last_used BIGINT,
    is_verified BOOLEAN DEFAULT FALSE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_primary BOOLEAN DEFAULT FALSE NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    CONSTRAINT fk_tenant_totp_user FOREIGN KEY (user_id, tenant_id)
        REFERENCES users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_totp_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tenant_totp_user
    ON tenant_totp_secrets(user_id);
CREATE INDEX IF NOT EXISTS idx_tenant_totp_tenant
    ON tenant_totp_secrets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_totp_active
    ON tenant_totp_secrets(is_active);
CREATE INDEX IF NOT EXISTS idx_tenant_totp_verified
    ON tenant_totp_secrets(is_verified);
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_totp_primary_device
    ON tenant_totp_secrets(user_id, tenant_id)
    WHERE is_primary = TRUE;

CREATE TABLE IF NOT EXISTS tenant_totp_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    code VARCHAR(64) NOT NULL UNIQUE,
    is_used BOOLEAN DEFAULT FALSE NOT NULL,
    created_at BIGINT NOT NULL,
    used_at BIGINT,
    CONSTRAINT fk_tenant_backup_user FOREIGN KEY (user_id, tenant_id)
        REFERENCES users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_backup_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tenant_backup_user
    ON tenant_totp_backup_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_tenant_backup_tenant
    ON tenant_totp_backup_codes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_backup_used
    ON tenant_totp_backup_codes(is_used);
