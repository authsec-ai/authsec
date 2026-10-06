-- Run once as a role with CREATEROLE when migration 054 could not create the
-- RLS role itself (it logs a NOTICE). Replace <app_user> with the role the
-- backend connects as.
CREATE ROLE authsec_tenant NOLOGIN NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO authsec_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authsec_tenant;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO authsec_tenant;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO authsec_tenant;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO authsec_tenant;
GRANT authsec_tenant TO <app_user>;
