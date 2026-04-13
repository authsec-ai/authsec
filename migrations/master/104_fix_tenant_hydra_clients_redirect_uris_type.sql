-- Convert tenant_hydra_clients.redirect_uris from jsonb to text[]
-- pq.StringArray in Go serializes as PostgreSQL array {val1,val2}, not JSON ["val1","val2"]

CREATE OR REPLACE FUNCTION _authsec_jsonb_to_text_array(input jsonb)
RETURNS text[]
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT COALESCE(array_agg(value), ARRAY[]::text[])
    FROM jsonb_array_elements_text(input) AS t(value)
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tenant_hydra_clients'
          AND column_name = 'redirect_uris'
          AND data_type = 'jsonb'
    ) THEN
        -- Convert existing jsonb values to text[]
        -- jsonb '["a","b"]' -> text[] '{a,b}'
        ALTER TABLE tenant_hydra_clients
            ALTER COLUMN redirect_uris DROP DEFAULT;

        ALTER TABLE tenant_hydra_clients
            ALTER COLUMN redirect_uris TYPE text[]
            USING _authsec_jsonb_to_text_array(redirect_uris);

        ALTER TABLE tenant_hydra_clients
            ALTER COLUMN redirect_uris SET DEFAULT '{}';
    END IF;
END $$;

DROP FUNCTION IF EXISTS _authsec_jsonb_to_text_array(jsonb);
