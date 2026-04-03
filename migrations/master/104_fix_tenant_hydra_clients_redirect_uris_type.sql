-- Convert tenant_hydra_clients.redirect_uris from jsonb to text[]
-- pq.StringArray in Go serializes as PostgreSQL array {val1,val2}, not JSON ["val1","val2"]

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
            ALTER COLUMN redirect_uris TYPE text[]
            USING ARRAY(SELECT jsonb_array_elements_text(redirect_uris));

        ALTER TABLE tenant_hydra_clients
            ALTER COLUMN redirect_uris SET DEFAULT '{}';
    END IF;
END $$;
