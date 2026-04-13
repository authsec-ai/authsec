ALTER TABLE auth_request_contexts
  ADD COLUMN IF NOT EXISTS hydra_request_uri VARCHAR(512);

CREATE UNIQUE INDEX IF NOT EXISTS idx_arc_hydra_request_uri
  ON auth_request_contexts(hydra_request_uri)
  WHERE hydra_request_uri IS NOT NULL AND hydra_request_uri != '';
