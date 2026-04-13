-- Migration 112: Hydra login_challenge values can exceed varchar(255)
-- Expand the bridge column to TEXT so local and real login flows bind cleanly.

ALTER TABLE auth_request_contexts
    ALTER COLUMN login_challenge TYPE TEXT;
