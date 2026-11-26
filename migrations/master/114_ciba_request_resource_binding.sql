-- ============================================================================
-- 114: workspace_ciba_auth_requests.resource_server_id
--
-- A CIBA request is bound to the client that started it and to the resource
-- server the user was asked to approve (AS-044). The poll must come from the
-- same client for the same resource server; the token audience is taken from
-- this row, never from the poll.
--
-- Nullable: requests live five minutes, and rows written before this column
-- existed are refused at poll time (no binding to compare against).
-- ============================================================================

ALTER TABLE public.workspace_ciba_auth_requests
    ADD COLUMN IF NOT EXISTS resource_server_id uuid;
