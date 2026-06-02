-- application_drift_events: records post-activation destructive admin
-- edits so the workspace banner can surface "what changed since activation."
-- Backport-lean equivalent of dev's resource_server_drift_events.
--
-- The check constraint lists the event types the backport actually emits.
-- Dev's full list is larger (scope_deleted, tool_unmapped, etc.); those
-- come in later phases when the corresponding admin mutations land.

CREATE TABLE IF NOT EXISTS application_drift_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    application_id UUID NOT NULL REFERENCES resource_servers(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    event_payload JSONB,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    occurred_by UUID,
    CONSTRAINT application_drift_events_type_chk CHECK (event_type IN (
        'secret_rotated',
        'default_role_disabled',
        'connection_revoked',
        'tool_unmapped',
        'scope_deleted'
    ))
);

CREATE INDEX IF NOT EXISTS idx_app_drift_events_application ON application_drift_events(application_id);
CREATE INDEX IF NOT EXISTS idx_app_drift_events_occurred_at ON application_drift_events(occurred_at);

-- application_drift_event_dismissals: per-admin dismissals of drift events.
-- One row per (event, admin) — primary key is the composite.

CREATE TABLE IF NOT EXISTS application_drift_event_dismissals (
    event_id UUID NOT NULL REFERENCES application_drift_events(id) ON DELETE CASCADE,
    admin_user_id UUID NOT NULL,
    dismissed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT application_drift_event_dismissals_pkey PRIMARY KEY (event_id, admin_user_id)
);
