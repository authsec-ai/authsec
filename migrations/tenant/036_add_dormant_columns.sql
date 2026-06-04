-- Adds columns needed to track dormant-list enrollment state per user.
-- dormant_enrolled: true once the user has been added to the dormant re-engagement list.
-- dormant_enrolled_at: timestamp of the most recent dormant enrollment (used for 90-day cooloff).
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS dormant_enrolled    BOOLEAN   NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS dormant_enrolled_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX IF NOT EXISTS idx_users_dormant_enrolled
    ON users (dormant_enrolled, last_login)
    WHERE active = true;
