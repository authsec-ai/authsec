-- Migration: 111_alter_role_bindings_add_group_id.sql
-- Description: Extend role_bindings principal model to support groups.
--   Today the table holds (user_id XOR service_account_id). Add group_id as a
--   third optional principal so a single role binding can target a group.
--   Drop and recreate the check_principal constraint to require exactly one of
--   the three columns be non-null.
--
--   Why nullable-FK union (not generic subject_type/subject_id):
--     1. Preserves the existing composite-FK pattern (tenant_id+user_id ->
--        users; tenant_id+service_account_id -> service_accounts).
--     2. Type-safe: each column has its own FK and ON DELETE behavior.
--     3. Avoids a wide migration that would touch every read site.
-- Date: 2026-05-14
-- Phase: A

-- Add the column.
ALTER TABLE role_bindings
    ADD COLUMN IF NOT EXISTS group_id UUID;

-- Composite FK so the group belongs to the same tenant as the binding.
-- Note: `groups.tenant_id` was added in migration 019 and (tenant_id, id) is
-- enforced unique by `uni_groups_tenant_name`'s sibling constraint added below.
DO $$
BEGIN
    -- Ensure (tenant_id, id) on groups is unique so the composite FK can target it.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'groups_tenant_id_id_key'
    ) THEN
        ALTER TABLE groups ADD CONSTRAINT groups_tenant_id_id_key UNIQUE (tenant_id, id);
    END IF;

    -- Add the FK if not already present.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_rb_group'
    ) THEN
        ALTER TABLE role_bindings
            ADD CONSTRAINT fk_rb_group FOREIGN KEY (tenant_id, group_id)
            REFERENCES groups(tenant_id, id) ON DELETE CASCADE;
    END IF;
END $$;

-- Replace the principal check constraint.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'check_principal') THEN
        ALTER TABLE role_bindings DROP CONSTRAINT check_principal;
    END IF;

    ALTER TABLE role_bindings
        ADD CONSTRAINT check_principal CHECK (
            (user_id IS NOT NULL)::int +
            (group_id IS NOT NULL)::int +
            (service_account_id IS NOT NULL)::int = 1
        );
END $$;

-- Index for group-subject scope resolution.
CREATE INDEX IF NOT EXISTS idx_rb_tenant_group ON role_bindings(tenant_id, group_id) WHERE group_id IS NOT NULL;
