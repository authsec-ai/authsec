-- Migration 060: Ensure role_scopes table exists with required indexes and relax users.project_id constraint
CREATE TABLE IF NOT EXISTS role_scopes(
    id SERIAL NOT NULL,
    role_id uuid,
    scope_id uuid,
    created_at timestamp with time zone DEFAULT now(),
    PRIMARY KEY(id)
);
CREATE INDEX IF NOT EXISTS idx_role_scopes_scope_id ON public.role_scopes USING btree (scope_id);
CREATE UNIQUE INDEX IF NOT EXISTS role_scopes_role_id_scope_id_key ON public.role_scopes USING btree (role_id, scope_id);
CREATE INDEX IF NOT EXISTS idx_role_scopes_role_id ON public.role_scopes USING btree (role_id);




ALTER TABLE users
ALTER COLUMN project_id DROP NOT NULL;
