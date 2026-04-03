-- Migration: Add Missing Foreign Key Constraints
-- Description: Add referential integrity constraints to prevent orphaned records

-- =====================================================
-- FOREIGN KEY CONSTRAINTS FOR REFERENTIAL INTEGRITY
-- =====================================================

-- 1. Permissions table foreign keys
-- Ensure all permission records reference valid roles, scopes, and resources

-- Permissions -> Roles
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'fk_permissions_role_id' 
        AND table_name = 'permissions'
    ) THEN
        -- Validate data to avoid deleting existing records
        IF EXISTS (
            SELECT 1 FROM permissions 
            WHERE role_id NOT IN (SELECT id FROM roles WHERE id IS NOT NULL)
        ) THEN
            RAISE EXCEPTION 'Migration 047 aborted: permissions contains role_id values without matching roles. Resolve data manually before rerunning.';
        END IF;
        
        ALTER TABLE permissions 
        ADD CONSTRAINT fk_permissions_role_id 
        FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE;
        
        RAISE NOTICE 'Added foreign key: fk_permissions_role_id';
    END IF;
END $$;

-- Permissions -> Scopes
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'fk_permissions_scope_id' 
        AND table_name = 'permissions'
    ) THEN
        -- Validate data to avoid deleting existing records
        IF EXISTS (
            SELECT 1 FROM permissions 
            WHERE scope_id NOT IN (SELECT id FROM scopes WHERE id IS NOT NULL)
        ) THEN
            RAISE EXCEPTION 'Migration 047 aborted: permissions contains scope_id values without matching scopes. Resolve data manually before rerunning.';
        END IF;
        
        ALTER TABLE permissions 
        ADD CONSTRAINT fk_permissions_scope_id 
        FOREIGN KEY (scope_id) REFERENCES scopes(id) ON DELETE CASCADE;
        
        RAISE NOTICE 'Added foreign key: fk_permissions_scope_id';
    END IF;
END $$;

-- 3. Projects -> Tenants
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'fk_projects_tenant_id' 
        AND table_name = 'projects'
    ) THEN
        -- Validate data to avoid deleting existing records
        IF EXISTS (
            SELECT 1 FROM projects 
            WHERE tenant_id NOT IN (SELECT id FROM tenants WHERE id IS NOT NULL)
        ) THEN
            RAISE EXCEPTION 'Migration 047 aborted: projects contains tenant_id values without matching tenants. Resolve data manually before rerunning.';
        END IF;
        
        ALTER TABLE projects 
        ADD CONSTRAINT fk_projects_tenant_id 
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
        
        RAISE NOTICE 'Added foreign key: fk_projects_tenant_id';
    END IF;
END $$;

-- =====================================================
-- VALIDATION AND CLEANUP
-- =====================================================

-- Create function to validate foreign key integrity
DO $$
BEGIN
    -- Validate permissions integrity
    IF EXISTS (
        SELECT 1 FROM permissions p 
        LEFT JOIN roles r ON p.role_id = r.id 
        WHERE r.id IS NULL
    ) THEN
        RAISE WARNING 'Found orphaned permissions records with invalid role_id';
    END IF;
    
    IF EXISTS (
        SELECT 1 FROM permissions p 
        LEFT JOIN scopes s ON p.scope_id = s.id 
        WHERE s.id IS NULL
    ) THEN
        RAISE WARNING 'Found orphaned permissions records with invalid scope_id';
    END IF;
    
    RAISE NOTICE 'Migration 047: Foreign key constraints added successfully';
    RAISE NOTICE 'Tables affected: permissions, projects';
END $$;
