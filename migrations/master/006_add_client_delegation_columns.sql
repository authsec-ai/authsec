-- Migration: 006_add_client_delegation_columns.sql
-- Description: Adds deleted, client_type, agent_type, spiffe_id columns to clients table
-- Source: authsec-migration repo (migration 003) — needed for existing deployments
--         where base schema (000) was applied before these columns existed.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clients' AND column_name = 'deleted') THEN
        ALTER TABLE clients ADD COLUMN deleted BOOLEAN DEFAULT false;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clients' AND column_name = 'client_type') THEN
        ALTER TABLE clients ADD COLUMN client_type VARCHAR(255);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clients' AND column_name = 'agent_type') THEN
        ALTER TABLE clients ADD COLUMN agent_type TEXT;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clients' AND column_name = 'spiffe_id') THEN
        ALTER TABLE clients ADD COLUMN spiffe_id TEXT;
    END IF;
END $$;
