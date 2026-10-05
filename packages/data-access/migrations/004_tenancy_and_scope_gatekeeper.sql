-- ============================================================================
-- Migration: 004_tenancy_and_scope_gatekeeper.sql
-- Description: Establishes workspace scopes and operational boundary definitions
--              for mechanical pre-dispatch target gatekeeping.
-- Authoritative Spec: Phase 0.1 (Section 18), Phase 0.3 (BC-SCP),
--                    Phase 0.4 (INV-06, INV-19), Phase 0.7 (mod_scope_gatekeeper),
--                    Phase 0.10 (Section 4.2), Phase 0.11 (Section 10),
--                    Phase 0.14 (Section 20, API-INV-02)
-- ============================================================================

-- Ensure schemas exist
CREATE SCHEMA IF NOT EXISTS workspace;
CREATE SCHEMA IF NOT EXISTS iam;

-- ----------------------------------------------------------------------------
-- 1. Workspace Context: Scope Boundaries
-- Strictly scoped to a workspace and organization; multi-tenant hermeticity.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS workspace.scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE RESTRICT,
    organization_id UUID NOT NULL REFERENCES iam.organizations(id) ON DELETE RESTRICT,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    inclusions JSONB NOT NULL DEFAULT '[]'::jsonb,
    exclusions JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    disallowed_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    port_ranges JSONB NOT NULL DEFAULT '[]'::jsonb,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    rate_limits JSONB NOT NULL DEFAULT '{}'::jsonb,
    scope_sha256 VARCHAR(64) NOT NULL,
    created_by UUID REFERENCES iam.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_workspace_scopes_name UNIQUE (workspace_id, name),
    CONSTRAINT chk_scope_status CHECK (status IN ('ACTIVE', 'SUSPENDED', 'ARCHIVED', 'EXPIRED')),
    CONSTRAINT chk_scope_window CHECK (valid_from <= valid_until)
);

CREATE INDEX IF NOT EXISTS idx_workspace_scopes_wks ON workspace.scopes (workspace_id);
CREATE INDEX IF NOT EXISTS idx_workspace_scopes_org ON workspace.scopes (organization_id);
CREATE INDEX IF NOT EXISTS idx_workspace_scopes_status ON workspace.scopes (status);
CREATE INDEX IF NOT EXISTS idx_workspace_scopes_window ON workspace.scopes (valid_from, valid_until);
CREATE INDEX IF NOT EXISTS idx_workspace_scopes_sha256 ON workspace.scopes (scope_sha256);
