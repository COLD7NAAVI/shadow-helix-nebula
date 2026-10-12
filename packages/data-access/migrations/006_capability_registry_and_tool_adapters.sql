-- ============================================================================
-- Migration: 006_capability_registry_and_tool_adapters.sql
-- Description: Establishes capability registry entities, tool adapter definitions,
--              versioning metadata, and workspace bindings.
-- Authoritative Spec: Phase 0.3 (BC-CAP), Phase 0.4 (INV-01, INV-03, INV-04),
--                    Phase 0.7 Section 4.2.3 (mod_capability_registry),
--                    Phase 0.8 (Plugin & Adapter Contracts),
--                    Phase 0.9 (Tool Integration Architecture),
--                    Phase 0.10 (Data Architecture), Phase 0.14
-- ============================================================================

-- Ensure schemas exist
CREATE SCHEMA IF NOT EXISTS capabilities;
CREATE SCHEMA IF NOT EXISTS workspace;
CREATE SCHEMA IF NOT EXISTS iam;

-- ----------------------------------------------------------------------------
-- 1. Capabilities Table
-- Stores canonical abstract capability definitions (both system-wide and workspace-specific).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS capabilities.capabilities (
    internal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    id VARCHAR(255) NOT NULL,
    workspace_id UUID REFERENCES workspace.workspaces(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    version VARCHAR(32) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(64) NOT NULL,
    risk_level VARCHAR(32) NOT NULL DEFAULT 'INFORMATIONAL',
    supported_targets TEXT[] NOT NULL DEFAULT '{}',
    required_permissions BIGINT NOT NULL DEFAULT 0,
    required_scope_action VARCHAR(64) NOT NULL,
    argument_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
    output_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
    environment_requirements JSONB NOT NULL DEFAULT '{}'::jsonb,
    resource_requirements JSONB NOT NULL DEFAULT '{}'::jsonb,
    platform_compatibility TEXT[] NOT NULL DEFAULT '{"linux","darwin","win32"}',
    lifecycle_state VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    integrity_digest VARCHAR(64) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT chk_cap_lifecycle CHECK (lifecycle_state IN (
        'DRAFT', 'ACTIVE', 'DEPRECATED', 'DISABLED', 'REVOKED'
    )),
    CONSTRAINT chk_cap_risk CHECK (risk_level IN (
        'INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INVASIVE'
    ))
);

-- Unique constraints for system vs workspace-scoped capabilities
CREATE UNIQUE INDEX IF NOT EXISTS idx_capabilities_system ON capabilities.capabilities(id) WHERE workspace_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_capabilities_workspace ON capabilities.capabilities(id, workspace_id) WHERE workspace_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_capabilities_category ON capabilities.capabilities(category);
CREATE INDEX IF NOT EXISTS idx_capabilities_state ON capabilities.capabilities(lifecycle_state);

-- ----------------------------------------------------------------------------
-- 2. Tool Adapters Table
-- Stores registered tool adapter provider metadata and capability bindings.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS capabilities.adapters (
    internal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    id VARCHAR(255) NOT NULL,
    workspace_id UUID REFERENCES workspace.workspaces(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    version VARCHAR(32) NOT NULL,
    lifecycle_state VARCHAR(32) NOT NULL DEFAULT 'REGISTERED',
    supported_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    platform_compatibility TEXT[] NOT NULL DEFAULT '{"linux","darwin","win32"}',
    binary_path VARCHAR(512) NOT NULL,
    manifest_digest VARCHAR(64) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT chk_adapter_lifecycle CHECK (lifecycle_state IN (
        'DISCOVERED', 'REGISTERED', 'VALIDATED', 'ENABLED', 'AVAILABLE', 'DISABLED', 'REVOKED'
    ))
);

-- Unique constraints for system vs workspace-scoped adapters
CREATE UNIQUE INDEX IF NOT EXISTS idx_adapters_system ON capabilities.adapters(id) WHERE workspace_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_adapters_workspace ON capabilities.adapters(id, workspace_id) WHERE workspace_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_adapters_state ON capabilities.adapters(lifecycle_state);

-- ----------------------------------------------------------------------------
-- 3. Capability Workspace Bindings
-- Allows workspaces to explicitly enable/disable or override provider priority.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS capabilities.workspace_bindings (
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE CASCADE,
    capability_id VARCHAR(255) NOT NULL,
    preferred_adapter_id VARCHAR(255) NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    overrides JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (workspace_id, capability_id)
);
