-- ============================================================================
-- Migration: 001_initial_schema.sql
-- Description: Establishes iam, workspace, and audit bounded contexts with
--              mechanical database-level immutability for audit.events.
-- Authoritative Spec: Phase 0.4, 0.7, 0.10, 0.11 (SEC-INV-11), 0.14 (API-INV-06)
-- ============================================================================

-- Bounded Context Schemas (ADR-DATA-06 / 0.10 Section 4.1)
CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS workspace;
CREATE SCHEMA IF NOT EXISTS audit;

-- ----------------------------------------------------------------------------
-- 1. IAM Context: Organizations
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iam.organizations (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON iam.organizations (slug);

-- ----------------------------------------------------------------------------
-- 2. Workspace Context: Workspaces
-- Scoped to an organization; multi-tenant hermeticity anchor (DATA-INV-08).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS workspace.workspaces (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES iam.organizations(id) ON DELETE RESTRICT,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(128) NOT NULL,
    environment VARCHAR(32) NOT NULL DEFAULT 'production',
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_workspaces_org_slug UNIQUE (organization_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_workspaces_organization_id ON workspace.workspaces (organization_id);

-- ----------------------------------------------------------------------------
-- 3. IAM Context: Users
-- Scoped to an organization; email uniqueness enforced per organization.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iam.users (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES iam.organizations(id) ON DELETE RESTRICT,
    email VARCHAR(320) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_users_org_email UNIQUE (organization_id, email)
);

CREATE INDEX IF NOT EXISTS idx_users_org_id ON iam.users (organization_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON iam.users (email);

-- ----------------------------------------------------------------------------
-- 4. Audit Context: Append-Only Immutable Event Ledger
-- Preserves all 13 canonical event envelope fields (API-INV-06 / 0.14 Section 13).
-- Mechanical mutation rejection enforced via PostgreSQL triggers (SEC-INV-11 / DATA-INV-07).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit.events (
    event_id UUID PRIMARY KEY,
    event_type VARCHAR(255) NOT NULL,
    schema_version VARCHAR(32) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    producer JSONB NOT NULL,
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE RESTRICT,
    correlation_id UUID NOT NULL,
    causation_id UUID NOT NULL,
    trace_id VARCHAR(128) NOT NULL,
    authorization_context JSONB NOT NULL,
    scope_reference JSONB NOT NULL,
    payload JSONB NOT NULL,
    integrity JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Performance & Query Indices
CREATE INDEX IF NOT EXISTS idx_audit_events_workspace_id ON audit.events (workspace_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at ON audit.events (occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_correlation_id ON audit.events (correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_causation_id ON audit.events (causation_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit.events (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_payload_gin ON audit.events USING GIN (payload);

-- ----------------------------------------------------------------------------
-- 5. Mechanical Immutability Trigger for Audit Events
-- Rejects UPDATE, DELETE, and TRUNCATE at database engine level.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit.reject_audit_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Forbidden: audit.events is an append-only immutable ledger. Operation % rejected by database engine (SEC-INV-11 / DATA-INV-07)', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_events_immutable_mutation ON audit.events;
CREATE TRIGGER trg_audit_events_immutable_mutation
BEFORE UPDATE OR DELETE ON audit.events
FOR EACH ROW
EXECUTE FUNCTION audit.reject_audit_mutation();

DROP TRIGGER IF EXISTS trg_audit_events_immutable_truncate ON audit.events;
CREATE TRIGGER trg_audit_events_immutable_truncate
BEFORE TRUNCATE ON audit.events
FOR EACH STATEMENT
EXECUTE FUNCTION audit.reject_audit_mutation();
