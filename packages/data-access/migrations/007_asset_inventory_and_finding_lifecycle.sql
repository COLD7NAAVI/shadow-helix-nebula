-- ============================================================================
-- Migration: 007_asset_inventory_and_finding_lifecycle.sql
-- Description: Establishes tenant- and workspace-scoped asset inventory,
--              vulnerability findings, risk scoring, evidence hashes, and
--              formal finding lifecycle state transition audit history.
-- Authoritative Spec: Phase 0.3 (BC-NRM, BC-FND), Phase 0.4 (INV-01, INV-05, INV-11),
--                    Phase 0.7 Section 4.3.5 (mod_finding_lifecycle),
--                    Phase 0.9 (Sections 6, 7 & 8),
--                    Phase 0.10 (Sections 4, 6 & 7),
--                    Phase 0.14 (Perimeter B, Level 2/3 REST)
-- ============================================================================

-- Ensure schemas exist
CREATE SCHEMA IF NOT EXISTS inventory;
CREATE SCHEMA IF NOT EXISTS findings;
CREATE SCHEMA IF NOT EXISTS workspace;
CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS execution;

-- ----------------------------------------------------------------------------
-- 1. Asset Inventory Table
-- Stores normalized, canonicalized, deduplicated network targets and host assets.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS inventory.assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES iam.organizations(id) ON DELETE RESTRICT,
    type VARCHAR(32) NOT NULL,
    canonical_value VARCHAR(1024) NOT NULL,
    name VARCHAR(256) NOT NULL,
    criticality VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    tags TEXT[] NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_asset_workspace_type_canonical UNIQUE (workspace_id, type, canonical_value),
    CONSTRAINT chk_asset_type CHECK (type IN ('IPV4', 'IPV6', 'CIDR', 'FQDN', 'URL', 'HOST')),
    CONSTRAINT chk_asset_criticality CHECK (criticality IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT chk_asset_status CHECK (status IN ('ACTIVE', 'INACTIVE', 'ARCHIVED'))
);

CREATE INDEX IF NOT EXISTS idx_inventory_assets_wks ON inventory.assets (workspace_id);
CREATE INDEX IF NOT EXISTS idx_inventory_assets_type ON inventory.assets (workspace_id, type);
CREATE INDEX IF NOT EXISTS idx_inventory_assets_status ON inventory.assets (workspace_id, status);
CREATE INDEX IF NOT EXISTS idx_inventory_assets_canonical ON inventory.assets (canonical_value);

-- ----------------------------------------------------------------------------
-- 2. Vulnerability Findings Table
-- Stores vulnerability findings with formal lifecycle states, CVSS risk scoring,
-- and mandatory cryptographic evidence hashes (INV-05).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings.findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES iam.organizations(id) ON DELETE RESTRICT,
    asset_id UUID NOT NULL REFERENCES inventory.assets(id) ON DELETE CASCADE,
    execution_id UUID REFERENCES execution.executions(id) ON DELETE SET NULL,
    title VARCHAR(256) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL DEFAULT 'INFORMATIONAL',
    cve_id VARCHAR(64),
    cwe_id VARCHAR(64),
    cvss_score NUMERIC(3, 1),
    cvss_vector VARCHAR(128),
    status VARCHAR(32) NOT NULL DEFAULT 'DRAFT',
    raw_evidence_sha256 VARCHAR(64) NOT NULL,
    evidence_artifact_id UUID REFERENCES execution.execution_artifacts(id) ON DELETE SET NULL,
    remediation_guidance TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT chk_finding_severity CHECK (severity IN (
        'INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    )),
    CONSTRAINT chk_finding_status CHECK (status IN (
        'DRAFT', 'UNDER_REVIEW', 'CONFIRMED', 'REMEDIATED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'
    )),
    CONSTRAINT chk_finding_cvss CHECK (cvss_score IS NULL OR (cvss_score >= 0.0 AND cvss_score <= 10.0))
);

CREATE INDEX IF NOT EXISTS idx_findings_workspace ON findings.findings (workspace_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings.findings (workspace_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings.findings (workspace_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings.findings (workspace_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_evidence_sha ON findings.findings (raw_evidence_sha256);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings.findings (cve_id);

-- ----------------------------------------------------------------------------
-- 3. Finding Status Transitions Table (Audit History)
-- Immutable audit log of all lifecycle state transitions (MOD-INV-04).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings.finding_status_transitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings.findings(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE CASCADE,
    from_status VARCHAR(32) NOT NULL,
    to_status VARCHAR(32) NOT NULL,
    changed_by UUID NOT NULL REFERENCES iam.users(id) ON DELETE RESTRICT,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_finding_transitions_finding ON findings.finding_status_transitions (finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_transitions_wks ON findings.finding_status_transitions (workspace_id);
