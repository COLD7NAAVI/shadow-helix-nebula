-- ============================================================================
-- Migration: 008_comprehensive_platform_schema.sql
-- Description: Establishes persistent storage for UI preferences & layouts,
--              AI provider configurations & credentials, AI security recommendations,
--              graph relationship layouts & annotations, professional reports,
--              and threat intelligence / vulnerability reference cache.
-- ============================================================================

-- Ensure schemas exist
CREATE SCHEMA IF NOT EXISTS ui;
CREATE SCHEMA IF NOT EXISTS ai;
CREATE SCHEMA IF NOT EXISTS reporting;
CREATE SCHEMA IF NOT EXISTS threat_intel;
CREATE SCHEMA IF NOT EXISTS workspace;
CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS inventory;
CREATE SCHEMA IF NOT EXISTS findings;

-- ----------------------------------------------------------------------------
-- 1. UI Preferences & Saved Dashboard Layouts
-- Persists user theme, accent colors, display density, and dashboard panel layouts.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ui.user_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspace.workspaces(id) ON DELETE CASCADE,
    theme VARCHAR(32) NOT NULL DEFAULT 'cyber-operations',
    accent_color VARCHAR(32) NOT NULL DEFAULT 'cyan',
    density VARCHAR(32) NOT NULL DEFAULT 'comfortable',
    reduced_motion BOOLEAN NOT NULL DEFAULT false,
    dashboard_layout JSONB NOT NULL DEFAULT '{
        "panels": [
            {"id": "geo-intel", "visible": true, "order": 1, "colSpan": 2},
            {"id": "telemetry", "visible": true, "order": 2, "colSpan": 1},
            {"id": "active-scope", "visible": true, "order": 3, "colSpan": 1},
            {"id": "severity-donut", "visible": true, "order": 4, "colSpan": 1},
            {"id": "recent-executions", "visible": true, "order": 5, "colSpan": 2},
            {"id": "ai-recommendations", "visible": true, "order": 6, "colSpan": 1},
            {"id": "activity-feed", "visible": true, "order": 7, "colSpan": 2}
        ],
        "refreshIntervalSec": 10
    }'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_user_pref_user_wks UNIQUE (user_id, workspace_id),
    CONSTRAINT chk_pref_theme CHECK (theme IN ('cyber-operations', 'light', 'ambient')),
    CONSTRAINT chk_pref_accent CHECK (accent_color IN ('cyan', 'emerald', 'violet', 'amber', 'rose')),
    CONSTRAINT chk_pref_density CHECK (density IN ('compact', 'comfortable'))
);

CREATE INDEX IF NOT EXISTS idx_user_preferences_user ON ui.user_preferences (user_id);

-- ----------------------------------------------------------------------------
-- 2. Interactive Graph Layouts & Saved Views
-- Persists Obsidian-like graph node positions, annotations, and view filters.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ui.graph_layouts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL DEFAULT 'Default Graph View',
    is_default BOOLEAN NOT NULL DEFAULT true,
    positions JSONB NOT NULL DEFAULT '{}'::jsonb,
    annotations JSONB NOT NULL DEFAULT '[]'::jsonb,
    filters JSONB NOT NULL DEFAULT '{
        "nodeTypes": ["ASSET", "SERVICE", "FINDING", "SCOPE", "EXECUTION", "HYPOTHESIS"],
        "minSeverity": "INFORMATIONAL",
        "showHypotheses": true
    }'::jsonb,
    created_by UUID NOT NULL REFERENCES iam.users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_graph_layout_wks_name UNIQUE (workspace_id, name)
);

CREATE INDEX IF NOT EXISTS idx_graph_layouts_wks ON ui.graph_layouts (workspace_id);

-- ----------------------------------------------------------------------------
-- 3. Configurable AI Provider Configurations
-- Stores user-configured AI models (OpenAI, Ollama, Anthropic, Local Heuristic).
-- API keys are stored encrypted via secrets.secrets_metadata reference.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai.provider_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES iam.organizations(id) ON DELETE RESTRICT,
    workspace_id UUID REFERENCES workspace.workspaces(id) ON DELETE CASCADE,
    provider_type VARCHAR(64) NOT NULL,
    display_name VARCHAR(128) NOT NULL,
    base_url VARCHAR(512),
    model_name VARCHAR(128) NOT NULL,
    secret_id UUID REFERENCES secrets.metadata(id) ON DELETE SET NULL,
    is_default BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    max_tokens INT NOT NULL DEFAULT 4096,
    temperature NUMERIC(3, 2) NOT NULL DEFAULT 0.20,
    timeout_ms INT NOT NULL DEFAULT 30000,
    health_status VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    last_health_check_at TIMESTAMPTZ,
    health_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    privacy_acknowledged BOOLEAN NOT NULL DEFAULT false,
    created_by UUID NOT NULL REFERENCES iam.users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT chk_ai_provider_type CHECK (provider_type IN (
        'OPENAI_COMPATIBLE', 'OLLAMA', 'ANTHROPIC', 'LOCAL_HEURISTIC'
    )),
    CONSTRAINT chk_ai_health_status CHECK (health_status IN (
        'UNKNOWN', 'HEALTHY', 'DEGRADED', 'UNREACHABLE'
    ))
);

CREATE INDEX IF NOT EXISTS idx_ai_provider_org ON ai.provider_configs (organization_id);
CREATE INDEX IF NOT EXISTS idx_ai_provider_wks ON ai.provider_configs (workspace_id);

-- ----------------------------------------------------------------------------
-- 4. Evidence-Driven AI Security Recommendations
-- Structured, schema-validated recommendations generated from actual findings.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai.recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES iam.organizations(id) ON DELETE RESTRICT,
    recommendation_id VARCHAR(128) NOT NULL,
    objective TEXT NOT NULL,
    rationale TEXT NOT NULL,
    proposed_capability VARCHAR(256) NOT NULL,
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    target VARCHAR(1024) NOT NULL,
    required_scope_action VARCHAR(64) NOT NULL,
    risk_level VARCHAR(32) NOT NULL DEFAULT 'LOW',
    requires_approval BOOLEAN NOT NULL DEFAULT false,
    confidence NUMERIC(3, 2) NOT NULL DEFAULT 0.85,
    supporting_evidence_ids UUID[] NOT NULL DEFAULT '{}',
    assumptions TEXT[] NOT NULL DEFAULT '{}',
    expected_impact TEXT,
    rollback_conditions TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    execution_id UUID REFERENCES execution.executions(id) ON DELETE SET NULL,
    approved_by UUID REFERENCES iam.users(id) ON DELETE SET NULL,
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_ai_recommendation_id UNIQUE (workspace_id, recommendation_id),
    CONSTRAINT chk_ai_rec_status CHECK (status IN (
        'PENDING', 'APPROVED', 'DISMISSED', 'EXECUTING', 'COMPLETED', 'FAILED'
    )),
    CONSTRAINT chk_ai_rec_risk CHECK (risk_level IN (
        'INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    ))
);

CREATE INDEX IF NOT EXISTS idx_ai_recommendations_wks ON ai.recommendations (workspace_id);
CREATE INDEX IF NOT EXISTS idx_ai_recommendations_status ON ai.recommendations (workspace_id, status);

-- ----------------------------------------------------------------------------
-- 5. Professional Reports Table
-- Persists generated security assessment reports with snapshots and hashes.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reporting.reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES iam.organizations(id) ON DELETE RESTRICT,
    title VARCHAR(256) NOT NULL,
    report_type VARCHAR(64) NOT NULL DEFAULT 'EXECUTIVE_SUMMARY',
    scope_id UUID REFERENCES workspace.scopes(id) ON DELETE SET NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'COMPLETED',
    version INT NOT NULL DEFAULT 1,
    summary_content JSONB NOT NULL DEFAULT '{}'::jsonb,
    findings_snapshot JSONB NOT NULL DEFAULT '[]'::jsonb,
    assets_snapshot JSONB NOT NULL DEFAULT '[]'::jsonb,
    executions_snapshot JSONB NOT NULL DEFAULT '[]'::jsonb,
    html_content TEXT,
    content_sha256 VARCHAR(64) NOT NULL,
    generated_by UUID NOT NULL REFERENCES iam.users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT chk_report_type CHECK (report_type IN (
        'EXECUTIVE_SUMMARY', 'TECHNICAL_ASSESSMENT', 'COMPLIANCE_AUDIT', 'EVIDENCE_CATALOG'
    )),
    CONSTRAINT chk_report_status CHECK (status IN (
        'DRAFT', 'GENERATING', 'COMPLETED', 'FAILED'
    ))
);

CREATE INDEX IF NOT EXISTS idx_reports_wks ON reporting.reports (workspace_id);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reporting.reports (created_at DESC);

-- ----------------------------------------------------------------------------
-- 6. Threat Intelligence & Vulnerability Reference Cache
-- Caches CVE, CWE, CVSS, and EPSS scores to cross-reference discovered assets.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_intel.vulnerabilities_cache (
    cve_id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(256),
    description TEXT NOT NULL,
    cvss_score NUMERIC(3, 1),
    cvss_vector VARCHAR(128),
    epss_score NUMERIC(5, 4),
    cwe_id VARCHAR(64),
    exploit_status VARCHAR(64) NOT NULL DEFAULT 'UNVERIFIED',
    advisory_url VARCHAR(512),
    published_at TIMESTAMPTZ,
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT chk_threat_exploit_status CHECK (exploit_status IN (
        'UNVERIFIED', 'PROOF_OF_CONCEPT', 'ACTIVE_EXPLOITATION', 'NOT_APPLICABLE'
    ))
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss ON threat_intel.vulnerabilities_cache (cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cwe ON threat_intel.vulnerabilities_cache (cwe_id);
