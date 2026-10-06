-- ============================================================================
-- Migration: 005_execution_supervisor_and_sandboxed_worker.sql
-- Description: Establishes execution control-plane entities, attempts,
--              artifacts, and worker leases for sandboxed execution supervision.
-- Authoritative Spec: Phase 0.3 (BC-EXE, BC-WFO), Phase 0.4 (INV-01, INV-14),
--                    Phase 0.7 (mod_execution_supervisor), Phase 0.9 (Sections 7 & 8),
--                    Phase 0.10 (Sections 4 & 5), Phase 0.14 (Perimeter D, Section 19)
-- ============================================================================

-- Ensure schemas exist
CREATE SCHEMA IF NOT EXISTS execution;
CREATE SCHEMA IF NOT EXISTS workspace;
CREATE SCHEMA IF NOT EXISTS iam;

-- ----------------------------------------------------------------------------
-- 1. Execution Control Plane: Executions
-- Authoritative state machine record for all capability/tool executions.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS execution.executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE RESTRICT,
    organization_id UUID NOT NULL REFERENCES iam.organizations(id) ON DELETE RESTRICT,
    scope_id UUID REFERENCES workspace.scopes(id) ON DELETE SET NULL,
    action VARCHAR(64) NOT NULL,
    target VARCHAR(1024) NOT NULL,
    capability_uri VARCHAR(256) NOT NULL,
    state VARCHAR(32) NOT NULL DEFAULT 'CREATED',
    requested_by UUID NOT NULL REFERENCES iam.users(id) ON DELETE RESTRICT,
    command JSONB NOT NULL DEFAULT '{}'::jsonb,
    resource_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    execution_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    worker_spec JSONB NOT NULL DEFAULT '{}'::jsonb,
    result_payload JSONB,
    failure_details JSONB,
    stdout_summary TEXT,
    stderr_summary TEXT,
    raw_output_sha256 VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version INT NOT NULL DEFAULT 1,
    CONSTRAINT chk_exec_state CHECK (state IN (
        'CREATED', 'VALIDATING', 'AUTHORIZED', 'QUEUED', 'STARTING',
        'RUNNING', 'CANCELLING', 'SUCCEEDED', 'FAILED', 'TIMED_OUT',
        'CANCELLED', 'TERMINATED', 'REJECTED'
    ))
);

CREATE INDEX IF NOT EXISTS idx_execution_executions_wks ON execution.executions (workspace_id);
CREATE INDEX IF NOT EXISTS idx_execution_executions_org ON execution.executions (organization_id);
CREATE INDEX IF NOT EXISTS idx_execution_executions_state ON execution.executions (workspace_id, state);
CREATE INDEX IF NOT EXISTS idx_execution_executions_created ON execution.executions (created_at DESC);

-- ----------------------------------------------------------------------------
-- 2. Execution Attempts
-- Historical execution attempt records per execution ID.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS execution.execution_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID NOT NULL REFERENCES execution.executions(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE RESTRICT,
    attempt_number INT NOT NULL DEFAULT 1,
    worker_id VARCHAR(128) NOT NULL,
    state VARCHAR(32) NOT NULL,
    exit_code INT,
    termination_reason VARCHAR(64),
    started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ,
    duration_ms INT
);

CREATE INDEX IF NOT EXISTS idx_execution_attempts_exec ON execution.execution_attempts (execution_id);
CREATE INDEX IF NOT EXISTS idx_execution_attempts_worker ON execution.execution_attempts (worker_id);

-- ----------------------------------------------------------------------------
-- 3. Execution Artifacts
-- Content-addressed cryptographic pointers to execution evidence and outputs.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS execution.execution_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID NOT NULL REFERENCES execution.executions(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE RESTRICT,
    name VARCHAR(256) NOT NULL,
    content_sha256 VARCHAR(64) NOT NULL,
    storage_uri VARCHAR(1024) NOT NULL,
    byte_size BIGINT NOT NULL,
    mime_type VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_execution_artifacts_exec ON execution.execution_artifacts (workspace_id, execution_id);
CREATE INDEX IF NOT EXISTS idx_execution_artifacts_sha ON execution.execution_artifacts (content_sha256);

-- ----------------------------------------------------------------------------
-- 4. Worker Leases
-- Tracks worker registration, assigned executions, liveness, and heartbeats.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS execution.worker_leases (
    worker_id VARCHAR(128) PRIMARY KEY,
    execution_id UUID REFERENCES execution.executions(id) ON DELETE SET NULL,
    workspace_id UUID REFERENCES workspace.workspaces(id) ON DELETE RESTRICT,
    status VARCHAR(32) NOT NULL DEFAULT 'IDLE',
    heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT chk_worker_lease_status CHECK (status IN ('IDLE', 'BUSY', 'DRAINING', 'TERMINATED'))
);

CREATE INDEX IF NOT EXISTS idx_execution_worker_leases_status ON execution.worker_leases (status, lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_execution_worker_leases_exec ON execution.worker_leases (execution_id);
