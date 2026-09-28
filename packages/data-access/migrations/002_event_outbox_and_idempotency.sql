-- ============================================================================
-- Migration: 002_event_outbox_and_idempotency.sql
-- Description: Establishes events bounded-context schema with transactional
--              outbox, consumer deduplication log, and dead-letter quarantine.
-- Authoritative Spec: Phase 0.10, 0.14 (Sections 12, 13, 16, 17, 35.7),
--                    ADR-API-04, API-INV-06, API-INV-09, DATA-INV-08
-- ============================================================================

-- Bounded Context Schema for Event Infrastructure
CREATE SCHEMA IF NOT EXISTS events;

-- ----------------------------------------------------------------------------
-- 1. Events Context: Transactional Outbox
-- Guarantees atomic domain write + event persistence within caller transaction.
-- Polled concurrently via SELECT ... FOR UPDATE SKIP LOCKED.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events.outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL UNIQUE,
    event_type VARCHAR(255) NOT NULL,
    schema_version VARCHAR(32) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE RESTRICT,
    correlation_id UUID NOT NULL,
    causation_id UUID NOT NULL,
    trace_id VARCHAR(128) NOT NULL,
    envelope JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempt_count INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    claimed_at TIMESTAMPTZ,
    claimed_by VARCHAR(128),
    lease_expires_at TIMESTAMPTZ,
    last_error TEXT,
    error_details JSONB,
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT chk_outbox_status CHECK (status IN ('PENDING', 'PROCESSING', 'PUBLISHED', 'FAILED', 'DEAD_LETTER'))
);

-- Performance & Polling Indices
CREATE INDEX IF NOT EXISTS idx_outbox_poll ON events.outbox (status, next_attempt_at)
    WHERE status IN ('PENDING', 'PROCESSING');
CREATE INDEX IF NOT EXISTS idx_outbox_lease_expiry ON events.outbox (lease_expires_at)
    WHERE status = 'PROCESSING';
CREATE INDEX IF NOT EXISTS idx_outbox_workspace_id ON events.outbox (workspace_id);
CREATE INDEX IF NOT EXISTS idx_outbox_correlation_id ON events.outbox (correlation_id);
CREATE INDEX IF NOT EXISTS idx_outbox_event_type ON events.outbox (event_type);
CREATE INDEX IF NOT EXISTS idx_outbox_created_at ON events.outbox (created_at);

-- ----------------------------------------------------------------------------
-- 2. Events Context: Consumer Deduplication Log
-- Enforces effectively-once processing across retried event deliveries (ADR-API-04).
-- Idempotency key format: ${consumer_id}:${event_id}
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events.deduplication_log (
    idempotency_key VARCHAR(255) PRIMARY KEY,
    event_id UUID NOT NULL,
    consumer_id VARCHAR(128) NOT NULL,
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE RESTRICT,
    status VARCHAR(32) NOT NULL DEFAULT 'COMPLETED',
    processed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT chk_dedup_status CHECK (status IN ('IN_FLIGHT', 'COMPLETED', 'FAILED'))
);

CREATE INDEX IF NOT EXISTS idx_dedup_event_id ON events.deduplication_log (event_id);
CREATE INDEX IF NOT EXISTS idx_dedup_workspace_id ON events.deduplication_log (workspace_id);
CREATE INDEX IF NOT EXISTS idx_dedup_expires_at ON events.deduplication_log (expires_at);

-- ----------------------------------------------------------------------------
-- 3. Events Context: Dead-Letter Queue (DLQ) Quarantine
-- Durable storage for poison-pill events exceeding retry limits (Section 35.7).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events.dead_letter (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL UNIQUE,
    event_type VARCHAR(255) NOT NULL,
    schema_version VARCHAR(32) NOT NULL,
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE RESTRICT,
    correlation_id UUID NOT NULL,
    causation_id UUID NOT NULL,
    trace_id VARCHAR(128) NOT NULL,
    envelope JSONB NOT NULL,
    attempt_count INT NOT NULL,
    last_error TEXT NOT NULL,
    error_details JSONB,
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    replayed_at TIMESTAMPTZ,
    replayed_by VARCHAR(128),
    replay_count INT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_dead_letter_workspace_id ON events.dead_letter (workspace_id);
CREATE INDEX IF NOT EXISTS idx_dead_letter_correlation_id ON events.dead_letter (correlation_id);
CREATE INDEX IF NOT EXISTS idx_dead_letter_event_type ON events.dead_letter (event_type);
CREATE INDEX IF NOT EXISTS idx_dead_letter_quarantined_at ON events.dead_letter (quarantined_at);
