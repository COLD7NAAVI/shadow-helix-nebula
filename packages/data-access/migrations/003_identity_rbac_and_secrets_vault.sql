-- ============================================================================
-- Migration: 003_identity_rbac_and_secrets_vault.sql
-- Description: Establishes credentials, sessions, roles, permissions, user_roles,
--              and secrets vault schemas (metadata + encrypted versions).
-- Authoritative Spec: Phase 0.3 (BC-IAM), 0.7 (mod_auth_rbac, mod_secrets_vault),
--                    0.10 (Section 9), 0.11 (Sections 3, 6, SEC-INV-05, SEC-INV-12),
--                    0.14 (Section 19, ADR-API-06)
-- ============================================================================

-- Ensure schemas exist
CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS secrets;

-- ----------------------------------------------------------------------------
-- 1. IAM Context: User Credentials
-- Plaintext passwords are NEVER stored. Scrypt hash with unique salt.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iam.user_credentials (
    user_id UUID PRIMARY KEY REFERENCES iam.users(id) ON DELETE RESTRICT,
    password_hash VARCHAR(255) NOT NULL,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_authenticated_at TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT chk_failed_attempts CHECK (failed_attempts >= 0)
);

-- ----------------------------------------------------------------------------
-- 2. IAM Context: Sessions & Refresh Tokens
-- Stores SHA-256 hashes of tokens; plaintext tokens are NEVER persisted.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iam.sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES iam.users(id) ON DELETE RESTRICT,
    organization_id UUID NOT NULL REFERENCES iam.organizations(id) ON DELETE RESTRICT,
    workspace_id UUID REFERENCES workspace.workspaces(id) ON DELETE RESTRICT,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    refresh_token_hash VARCHAR(64) UNIQUE,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    ip_address VARCHAR(45),
    user_agent VARCHAR(512),
    expires_at TIMESTAMPTZ NOT NULL,
    refreshed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT chk_session_status CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON iam.sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON iam.sessions (token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_hash ON iam.sessions (refresh_token_hash) WHERE refresh_token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON iam.sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_org_wks ON iam.sessions (organization_id, workspace_id);

-- ----------------------------------------------------------------------------
-- 3. IAM Context: Roles
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iam.roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(64) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    is_system BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- ----------------------------------------------------------------------------
-- 4. IAM Context: Permissions
-- Stores permission names and distinct bitmask flags for microsecond checks.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iam.permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(64) NOT NULL UNIQUE,
    bitmask INT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- ----------------------------------------------------------------------------
-- 5. IAM Context: Role-Permission Mappings
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iam.role_permissions (
    role_id UUID NOT NULL REFERENCES iam.roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES iam.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- ----------------------------------------------------------------------------
-- 6. IAM Context: User Role Assignments
-- Bounded by organization and optionally workspace scope.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iam.user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES iam.users(id) ON DELETE RESTRICT,
    role_id UUID NOT NULL REFERENCES iam.roles(id) ON DELETE RESTRICT,
    organization_id UUID NOT NULL REFERENCES iam.organizations(id) ON DELETE RESTRICT,
    workspace_id UUID REFERENCES workspace.workspaces(id) ON DELETE RESTRICT,
    assigned_by UUID REFERENCES iam.users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_user_roles UNIQUE NULLS NOT DISTINCT (user_id, role_id, organization_id, workspace_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_org ON iam.user_roles (user_id, organization_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_wks ON iam.user_roles (user_id, workspace_id);

-- ----------------------------------------------------------------------------
-- 7. Secrets Context: Metadata Entity
-- Strictly separated from secret ciphertext/material.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS secrets.metadata (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES iam.organizations(id) ON DELETE RESTRICT,
    workspace_id UUID NOT NULL REFERENCES workspace.workspaces(id) ON DELETE RESTRICT,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    secret_type VARCHAR(64) NOT NULL DEFAULT 'GENERIC',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    current_version INT NOT NULL DEFAULT 1,
    tags JSONB NOT NULL DEFAULT '{}'::jsonb,
    access_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ,
    created_by UUID NOT NULL REFERENCES iam.users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_secrets_workspace_name UNIQUE (workspace_id, name),
    CONSTRAINT chk_secret_status CHECK (status IN ('ACTIVE', 'DISABLED', 'REVOKED', 'EXPIRED'))
);

CREATE INDEX IF NOT EXISTS idx_secrets_metadata_wks ON secrets.metadata (workspace_id);
CREATE INDEX IF NOT EXISTS idx_secrets_metadata_org ON secrets.metadata (organization_id);
CREATE INDEX IF NOT EXISTS idx_secrets_metadata_status ON secrets.metadata (status);

-- ----------------------------------------------------------------------------
-- 8. Secrets Context: Encrypted Secret Material (Envelope Encryption)
-- AES-256-GCM ciphertext + wrapped DEK + unique 12-byte IV + 16-byte tag.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS secrets.versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id UUID NOT NULL REFERENCES secrets.metadata(id) ON DELETE CASCADE,
    version INT NOT NULL,
    ciphertext BYTEA NOT NULL,
    encrypted_dek BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    auth_tag BYTEA NOT NULL,
    kek_id VARCHAR(64) NOT NULL,
    algorithm VARCHAR(32) NOT NULL DEFAULT 'AES-256-GCM',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES iam.users(id) ON DELETE SET NULL,
    revocation_reason VARCHAR(255),
    CONSTRAINT uq_secret_versions UNIQUE (secret_id, version),
    CONSTRAINT chk_version_status CHECK (status IN ('ACTIVE', 'SUPERSEDED', 'REVOKED', 'DISABLED'))
);

CREATE INDEX IF NOT EXISTS idx_secret_versions_lookup ON secrets.versions (secret_id, version);
CREATE INDEX IF NOT EXISTS idx_secret_versions_status ON secrets.versions (secret_id, status);

-- ----------------------------------------------------------------------------
-- 9. Seed Canonical System Permissions (Phase 0.11 Section 3.2)
-- ----------------------------------------------------------------------------
INSERT INTO iam.permissions (id, name, bitmask, description) VALUES
    ('00000000-0000-7000-8000-000000000001', 'scope:read', 1, 'View authorized scope boundaries, inclusions, and exclusions'),
    ('00000000-0000-7000-8000-000000000002', 'scope:admin', 2, 'Create, mutate, lock, or archive scope definitions'),
    ('00000000-0000-7000-8000-000000000004', 'workflow:read', 4, 'Inspect workflow definitions, DAG structures, and execution history'),
    ('00000000-0000-7000-8000-000000000008', 'workflow:author', 8, 'Create, edit, compile, and validate declarative workflow graphs'),
    ('00000000-0000-7000-8000-000000000010', 'workflow:execute', 16, 'Dispatch workflow runs and trigger task execution'),
    ('00000000-0000-7000-8000-000000000020', 'recon:passive', 32, 'Execute passive OSINT and non-invasive network observation'),
    ('00000000-0000-7000-8000-000000000040', 'probing:active', 64, 'Execute active port scanning, banner grabbing, and service discovery'),
    ('00000000-0000-7000-8000-000000000080', 'scan:invasive', 128, 'Execute invasive vulnerability exploitation and intrusive scanning'),
    ('00000000-0000-7000-8000-000000000100', 'report:draft', 256, 'Generate and view draft security reports and findings summaries'),
    ('00000000-0000-7000-8000-000000000200', 'report:sign_off', 512, 'Officially approve, digitally seal, and deliver final reports'),
    ('00000000-0000-7000-8000-000000000400', 'secrets:read_metadata', 1024, 'Inspect secret identifiers, aliases, lifecycle states, and expiration'),
    ('00000000-0000-7000-8000-000000000800', 'secrets:read_material', 2048, 'Decrypt and retrieve plaintext secret material (Audited)'),
    ('00000000-0000-7000-8000-000000001000', 'secrets:write', 4096, 'Store, update, and manage secret definitions'),
    ('00000000-0000-7000-8000-000000002000', 'secrets:rotate', 8192, 'Perform cryptographic key and secret material rotation'),
    ('00000000-0000-7000-8000-000000004000', 'secrets:revoke', 16384, 'Immediately revoke or disable secret keys and versions'),
    ('00000000-0000-7000-8000-000000008000', 'audit:read', 32768, 'Inspect immutable operational audit trail and security logs'),
    ('00000000-0000-7000-8000-000000010000', 'iam:admin', 65536, 'Manage user identities, memberships, credentials, and role bindings')
ON CONFLICT (name) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 10. Seed Canonical System Roles (Phase 0.11 Section 3.2)
-- ----------------------------------------------------------------------------
INSERT INTO iam.roles (id, name, description, is_system) VALUES
    ('00000000-0000-7000-8001-000000000001', 'ORG_ADMIN', 'Organization Administrator with comprehensive sovereign authority', true),
    ('00000000-0000-7000-8001-000000000002', 'WORKSPACE_ADMIN', 'Workspace Administrator with full workspace governance rights', true),
    ('00000000-0000-7000-8001-000000000003', 'OPERATOR', 'Operational Security Engineer executing authorized workflows', true),
    ('00000000-0000-7000-8001-000000000004', 'ANALYST', 'Security Analyst reviewing observations, telemetry, and evidence', true),
    ('00000000-0000-7000-8001-000000000005', 'AUDITOR', 'Independent Compliance and Security Auditor with read-only trail access', true),
    ('00000000-0000-7000-8001-000000000006', 'OBSERVER', 'Read-only observer restricted to passive assessment results', true)
ON CONFLICT (name) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 11. Seed Canonical Role-Permission Mappings
-- ----------------------------------------------------------------------------
-- ORG_ADMIN: All permissions
INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM iam.roles r, iam.permissions p
WHERE r.name = 'ORG_ADMIN'
ON CONFLICT DO NOTHING;

-- WORKSPACE_ADMIN: Scope Admin, Workflow Full, Recon, Probing, Invasive Scan, Report Sign-off, Secrets Full, Audit Read
INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM iam.roles r, iam.permissions p
WHERE r.name = 'WORKSPACE_ADMIN'
  AND p.name IN (
    'scope:read', 'scope:admin',
    'workflow:read', 'workflow:author', 'workflow:execute',
    'recon:passive', 'probing:active', 'scan:invasive',
    'report:draft', 'report:sign_off',
    'secrets:read_metadata', 'secrets:read_material', 'secrets:write', 'secrets:rotate', 'secrets:revoke',
    'audit:read'
  )
ON CONFLICT DO NOTHING;

-- OPERATOR: Scope Read, Workflow Author & Execute, Recon, Probing, Invasive Scan, Report Draft, Secrets Read & Material, Audit Read
INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM iam.roles r, iam.permissions p
WHERE r.name = 'OPERATOR'
  AND p.name IN (
    'scope:read',
    'workflow:read', 'workflow:author', 'workflow:execute',
    'recon:passive', 'probing:active', 'scan:invasive',
    'report:draft',
    'secrets:read_metadata', 'secrets:read_material',
    'audit:read'
  )
ON CONFLICT DO NOTHING;

-- ANALYST: Scope Read, Workflow Read, Recon, Probing, Report Draft, Secrets Read Metadata, Audit Read
INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM iam.roles r, iam.permissions p
WHERE r.name = 'ANALYST'
  AND p.name IN (
    'scope:read',
    'workflow:read',
    'recon:passive', 'probing:active',
    'report:draft',
    'secrets:read_metadata',
    'audit:read'
  )
ON CONFLICT DO NOTHING;

-- AUDITOR: Scope Read, Workflow Read, Recon, Probing, Report Draft & Sign-off, Secrets Read Metadata, Audit Read
INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM iam.roles r, iam.permissions p
WHERE r.name = 'AUDITOR'
  AND p.name IN (
    'scope:read',
    'workflow:read',
    'recon:passive', 'probing:active',
    'report:draft', 'report:sign_off',
    'secrets:read_metadata',
    'audit:read'
  )
ON CONFLICT DO NOTHING;

-- OBSERVER: Scope Read, Workflow Read, Recon
INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM iam.roles r, iam.permissions p
WHERE r.name = 'OBSERVER'
  AND p.name IN (
    'scope:read',
    'workflow:read',
    'recon:passive'
  )
ON CONFLICT DO NOTHING;
