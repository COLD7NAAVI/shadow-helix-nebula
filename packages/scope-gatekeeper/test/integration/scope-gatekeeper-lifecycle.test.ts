/**
 * Shadow : Helix Nebula (SHN) — Scope Gatekeeper Lifecycle Integration Tests
 *
 * Enforces SEC-INV-01, SEC-INV-08, INV-06, INV-19, API-INV-02:
 * - End-to-end database-backed target evaluation
 * - CIDR, Hostname, and URL scope containment against live PostgreSQL
 * - Port boundary enforcement
 * - Action capability enforcement
 * - Exclusion precedence over inclusion
 * - Cloud metadata & SSRF blacklist enforcement
 * - Token-based evaluation lifecycle
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { ErrorCode } from '@shn/error-catalog';
import {
  createScopeTestPool,
  setupScopeTestDatabase,
  cleanScopeTables,
  createScopeTestServices,
  createTestOrgAndWorkspace,
  createTestSecurityContext,
  createPersistedScope,
  type ScopeTestServices,
} from './scope-test-helper.ts';

describe('Scope Gatekeeper Lifecycle (Database Integration Tests)', () => {
  const pool = createScopeTestPool();
  let services: ScopeTestServices;

  before(async () => {
    await setupScopeTestDatabase(pool);
    services = createScopeTestServices(pool);
  });

  after(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    await cleanScopeTables(pool);
  });

  describe('Database-Backed Scope Evaluation (by scopeId)', () => {
    it('should authorize valid targets matching declared inclusions', async () => {
      const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
      const context = createTestSecurityContext(services, workspaceId);

      const scope = await createPersistedScope(services, workspaceId, orgId, {
        inclusions: ['10.0.0.0/16', '*.example.com', 'https://example.com/api'],
        port_ranges: [{ start: 80, end: 443 }],
      });

      // 1. IP within CIDR
      const ipVerdict = await services.gatekeeper.evaluateTarget({
        context,
        target: '10.0.5.25',
        action: 'recon_passive',
        scopeId: scope.id,
      });
      assert.strictEqual(ipVerdict.isOk, true);
      assert.strictEqual(ipVerdict.value.allowed, true);
      assert.match(ipVerdict.value.reason, /explicitly authorized/i);

      // 2. Subdomain within wildcard
      const hostVerdict = await services.gatekeeper.evaluateTarget({
        context,
        target: 'api.example.com',
        action: 'probing_active',
        scopeId: scope.id,
      });
      assert.strictEqual(hostVerdict.isOk, true);
      assert.strictEqual(hostVerdict.value.allowed, true);

      // 3. Child path within URL scope
      const urlVerdict = await services.gatekeeper.evaluateTarget({
        context,
        target: 'https://example.com/api/v1/scan',
        action: 'scan_invasive',
        scopeId: scope.id,
      });
      assert.strictEqual(urlVerdict.isOk, true);
      assert.strictEqual(urlVerdict.value.allowed, true);
    });

    it('should reject out-of-bounds targets (Zero-Trust fail closed)', async () => {
      const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
      const context = createTestSecurityContext(services, workspaceId);

      const scope = await createPersistedScope(services, workspaceId, orgId, {
        inclusions: ['10.0.0.0/16', '*.example.com'],
      });

      // IP outside CIDR
      const ipVerdict = await services.gatekeeper.evaluateTarget({
        context,
        target: '192.168.1.1',
        action: 'recon_passive',
        scopeId: scope.id,
      });
      assert.strictEqual(ipVerdict.isOk, true);
      assert.strictEqual(ipVerdict.value.allowed, false);
      assert.strictEqual(ipVerdict.value.errorCode, ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS);

      // Hostname outside domain
      const hostVerdict = await services.gatekeeper.evaluateTarget({
        context,
        target: 'evil.com',
        action: 'probing_active',
        scopeId: scope.id,
      });
      assert.strictEqual(hostVerdict.isOk, true);
      assert.strictEqual(hostVerdict.value.allowed, false);
      assert.strictEqual(hostVerdict.value.errorCode, ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS);
    });

    it('should reject targets matching explicit exclusions even if within inclusions', async () => {
      const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
      const context = createTestSecurityContext(services, workspaceId);

      const scope = await createPersistedScope(services, workspaceId, orgId, {
        inclusions: ['10.0.0.0/16'],
        exclusions: ['10.0.99.0/24'],
      });

      // 10.0.99.5 is in 10.0.0.0/16, but explicitly in exclusions!
      const verdict = await services.gatekeeper.evaluateTarget({
        context,
        target: '10.0.99.5',
        action: 'recon_passive',
        scopeId: scope.id,
      });
      assert.strictEqual(verdict.isOk, true);
      assert.strictEqual(verdict.value.allowed, false);
      assert.strictEqual(verdict.value.errorCode, ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS);
      assert.match(verdict.value.reason, /matches explicit scope exclusion/i);
    });

    it('should reject unauthorized ports', async () => {
      const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
      const context = createTestSecurityContext(services, workspaceId);

      const scope = await createPersistedScope(services, workspaceId, orgId, {
        inclusions: ['10.0.0.0/16'],
        port_ranges: [{ start: 80, end: 443 }],
      });

      const verdict = await services.gatekeeper.evaluateTarget({
        context,
        target: '10.0.1.1',
        port: 8080,
        action: 'recon_passive',
        scopeId: scope.id,
      });
      assert.strictEqual(verdict.isOk, true);
      assert.strictEqual(verdict.value.allowed, false);
      assert.strictEqual(verdict.value.errorCode, ErrorCode.SCOPE_PORT_DISALLOWED);
    });

    it('should reject disallowed or unpermitted actions', async () => {
      const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
      const context = createTestSecurityContext(services, workspaceId);

      const scope = await createPersistedScope(services, workspaceId, orgId, {
        inclusions: ['10.0.0.0/16'],
        allowed_actions: ['recon_passive'],
        disallowed_actions: ['scan_invasive'],
      });

      // Unpermitted action
      const verdict1 = await services.gatekeeper.evaluateTarget({
        context,
        target: '10.0.1.1',
        action: 'probing_active',
        scopeId: scope.id,
      });
      assert.strictEqual(verdict1.isOk, true);
      assert.strictEqual(verdict1.value.allowed, false);
      assert.strictEqual(verdict1.value.errorCode, ErrorCode.SCOPE_ACTION_DISALLOWED);

      // Explicitly disallowed action
      const verdict2 = await services.gatekeeper.evaluateTarget({
        context,
        target: '10.0.1.1',
        action: 'scan_invasive',
        scopeId: scope.id,
      });
      assert.strictEqual(verdict2.isOk, true);
      assert.strictEqual(verdict2.value.allowed, false);
      assert.strictEqual(verdict2.value.errorCode, ErrorCode.SCOPE_ACTION_DISALLOWED);
    });

    it('should permanently reject cloud metadata and loopback targets (SEC-INV-08)', async () => {
      const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
      const context = createTestSecurityContext(services, workspaceId);

      // Attempt to include 0.0.0.0/0
      const scope = await createPersistedScope(services, workspaceId, orgId, {
        inclusions: ['0.0.0.0/0', '*.internal'],
      });

      // AWS metadata IP
      const v1 = await services.gatekeeper.evaluateTarget({
        context,
        target: '169.254.169.254',
        action: 'recon_passive',
        scopeId: scope.id,
      });
      assert.strictEqual(v1.isOk, true);
      assert.strictEqual(v1.value.allowed, false);
      assert.strictEqual(v1.value.errorCode, ErrorCode.SCOPE_METADATA_PROHIBITED);

      // GCP metadata hostname
      const v2 = await services.gatekeeper.evaluateTarget({
        context,
        target: 'metadata.google.internal',
        action: 'recon_passive',
        scopeId: scope.id,
      });
      assert.strictEqual(v2.isOk, true);
      assert.strictEqual(v2.value.allowed, false);
      assert.strictEqual(v2.value.errorCode, ErrorCode.SCOPE_METADATA_PROHIBITED);

      // IPv4 loopback
      const v3 = await services.gatekeeper.evaluateTarget({
        context,
        target: '127.0.0.1',
        action: 'recon_passive',
        scopeId: scope.id,
      });
      assert.strictEqual(v3.isOk, true);
      assert.strictEqual(v3.value.allowed, false);
      assert.strictEqual(v3.value.errorCode, ErrorCode.SCOPE_METADATA_PROHIBITED);
    });
  });

  describe('Cryptographic ScopeToken-Based Evaluation', () => {
    it('should authorize valid targets via minted ScopeToken', async () => {
      const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
      const context = createTestSecurityContext(services, workspaceId);

      const scopeRecord = await createPersistedScope(services, workspaceId, orgId, {
        inclusions: ['10.0.0.0/16'],
        allowed_actions: ['scan_invasive'],
        port_ranges: [{ start: 80, end: 443 }],
      });

      // Map to ScopeDefinition
      const scopeDef = {
        id: scopeRecord.id,
        workspaceId,
        organizationId: orgId,
        name: scopeRecord.name,
        inclusions: { cidrs: ['10.0.0.0/16'] },
        exclusions: {},
        allowedActions: ['scan_invasive'],
        disallowedActions: [],
        portRanges: [{ start: 80, end: 443 }],
        validFrom: scopeRecord.valid_from,
        validUntil: scopeRecord.valid_until,
        scopeSha256: scopeRecord.scope_sha256,
        status: 'active' as const,
        version: 1,
      };

      const tokenRes = services.tokenSigner.mintScopeToken({
        scope: scopeDef,
        actorId: context.subject_id as any,
      });
      assert.strictEqual(tokenRes.isOk, true);
      const scopeToken = tokenRes.value;

      // In-scope evaluation
      const allowVerdict = await services.gatekeeper.evaluateTarget({
        context,
        target: '10.0.10.1',
        action: 'scan_invasive',
        port: 443,
        scopeToken,
      });
      assert.strictEqual(allowVerdict.isOk, true);
      assert.strictEqual(allowVerdict.value.allowed, true);

      // Out-of-scope evaluation
      const denyVerdict = await services.gatekeeper.evaluateTarget({
        context,
        target: '192.168.1.1',
        action: 'scan_invasive',
        port: 443,
        scopeToken,
      });
      assert.strictEqual(denyVerdict.isOk, true);
      assert.strictEqual(denyVerdict.value.allowed, false);
      assert.strictEqual(denyVerdict.value.errorCode, ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS);
    });
  });
});
