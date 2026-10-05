/**
 * Shadow : Helix Nebula (SHN) — Tenancy Isolation Integration Tests
 *
 * Enforces SEC-INV-05, INV-01, INV-19, and DATA-INV-08:
 * - Mechanical Organization and Workspace isolation
 * - Prohibition of cross-workspace scope access
 * - Scoped query hermeticity
 * - Cross-tenant token defense
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

describe('Tenancy & Scope Isolation (Integration Tests)', () => {
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

  describe('Workspace Isolation within Same Organization', () => {
    it('should deny cross-workspace scope access when evaluating by scopeId', async () => {
      const { orgId, workspaceId: ws1 } = await createTestOrgAndWorkspace(services);
      const { workspaceId: ws2 } = await createTestOrgAndWorkspace(services);

      // Create Scope in Workspace 1
      const scopeWs1 = await createPersistedScope(services, ws1, orgId, {
        name: 'Workspace 1 Scope',
        inclusions: ['10.1.0.0/16'],
      });

      // Context belongs to Workspace 2
      const contextWs2 = createTestSecurityContext(services, ws2);

      // Attempt to evaluate target using Scope 1's ID under Workspace 2 context
      const verdict = await services.gatekeeper.evaluateTarget({
        context: contextWs2,
        target: '10.1.5.5',
        action: 'recon_passive',
        scopeId: scopeWs1.id,
      });

      assert.strictEqual(verdict.isOk, true);
      assert.strictEqual(verdict.value.allowed, false);
      assert.strictEqual(verdict.value.errorCode, ErrorCode.STORAGE_NOT_FOUND);
      assert.match(verdict.value.reason, /not found in workspace/i);
    });

    it('should reject cross-workspace scope token usage fail-closed', async () => {
      const { orgId, workspaceId: ws1 } = await createTestOrgAndWorkspace(services);
      const { workspaceId: ws2 } = await createTestOrgAndWorkspace(services);

      const scopeWs1 = await createPersistedScope(services, ws1, orgId, {
        inclusions: ['10.1.0.0/16'],
      });

      const scopeDef = {
        id: scopeWs1.id,
        workspaceId: ws1,
        organizationId: orgId,
        name: scopeWs1.name,
        inclusions: { cidrs: ['10.1.0.0/16'] },
        exclusions: {},
        allowedActions: ['recon_passive'],
        disallowedActions: [],
        portRanges: [{ start: 80, end: 443 }],
        validFrom: scopeWs1.valid_from,
        validUntil: scopeWs1.valid_until,
        scopeSha256: scopeWs1.scope_sha256,
        status: 'active' as const,
        version: 1,
      };

      const contextWs2 = createTestSecurityContext(services, ws2);

      // Mint token bound to Workspace 1, using actor from contextWs2
      const token = services.tokenSigner.mintScopeToken({
        scope: scopeDef,
        actorId: contextWs2.subject_id as any,
      }).value;

      // Present token in Workspace 2 context
      const verdict = await services.gatekeeper.evaluateTarget({
        context: contextWs2,
        target: '10.1.5.5',
        action: 'recon_passive',
        scopeToken: token,
      });

      assert.strictEqual(verdict.isOk, true);
      assert.strictEqual(verdict.value.allowed, false);
      assert.strictEqual(verdict.value.errorCode, ErrorCode.AUTH_CROSS_WORKSPACE_DENIED);
      assert.match(verdict.value.reason, /does not match context workspace/i);
    });
  });

  describe('Organization Isolation', () => {
    it('should reject cross-organization scope token usage fail-closed', async () => {
      const { orgId: orgA, workspaceId: wsA } = await createTestOrgAndWorkspace(services);
      const { orgId: orgB, workspaceId: wsB } = await createTestOrgAndWorkspace(services);

      const scopeRecordA = await createPersistedScope(services, wsA, orgA, {
        inclusions: ['10.2.0.0/16'],
      });

      const contextB = createTestSecurityContext(services, wsB);

      // Forged / modified token with Workspace B but Organization A
      const forgedScopeDef = {
        id: scopeRecordA.id,
        workspaceId: wsB,
        organizationId: orgA, // Mismatched organization!
        name: 'Forged Scope',
        inclusions: { cidrs: ['10.2.0.0/16'] },
        exclusions: {},
        allowedActions: ['recon_passive'],
        disallowedActions: [],
        portRanges: [{ start: 80, end: 443 }],
        validFrom: scopeRecordA.valid_from,
        validUntil: scopeRecordA.valid_until,
        scopeSha256: scopeRecordA.scope_sha256,
        status: 'active' as const,
        version: 1,
      };

      const token = services.tokenSigner.mintScopeToken({
        scope: forgedScopeDef,
        actorId: contextB.subject_id as any,
      }).value;

      const verdict = await services.gatekeeper.evaluateTarget({
        context: contextB,
        target: '10.2.1.1',
        action: 'recon_passive',
        scopeToken: token,
      });

      assert.strictEqual(verdict.isOk, true);
      assert.strictEqual(verdict.value.allowed, false);
      assert.strictEqual(verdict.value.errorCode, ErrorCode.AUTH_CROSS_ORG_DENIED);
    });
  });

  describe('Persistence Scoped Query Hermeticity (DATA-INV-08)', () => {
    it('should enforce workspace_id boundary on findById in ScopeRepository', async () => {
      const { orgId, workspaceId: ws1 } = await createTestOrgAndWorkspace(services);
      const { workspaceId: ws2 } = await createTestOrgAndWorkspace(services);

      const scope1 = await createPersistedScope(services, ws1, orgId);

      // Query with correct workspaceId
      const foundCorrect = await services.scopeRepo.findById(scope1.id, ws1);
      assert.notStrictEqual(foundCorrect, null);
      assert.strictEqual(foundCorrect?.id, scope1.id);

      // Query with different workspaceId returns null
      const foundCross = await services.scopeRepo.findById(scope1.id, ws2);
      assert.strictEqual(foundCross, null);
    });

    it('should list only scopes belonging to queried workspace', async () => {
      const { orgId, workspaceId: ws1 } = await createTestOrgAndWorkspace(services);
      const { workspaceId: ws2 } = await createTestOrgAndWorkspace(services);

      await createPersistedScope(services, ws1, orgId, { name: 'WS1 Scope 1' });
      await createPersistedScope(services, ws1, orgId, { name: 'WS1 Scope 2' });
      await createPersistedScope(services, ws2, orgId, { name: 'WS2 Scope 1' });

      const ws1Scopes = await services.scopeRepo.findActiveByWorkspace(ws1);
      const ws2Scopes = await services.scopeRepo.findActiveByWorkspace(ws2);

      assert.strictEqual(ws1Scopes.length, 2);
      assert.strictEqual(ws2Scopes.length, 1);
      assert.ok(ws1Scopes.every((s) => s.workspace_id === ws1));
      assert.ok(ws2Scopes.every((s) => s.workspace_id === ws2));
    });
  });
});
