/**
 * Shadow : Helix Nebula (SHN) — Scope Gatekeeper Concurrency & Race Condition Tests
 *
 * Verifies that concurrent target authorizations under load remain deterministic,
 * isolated, and free of shared mutable state corruptions.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

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

describe('Scope Gatekeeper Concurrency & High Load (Integration Tests)', () => {
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

  it('should execute 50 concurrent target evaluations deterministically without state leakage', async () => {
    const { orgId, workspaceId: ws1 } = await createTestOrgAndWorkspace(services);
    const { workspaceId: ws2 } = await createTestOrgAndWorkspace(services);

    const context1 = createTestSecurityContext(services, ws1);
    const context2 = createTestSecurityContext(services, ws2);

    const scope1 = await createPersistedScope(services, ws1, orgId, {
      name: 'Scope WS1',
      inclusions: ['10.1.0.0/16'],
    });

    const scope2 = await createPersistedScope(services, ws2, orgId, {
      name: 'Scope WS2',
      inclusions: ['10.2.0.0/16'],
    });

    // Generate 50 concurrent evaluations:
    // - 25 for WS1 (even indices valid: 10.1.x.x, odd indices invalid: 10.2.x.x)
    // - 25 for WS2 (even indices valid: 10.2.x.x, odd indices invalid: 10.1.x.x)
    const tasks = Array.from({ length: 50 }, async (_, i) => {
      if (i % 2 === 0) {
        // WS1 evaluating
        const isAllowed = i % 4 === 0;
        const target = isAllowed ? `10.1.${i}.1` : `10.2.${i}.1`;
        const res = await services.gatekeeper.evaluateTarget({
          context: context1,
          target,
          action: 'recon_passive',
          scopeId: scope1.id,
        });

        assert.strictEqual(res.isOk, true);
        assert.strictEqual(res.value.allowed, isAllowed);
      } else {
        // WS2 evaluating
        const isAllowed = i % 3 === 0;
        const target = isAllowed ? `10.2.${i}.1` : `10.1.${i}.1`;
        const res = await services.gatekeeper.evaluateTarget({
          context: context2,
          target,
          action: 'recon_passive',
          scopeId: scope2.id,
        });

        assert.strictEqual(res.isOk, true);
        assert.strictEqual(res.value.allowed, isAllowed);
      }
    });

    await Promise.all(tasks);
  });
});
