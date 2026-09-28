/**
 * Shadow : Helix Nebula (SHN) — Event Handler Registry Pure Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ok } from '@shn/shared-kernel';
import {
  createEventRegistry,
  isSchemaVersionCompatible,
} from '../../dist/index.js';

describe('Event Handler Registry & Compatibility (Pure Unit Tests)', () => {
  it('should register typed event handlers successfully', () => {
    const registry = createEventRegistry();

    const result = registry.registerHandler(
      'scan.host.discovered',
      async () => ok(undefined),
      {
        handlerName: 'asset-inventory-sync',
        schemaVersion: '1.0.0',
      }
    );

    assert.ok(result.isOk);
    assert.equal(registry.hasHandler('scan.host.discovered', 'asset-inventory-sync'), true);
  });

  it('should reject duplicate handler registration for the same event and handlerName fail-closed', () => {
    const registry = createEventRegistry();

    const reg1 = registry.registerHandler(
      'workflow.step.completed',
      async () => ok(undefined),
      {
        handlerName: 'orchestrator-step-finisher',
        schemaVersion: '1.0.0',
      }
    );
    assert.ok(reg1.isOk);

    // Attempt duplicate registration
    const reg2 = registry.registerHandler(
      'workflow.step.completed',
      async () => ok(undefined),
      {
        handlerName: 'orchestrator-step-finisher',
        schemaVersion: '1.0.0',
      }
    );

    assert.ok(reg2.isErr);
    assert.equal(reg2.error.error_code, 'ERR_IDEMPOTENCY_CONFLICT');
  });

  it('should correctly evaluate SemVer schema compatibility according to Phase 0.14 Section 15', () => {
    // Exact match
    assert.equal(isSchemaVersionCompatible('1.0.0', '1.0.0'), true);

    // Additive minor version evolution: event has higher minor version than handler requirement
    assert.equal(isSchemaVersionCompatible('1.2.0', '1.0.0'), true);
    assert.equal(isSchemaVersionCompatible('1.5.1', '1.2.0'), true);

    // Event with lower minor version than handler requirement is incompatible
    assert.equal(isSchemaVersionCompatible('1.0.0', '1.2.0'), false);

    // Major version mismatch is always breaking (API-INV-16)
    assert.equal(isSchemaVersionCompatible('2.0.0', '1.0.0'), false);
    assert.equal(isSchemaVersionCompatible('1.0.0', '2.0.0'), false);
  });

  it('should filter handlers by schema version compatibility', () => {
    const registry = createEventRegistry();

    registry.registerHandler('vuln.detected', async () => ok(undefined), {
      handlerName: 'v1-handler',
      schemaVersion: '1.0.0',
    });

    registry.registerHandler('vuln.detected', async () => ok(undefined), {
      handlerName: 'v2-handler',
      schemaVersion: '2.0.0',
    });

    // Event version 1.3.0 should match v1-handler only
    const v1Matches = registry.getHandlers('vuln.detected', '1.3.0');
    assert.equal(v1Matches.length, 1);
    assert.equal(v1Matches[0]!.handlerName, 'v1-handler');

    // Event version 2.0.0 should match v2-handler only
    const v2Matches = registry.getHandlers('vuln.detected', '2.0.0');
    assert.equal(v2Matches.length, 1);
    assert.equal(v2Matches[0]!.handlerName, 'v2-handler');
  });

  it('should allow unregistering handlers cleanly', () => {
    const registry = createEventRegistry();

    registry.registerHandler('test.event', async () => ok(undefined), {
      handlerName: 'transient-handler',
      schemaVersion: '1.0.0',
    });

    assert.equal(registry.hasHandler('test.event', 'transient-handler'), true);
    const unreg = registry.unregisterHandler('test.event', 'transient-handler');
    assert.equal(unreg, true);
    assert.equal(registry.hasHandler('test.event', 'transient-handler'), false);
  });
});
