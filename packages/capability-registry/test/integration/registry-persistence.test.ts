import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  setupRegistryTestEnv,
  type RegistryTestEnvironment,
} from './registry-test-helper.ts';
import {
  NetworkPortScanAdapter,
  HttpDiscoveryAdapter,
  type CapabilityDefinition,
} from '../../dist/index.js';
import { ErrorCode } from '@shn/error-catalog';

describe('Capability Registry Database Persistence (Integration)', () => {
  let env: RegistryTestEnvironment;

  const sampleCap: CapabilityDefinition = {
    id: 'shn://capabilities/network/port-scan' as any,
    name: 'network.port-scan',
    version: '1.0.0',
    displayName: 'Port Scanner',
    description: 'Scans network ports',
    category: 'RECONNAISSANCE',
    riskLevel: 'LOW',
    supportedTargets: ['IP', 'CIDR'],
    requiredPermissions: 1,
    requiredScopeAction: 'network:scan',
    argumentSchema: { type: 'object' },
    outputSchema: { type: 'object' },
    platformCompatibility: ['linux', 'darwin', 'win32'],
    lifecycleState: 'ACTIVE',
    integrityDigest: '1'.repeat(64),
  };

  before(async () => {
    env = await setupRegistryTestEnv('shn_test_capability_persistence');
  });

  after(async () => {
    await env.cleanup();
  });

  it('should register a global capability and persist it to PostgreSQL', async () => {
    const regRes = await env.registry.registerCapability(sampleCap);
    assert.strictEqual(regRes.isOk, true);

    // Verify in database directly via repository
    const dbRecord = await env.capRepo.findCapabilityById(sampleCap.id);
    assert.strictEqual(dbRecord !== null, true);
    assert.strictEqual(dbRecord?.name, 'network.port-scan');
    assert.strictEqual(dbRecord?.version, '1.0.0');
    assert.strictEqual(dbRecord?.category, 'RECONNAISSANCE');
    assert.strictEqual(dbRecord?.workspaceId, null);
  });

  it('should register a workspace-scoped capability and persist workspace isolation', async () => {
    const wsScopedCap: CapabilityDefinition = {
      ...sampleCap,
      id: 'shn://capabilities/custom/ws-scanner' as any,
      name: 'custom.ws-scanner',
    };

    const regRes = await env.registry.registerCapability(wsScopedCap, env.workspaceId);
    assert.strictEqual(regRes.isOk, true);

    // Verify in database with workspace filter
    const wsRecord = await env.capRepo.findCapabilityById(wsScopedCap.id, env.workspaceId);
    assert.strictEqual(wsRecord !== null, true);
    assert.strictEqual(wsRecord?.workspaceId, env.workspaceId);

    // Foreign workspace cannot see workspace-scoped capability
    const foreignRecord = await env.capRepo.findCapabilityById(
      wsScopedCap.id,
      env.foreignWorkspaceId
    );
    assert.strictEqual(foreignRecord, null);
  });

  it('should persist capability lifecycle state updates to PostgreSQL', async () => {
    const updateRes = await env.registry.updateCapabilityState(sampleCap.id, 'DEPRECATED');
    assert.strictEqual(updateRes.isOk, true);

    const dbRecord = await env.capRepo.findCapabilityById(sampleCap.id);
    assert.strictEqual(dbRecord?.lifecycleState, 'DEPRECATED');

    // Restore to ACTIVE
    await env.registry.updateCapabilityState(sampleCap.id, 'ACTIVE');
  });

  it('should register a tool adapter and persist it to PostgreSQL', async () => {
    const adapter = new NetworkPortScanAdapter();
    const regRes = await env.registry.registerAdapter(adapter);
    assert.strictEqual(regRes.isOk, true);

    const dbRecord = await env.capRepo.findAdapterById(adapter.adapterId);
    assert.strictEqual(dbRecord !== null, true);
    assert.strictEqual(dbRecord?.name, 'network-port-scan-adapter');
    assert.strictEqual(dbRecord?.supportedCapabilities.length, 1);
  });

  it('should persist adapter lifecycle state transitions to PostgreSQL', async () => {
    const adapter = new NetworkPortScanAdapter();
    const updateRes = await env.registry.updateAdapterState(adapter.adapterId, 'DISABLED');
    assert.strictEqual(updateRes.isOk, true);

    const dbRecord = await env.capRepo.findAdapterById(adapter.adapterId);
    assert.strictEqual(dbRecord?.lifecycleState, 'DISABLED');

    // Restore to AVAILABLE
    await env.registry.updateAdapterState(adapter.adapterId, 'AVAILABLE');
  });

  it('should persist and enforce workspace capability bindings in PostgreSQL', async () => {
    const adapter = new NetworkPortScanAdapter();

    // Disable capability for this workspace
    const setRes = await env.registry.setWorkspaceBinding(
      env.workspaceId,
      sampleCap.id,
      adapter.adapterId,
      false,
      { customSetting: 'test' }
    );
    assert.strictEqual(setRes.isOk, true);

    // Query DB directly
    const dbBinding = await env.capRepo.getWorkspaceBinding(env.workspaceId, sampleCap.id);
    assert.strictEqual(dbBinding !== null, true);
    assert.strictEqual(dbBinding?.isEnabled, false);
    assert.strictEqual(dbBinding?.preferredAdapterId, String(adapter.adapterId));
    assert.strictEqual(dbBinding?.overrides['customSetting'], 'test');

    // Resolution in disabled workspace should fail-closed
    const resolveRes = await env.registry.resolveProvider(sampleCap.id, {
      workspaceId: env.workspaceId,
    });
    assert.strictEqual(resolveRes.isErr, true);
    if (resolveRes.isErr) {
      assert.strictEqual(resolveRes.error.error_code, ErrorCode.CAP_DISABLED);
    }

    // Re-enable in workspace
    await env.registry.setWorkspaceBinding(
      env.workspaceId,
      sampleCap.id,
      adapter.adapterId,
      true
    );

    const reResolveRes = await env.registry.resolveProvider(sampleCap.id, {
      workspaceId: env.workspaceId,
    });
    assert.strictEqual(reResolveRes.isOk, true);
  });
});
