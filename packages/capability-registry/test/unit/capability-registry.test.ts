import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  CapabilityRegistry,
  NetworkPortScanAdapter,
  HttpDiscoveryAdapter,
  type CapabilityDefinition,
} from '../../dist/index.js';
import { ErrorCode } from '@shn/error-catalog';

describe('CapabilityRegistry (Unit Tests)', () => {
  let registry: CapabilityRegistry;

  const sampleCapability: CapabilityDefinition = {
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

  const sampleCapabilityV2: CapabilityDefinition = {
    ...sampleCapability,
    id: 'shn://capabilities/network/port-scan' as any,
    version: '2.0.0',
    integrityDigest: '2'.repeat(64),
  };

  beforeEach(() => {
    registry = new CapabilityRegistry();
  });

  describe('Capability Registration & Discovery', () => {
    it('should register and retrieve a capability', async () => {
      const regRes = await registry.registerCapability(sampleCapability);
      assert.strictEqual(regRes.isOk, true);

      const found = await registry.findCapability(sampleCapability.id);
      assert.strictEqual(found !== null, true);
      assert.strictEqual(found?.name, 'network.port-scan');
    });

    it('should reject registering a duplicate capability ID', async () => {
      await registry.registerCapability(sampleCapability);
      const dupRes = await registry.registerCapability(sampleCapability);
      assert.strictEqual(dupRes.isErr, true);
      if (dupRes.isErr) {
        assert.strictEqual(dupRes.error.error_code, ErrorCode.CAP_ALREADY_EXISTS);
      }
    });

    it('should update capability lifecycle state', async () => {
      await registry.registerCapability(sampleCapability);
      const updateRes = await registry.updateCapabilityState(sampleCapability.id, 'DEPRECATED');
      assert.strictEqual(updateRes.isOk, true);

      const found = await registry.findCapability(sampleCapability.id);
      assert.strictEqual(found?.lifecycleState, 'DEPRECATED');
    });

    it('should filter capabilities by category and risk level', async () => {
      await registry.registerCapability(sampleCapability);
      await registry.registerCapability({
        ...sampleCapability,
        id: 'shn://capabilities/web/http-discovery' as any,
        name: 'web.http-discovery',
        category: 'DISCOVERY',
        riskLevel: 'MEDIUM',
      });

      const recon = await registry.listCapabilities({ category: 'RECONNAISSANCE' });
      assert.strictEqual(recon.length, 1);
      assert.strictEqual(recon[0]?.name, 'network.port-scan');

      const discovery = await registry.listCapabilities({ category: 'DISCOVERY' });
      assert.strictEqual(discovery.length, 1);
      assert.strictEqual(discovery[0]?.name, 'web.http-discovery');
    });
  });

  describe('Adapter Registration & Lifecycle', () => {
    it('should register and retrieve an adapter', async () => {
      const adapterInstance = new NetworkPortScanAdapter();
      const regRes = await registry.registerAdapter(adapterInstance);
      assert.strictEqual(regRes.isOk, true);

      const found = await registry.findAdapter(adapterInstance.adapterId);
      assert.strictEqual(found !== null, true);
      assert.strictEqual(found?.adapterId, adapterInstance.adapterId);
    });

    it('should reject registering a duplicate adapter', async () => {
      const adapterInstance = new NetworkPortScanAdapter();
      await registry.registerAdapter(adapterInstance);
      const dupRes = await registry.registerAdapter(adapterInstance);
      assert.strictEqual(dupRes.isErr, true);
      if (dupRes.isErr) {
        assert.strictEqual(dupRes.error.error_code, ErrorCode.CAP_ALREADY_EXISTS);
      }
    });

    it('should update adapter lifecycle state', async () => {
      const adapterInstance = new NetworkPortScanAdapter();
      await registry.registerAdapter(adapterInstance);

      const updateRes = await registry.updateAdapterState(
        adapterInstance.adapterId,
        'DEPRECATED'
      );
      assert.strictEqual(updateRes.isOk, true);

      const found = await registry.findAdapter(adapterInstance.adapterId);
      assert.strictEqual(found?.getLifecycleState(), 'DEPRECATED');
    });
  });

  describe('Provider Resolution & SemVer Matching', () => {
    it('should resolve the best matching adapter for a capability', async () => {
      await registry.registerCapability(sampleCapability);
      const adapterInstance = new NetworkPortScanAdapter();
      await registry.registerAdapter(adapterInstance);

      const resolved = await registry.resolveProvider(sampleCapability.id);
      assert.strictEqual(resolved.isOk, true);
      if (resolved.isOk) {
        assert.strictEqual(resolved.value.adapterId, adapterInstance.adapterId);
      }
    });

    it('should fail-closed if capability is not registered', async () => {
      const resolved = await registry.resolveProvider('shn://capabilities/non/existent' as any);
      assert.strictEqual(resolved.isErr, true);
      if (resolved.isErr) {
        assert.strictEqual(resolved.error.error_code, ErrorCode.CAP_NOT_FOUND);
      }
    });

    it('should fail-closed if no compatible adapter exists for capability version', async () => {
      // Register Capability v2.0.0, but adapter only supports ^1.0.0
      await registry.registerCapability(sampleCapabilityV2);
      const adapterInstance = new NetworkPortScanAdapter();
      await registry.registerAdapter(adapterInstance);

      const resolved = await registry.resolveProvider(sampleCapabilityV2.id);
      assert.strictEqual(resolved.isErr, true);
      if (resolved.isErr) {
        assert.strictEqual(resolved.error.error_code, ErrorCode.ADAPTER_NOT_FOUND);
      }
    });

    it('should not resolve adapters in REVOKED or DISABLED states', async () => {
      await registry.registerCapability(sampleCapability);
      const adapterInstance = new NetworkPortScanAdapter();
      await registry.registerAdapter(adapterInstance);

      // Disable the adapter
      await registry.updateAdapterState(adapterInstance.adapterId, 'DISABLED');
      const resolved = await registry.resolveProvider(sampleCapability.id);
      assert.strictEqual(resolved.isErr, true);
      if (resolved.isErr) {
        assert.strictEqual(resolved.error.error_code, ErrorCode.ADAPTER_NOT_FOUND);
      }
    });
  });

  describe('Workspace Bindings & Tenancy Scoping', () => {
    it('should store and apply workspace binding overrides', async () => {
      await registry.registerCapability(sampleCapability);
      const adapterInstance = new NetworkPortScanAdapter();
      await registry.registerAdapter(adapterInstance);

      const workspaceId = '00000000-0000-7000-8000-000000000001' as any;

      // Set workspace binding overriding adapter
      const setRes = await registry.setWorkspaceBinding(
        workspaceId,
        sampleCapability.id,
        adapterInstance.adapterId,
        true
      );
      assert.strictEqual(setRes.isOk, true);

      // Retrieve workspace binding
      const binding = await registry.getWorkspaceBinding(workspaceId, sampleCapability.id);
      assert.strictEqual(binding !== null, true);
      if (binding) {
        assert.strictEqual(binding.preferredAdapterId, String(adapterInstance.adapterId));
      }

      // Resolving with workspaceId uses binding
      const resolved = await registry.resolveProvider(sampleCapability.id, { workspaceId });
      assert.strictEqual(resolved.isOk, true);
    });

    it('should respect disabled capability in workspace binding', async () => {
      await registry.registerCapability(sampleCapability);
      const adapterInstance = new NetworkPortScanAdapter();
      await registry.registerAdapter(adapterInstance);

      const workspaceId = '00000000-0000-7000-8000-000000000002' as any;

      // Disable capability for this workspace
      await registry.setWorkspaceBinding(
        workspaceId,
        sampleCapability.id,
        adapterInstance.adapterId,
        false
      );

      const resolved = await registry.resolveProvider(sampleCapability.id, { workspaceId });
      assert.strictEqual(resolved.isErr, true);
      if (resolved.isErr) {
        assert.strictEqual(resolved.error.error_code, ErrorCode.CAP_DISABLED);
      }
    });
  });
});
