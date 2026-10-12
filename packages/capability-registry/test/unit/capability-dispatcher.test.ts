import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  CapabilityDispatcher,
  CapabilityRegistry,
  NetworkPortScanAdapter,
  type CapabilityDefinition,
  type CapabilityExecutionRequest,
} from '../../dist/index.js';
import type {
  IExecutionSupervisor,
  ExecutionRequest,
  ExecutionResult,
} from '@shn/execution-supervisor';
import type { IScopeGatekeeper, ScopeEvaluationResult } from '@shn/scope-gatekeeper';
import type { SecurityContextToken } from '@shn/shared-kernel';
import { ok, err, type Result } from '@shn/shared-kernel';
import { ErrorCode, type ProblemDetails } from '@shn/error-catalog';

class MockExecutionSupervisor implements IExecutionSupervisor {
  lastExecutionRequest?: ExecutionRequest | undefined;
  mockResult?: Result<ExecutionResult, ProblemDetails> | undefined;

  async execute(request: ExecutionRequest): Promise<Result<ExecutionResult, ProblemDetails>> {
    this.lastExecutionRequest = request;
    if (this.mockResult) return this.mockResult;

    return ok({
      executionId: '00000000-0000-7000-8000-000000000099' as any,
      state: 'SUCCEEDED',
      exitCode: 0,
      stdout: 'PORT 80/tcp open http',
      stderr: '',
      outputSha256: 'a'.repeat(64),
      durationMs: 42,
      artifacts: [],
    } as any);
  }

  async cancel(): Promise<Result<void, ProblemDetails>> {
    return ok(undefined);
  }

  async getStatus(): Promise<Result<any, ProblemDetails>> {
    return ok({ state: 'SUCCEEDED' } as any);
  }
}

class MockScopeGatekeeper implements IScopeGatekeeper {
  allowed = true;
  reason = 'Mock allowed';

  async evaluateTarget(): Promise<Result<ScopeEvaluationResult, ProblemDetails>> {
    return ok({
      allowed: this.allowed,
      reason: this.reason,
      matchedRuleId: 'rule-1',
    });
  }

  async validateTarget(): Promise<Result<void, ProblemDetails>> {
    return ok(undefined);
  }
}

describe('CapabilityDispatcher (Unit Tests)', () => {
  let registry: CapabilityRegistry;
  let supervisor: MockExecutionSupervisor;
  let gatekeeper: MockScopeGatekeeper;
  let dispatcher: CapabilityDispatcher;

  const validToken: SecurityContextToken = {
    subject_id: 'user-123',
    subject_type: 'OPERATOR',
    workspace_id: 'ws-1' as any,
    roles: ['OPERATOR'],
    permission_mask: 0xffffffff,
    issued_at: new Date(Date.now() - 10_000).toISOString() as any,
    expires_at: new Date(Date.now() + 3600_000).toISOString() as any,
    signature: 'mock-sig',
  };

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

  const baseRequest: CapabilityExecutionRequest = {
    capabilityId: sampleCapability.id,
    target: '192.168.1.1',
    port: 80,
    workspaceId: 'ws-1' as any,
    organizationId: 'org-1' as any,
    actorId: 'user-123',
    securityContext: validToken,
  };

  beforeEach(async () => {
    registry = new CapabilityRegistry();
    supervisor = new MockExecutionSupervisor();
    gatekeeper = new MockScopeGatekeeper();

    await registry.registerCapability(sampleCapability);
    await registry.registerAdapter(new NetworkPortScanAdapter());

    dispatcher = new CapabilityDispatcher({
      registry,
      supervisor,
      scopeGatekeeper: gatekeeper,
    });
  });

  describe('Security Context & Tenancy Gatekeeping', () => {
    it('should reject request missing security context', async () => {
      const res = await dispatcher.executeCapability({
        ...baseRequest,
        securityContext: undefined as any,
      });
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.AUTH_UNAUTHENTICATED);
      }
    });

    it('should reject request when actorId does not match subject_id', async () => {
      const res = await dispatcher.executeCapability({
        ...baseRequest,
        actorId: 'different-actor',
      });
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.AUTH_FORBIDDEN);
      }
    });

    it('should reject cross-workspace request (token workspace does not match request)', async () => {
      const res = await dispatcher.executeCapability({
        ...baseRequest,
        workspaceId: 'ws-different' as any,
      });
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.AUTH_CROSS_WORKSPACE_DENIED);
      }
    });

    it('should reject execution when actor lacks required permission mask', async () => {
      const tokenWithNoPermissions: SecurityContextToken = {
        ...validToken,
        permission_mask: 0,
      };
      const res = await dispatcher.executeCapability({
        ...baseRequest,
        securityContext: tokenWithNoPermissions,
      });
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.AUTH_FORBIDDEN);
      }
    });
  });

  describe('Scope Gatekeeping Integration', () => {
    it('should block execution fail-closed if Scope Gatekeeper rejects target', async () => {
      gatekeeper.allowed = false;
      gatekeeper.reason = 'Target IP is not in authorized scope boundary';

      const res = await dispatcher.executeCapability(baseRequest);
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS);
      }
      // Supervisor should NOT have been invoked
      assert.strictEqual(supervisor.lastExecutionRequest, undefined);
    });
  });

  describe('Target & Parameter Injection Defenses', () => {
    it('should reject target containing shell injection characters', async () => {
      const res = await dispatcher.executeCapability({
        ...baseRequest,
        target: '192.168.1.1; cat /etc/passwd',
      });
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.EXEC_COMMAND_INJECTION_REJECTED);
      }
      assert.strictEqual(supervisor.lastExecutionRequest, undefined);
    });
  });

  describe('Dispatch Execution Flow', () => {
    it('should resolve adapter, build command, execute through supervisor, and return structured output', async () => {
      const res = await dispatcher.executeCapability(baseRequest);
      assert.strictEqual(res.isOk, true);
      if (res.isOk) {
        assert.strictEqual(res.value.capabilityId, sampleCapability.id);
        assert.strictEqual(res.value.adapterId, 'adapter:network-port-scan');
        assert.strictEqual(res.value.state, 'SUCCEEDED');
        assert.strictEqual(res.value.exitCode, 0);
        assert.strictEqual(res.value.rawOutputSha256, 'a'.repeat(64));
      }

      // Check execution request sent to supervisor
      assert.strictEqual(supervisor.lastExecutionRequest !== undefined, true);
      if (supervisor.lastExecutionRequest) {
        assert.strictEqual(supervisor.lastExecutionRequest.target, '192.168.1.1');
        assert.strictEqual(supervisor.lastExecutionRequest.port, 80);
        assert.strictEqual(supervisor.lastExecutionRequest.action, 'network:scan');
      }
    });

    it('should fail-closed if capability is not found', async () => {
      const res = await dispatcher.executeCapability({
        ...baseRequest,
        capabilityId: 'shn://capabilities/non/existent' as any,
      });
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.CAP_NOT_FOUND);
      }
    });
  });
});
