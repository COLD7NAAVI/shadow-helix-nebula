import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  setupRegistryTestEnv,
  type RegistryTestEnvironment,
} from './registry-test-helper.ts';
import {
  BaseToolAdapter,
  type CapabilityDefinition,
  type CommandVector,
  type AdapterExecutionOutput,
  type EvidenceArtifact,
  type AdapterCapabilityBinding,
  type PlatformType,
} from '../../dist/index.js';
import { ok, type Result, createAdapterId, type AdapterId } from '@shn/shared-kernel';
import { ErrorCode, type ProblemDetails } from '@shn/error-catalog';
import { PermissionBit } from '@shn/auth-rbac';

class TestExecutableAdapter extends BaseToolAdapter {
  readonly adapterId: AdapterId;
  readonly name = 'test-node-adapter';
  readonly version = '1.0.0';
  readonly platformSupport: readonly PlatformType[] = ['linux', 'darwin', 'win32'];
  readonly supportedCapabilities: readonly AdapterCapabilityBinding[];

  constructor() {
    super();
    this.adapterId = createAdapterId('adapter:test-node').unwrapOr('adapter:test-node' as AdapterId);
    this.lifecycleState = 'AVAILABLE';
    this.supportedCapabilities = [
      {
        capabilityId: 'shn://capabilities/network/port-scan' as any,
        versionConstraint: '^1.0.0',
        supportedTargetTypes: ['IP', 'CIDR'],
        priority: 500,
      },
      {
        capabilityId: 'shn://capabilities/web/http-discovery' as any,
        versionConstraint: '^1.0.0',
        supportedTargetTypes: ['IP', 'CIDR', 'URL', 'HOST'],
        priority: 500,
      },
    ];
  }

  buildCommand(
    _capability: CapabilityDefinition,
    target: string,
    params: Record<string, unknown>,
    port?: number
  ): Result<CommandVector, ProblemDetails> {
    const p = port ?? 80;
    const script = `process.stdout.write("PORT ${p}/tcp open http\\n"); process.stderr.write("scan completed successfully\\n");`;
    return ok({
      executable: process.execPath,
      args: ['-e', script],
      resourceLimits: {
        timeoutMs: 15_000,
      },
    });
  }

  parseOutput(
    rawOutput: string,
    rawStderr: string,
    exitCode: number,
    sha256: string
  ): Result<AdapterExecutionOutput, ProblemDetails> {
    const findings = [
      {
        port: 80,
        protocol: 'tcp',
        state: 'open',
        service: 'http',
      },
    ];
    return ok({
      exitCode,
      rawOutput,
      rawStderr,
      rawOutputSha256: sha256,
      parsedPayload: {
        targetStatus: 'OPEN',
        findingsCount: 1,
      },
      findings,
      artifacts: this.extractEvidence(rawOutput, rawStderr, sha256),
    });
  }

  override extractEvidence(
    rawOutput: string,
    _rawStderr: string,
    sha256: string
  ): readonly EvidenceArtifact[] {
    return [
      {
        name: 'scan_report.txt',
        mimeType: 'text/plain',
        contentSha256: sha256,
        content: rawOutput,
        byteSize: Buffer.byteLength(rawOutput, 'utf8'),
      },
    ];
  }
}

describe('CapabilityDispatcher End-to-End Execution (Integration)', () => {
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

  const sampleHttpCap: CapabilityDefinition = {
    id: 'shn://capabilities/web/http-discovery' as any,
    name: 'web.http-discovery',
    version: '1.0.0',
    displayName: 'HTTP Discovery',
    description: 'Probes HTTP services',
    category: 'RECONNAISSANCE',
    riskLevel: 'LOW',
    supportedTargets: ['IP', 'CIDR', 'URL', 'HOST'],
    requiredPermissions: PermissionBit.PROBING_ACTIVE,
    requiredScopeAction: 'http:probe',
    argumentSchema: { type: 'object' },
    outputSchema: { type: 'object' },
    platformCompatibility: ['linux', 'darwin', 'win32'],
    lifecycleState: 'ACTIVE',
    integrityDigest: '2'.repeat(64),
  };

  before(async () => {
    env = await setupRegistryTestEnv('shn_test_capability_dispatcher');
    await env.registry.registerCapability(sampleCap);
    await env.registry.registerCapability(sampleHttpCap);
    await env.registry.registerAdapter(new TestExecutableAdapter());
  });

  after(async () => {
    await env.cleanup();
  });

  it('should dispatch capability execution end-to-end, enforce scope, execute sandbox, and return output', async () => {
    const secToken = env.mintToken(env.workspaceId);

    const result = await env.dispatcher.executeCapability({
      capabilityId: sampleCap.id,
      target: '192.168.1.1',
      port: 80,
      workspaceId: env.workspaceId,
      organizationId: env.orgId,
      actorId: env.userId,
      securityContext: secToken,
      scopeId: env.scopeId,
    });

    assert.strictEqual(result.isOk, true);
    const execRes = result.unwrapOr(null as any);
    assert.ok(execRes);
    assert.strictEqual(execRes.capabilityId, sampleCap.id);
    assert.strictEqual(execRes.adapterId, 'adapter:test-node');
    assert.strictEqual(execRes.state, 'SUCCEEDED');
    assert.strictEqual(execRes.exitCode, 0);
    assert.strictEqual(execRes.rawOutputSha256.length, 64);
    assert.ok(execRes.rawOutput.includes('PORT 80/tcp open http'));
    assert.ok(execRes.rawStderr.includes('scan completed successfully'));
    assert.ok(execRes.output);
    assert.strictEqual(execRes.output?.findings?.length, 1);

    // Verify execution persisted in DB
    const dbRecord = await env.executionRepo.findById(execRes.executionId, env.workspaceId);
    assert.ok(dbRecord);
    assert.strictEqual(dbRecord.state, 'SUCCEEDED');
    assert.strictEqual(dbRecord.raw_output_sha256, execRes.rawOutputSha256);
    assert.strictEqual(dbRecord.action, 'network:scan');
  });

  it('should reject execution fail-closed when target is outside authorized scope', async () => {
    const secToken = env.mintToken(env.workspaceId);

    // 172.16.0.1 is not in the scope's inclusions (192.168.0.0/16, 10.0.0.1)
    const result = await env.dispatcher.executeCapability({
      capabilityId: sampleCap.id,
      target: '172.16.0.1',
      port: 80,
      workspaceId: env.workspaceId,
      organizationId: env.orgId,
      actorId: env.userId,
      securityContext: secToken,
      scopeId: env.scopeId,
    });

    assert.strictEqual(result.isErr, true);
    if (result.isErr) {
      assert.strictEqual(result.error.error_code, ErrorCode.SCOPE_VIOLATION_OUT_OF_BOUNDS);
    }
  });

  it('should reject execution fail-closed on cross-workspace tenancy boundary violation', async () => {
    // Token is minted for foreign workspace, but execution request specifies main workspace
    const foreignToken = env.mintToken(env.foreignWorkspaceId);

    const result = await env.dispatcher.executeCapability({
      capabilityId: sampleCap.id,
      target: '192.168.1.1',
      port: 80,
      workspaceId: env.workspaceId,
      organizationId: env.orgId,
      actorId: env.userId,
      securityContext: foreignToken,
      scopeId: env.scopeId,
    });

    assert.strictEqual(result.isErr, true);
    if (result.isErr) {
      assert.strictEqual(result.error.error_code, ErrorCode.AUTH_CROSS_WORKSPACE_DENIED);
    }
  });

  it('should reject execution fail-closed when actor lacks required permission mask', async () => {
    const unprivilegedToken = env.mintToken(env.workspaceId, {
      permission_mask: 0,
    });

    const result = await env.dispatcher.executeCapability({
      capabilityId: sampleCap.id,
      target: '192.168.1.1',
      port: 80,
      workspaceId: env.workspaceId,
      organizationId: env.orgId,
      actorId: env.userId,
      securityContext: unprivilegedToken,
      scopeId: env.scopeId,
    });

    assert.strictEqual(result.isErr, true);
    if (result.isErr) {
      assert.strictEqual(result.error.error_code, ErrorCode.AUTH_FORBIDDEN);
    }
  });

  it('should successfully dispatch http:probe capability when target is in scope and actor is authorized', async () => {
    const secToken = env.mintToken(env.workspaceId, {
      permission_mask: PermissionBit.PROBING_ACTIVE | PermissionBit.SCOPE_READ,
    });

    const result = await env.dispatcher.executeCapability({
      capabilityId: sampleHttpCap.id,
      target: '192.168.1.1',
      port: 80,
      workspaceId: env.workspaceId,
      organizationId: env.orgId,
      actorId: env.userId,
      securityContext: secToken,
      scopeId: env.scopeId,
    });

    assert.strictEqual(result.isOk, true);
    const execRes = result.unwrapOr(null as any);
    assert.strictEqual(execRes.capabilityId, sampleHttpCap.id);
    assert.strictEqual(execRes.state, 'SUCCEEDED');
    assert.strictEqual(execRes.exitCode, 0);

    const dbRecord = await env.executionRepo.findById(execRes.executionId, env.workspaceId);
    assert.ok(dbRecord);
    assert.strictEqual(dbRecord.state, 'SUCCEEDED');
    assert.strictEqual(dbRecord.action, 'http:probe');
  });

  it('should reject http:probe capability when actor lacks PROBING_ACTIVE permission', async () => {
    const readOnlyToken = env.mintToken(env.workspaceId, {
      permission_mask: PermissionBit.SCOPE_READ,
    });

    const result = await env.dispatcher.executeCapability({
      capabilityId: sampleHttpCap.id,
      target: '192.168.1.1',
      port: 80,
      workspaceId: env.workspaceId,
      organizationId: env.orgId,
      actorId: env.userId,
      securityContext: readOnlyToken,
      scopeId: env.scopeId,
    });

    assert.strictEqual(result.isErr, true);
    if (result.isErr) {
      assert.strictEqual(result.error.error_code, ErrorCode.AUTH_FORBIDDEN);
    }
  });
});

