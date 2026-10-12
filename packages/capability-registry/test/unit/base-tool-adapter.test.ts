import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  BaseToolAdapter,
  NetworkPortScanAdapter,
  HttpDiscoveryAdapter,
  type CapabilityDefinition,
  type CommandVector,
  type AdapterExecutionOutput,
  type EvidenceArtifact,
  type ProblemDetails,
} from '../../dist/index.js';
import { ok, type Result } from '@shn/shared-kernel';
import { ErrorCode } from '@shn/error-catalog';

class TestMockToolAdapter extends BaseToolAdapter {
  readonly adapterId = 'adapter:mock-tool' as any;
  readonly name = 'Mock Tool Adapter';
  readonly version = '1.0.0';
  readonly binaryPath = '/usr/bin/mock-tool';
  readonly platformSupport = ['linux', 'darwin', 'win32'] as const;
  readonly supportedCapabilities = [
    {
      capabilityId: 'shn://capabilities/test/mock' as any,
      versionConstraint: '^1.0.0',
      priority: 50,
    },
  ];

  constructor() {
    super();
  }

  buildCommand(
    _capability: CapabilityDefinition,
    target: string,
    params: Record<string, unknown>,
    port?: number
  ): Result<CommandVector, ProblemDetails> {
    const args: string[] = ['--target', target];
    if (port) args.push('--port', String(port));
    if (params['flag']) args.push(String(params['flag']));

    return ok({
      executable: this.binaryPath,
      args,
      resourceLimits: {},
    });
  }

  parseOutput(
    rawOutput: string,
    rawStderr: string,
    exitCode: number,
    sha256: string
  ): Result<AdapterExecutionOutput, ProblemDetails> {
    return ok({
      success: exitCode === 0,
      exitCode,
      summary: `Parsed ${rawOutput.length} output bytes`,
      structuredData: { stdoutLen: rawOutput.length, stderrLen: rawStderr.length },
      artifacts: this.extractEvidence(rawOutput, rawStderr, sha256),
    });
  }

  extractEvidence(
    rawOutput: string,
    _rawStderr: string,
    sha256: string
  ): readonly EvidenceArtifact[] {
    return [
      {
        artifactId: 'evidence-1',
        label: 'Raw Output Log',
        mediaType: 'text/plain',
        sizeBytes: rawOutput.length,
        sha256,
      },
    ];
  }
}

describe('Base Tool Adapter & Reference Adapters (Unit Tests)', () => {
  const mockCapability: CapabilityDefinition = {
    id: 'shn://capabilities/test/mock' as any,
    name: 'test.mock',
    version: '1.0.0',
    displayName: 'Mock Test Capability',
    description: 'Capability for unit testing base tool adapter',
    category: 'UTILITY',
    riskLevel: 'LOW',
    supportedTargets: ['IP', 'DOMAIN'],
    requiredPermissions: 0,
    requiredScopeAction: 'test:mock',
    argumentSchema: {
      type: 'object',
      required: ['flag'],
      properties: { flag: { type: 'string' } },
    },
    outputSchema: { type: 'object' },
    platformCompatibility: ['linux', 'darwin', 'win32'],
    lifecycleState: 'ACTIVE',
    integrityDigest: 'd'.repeat(64),
  };

  const adapter = new TestMockToolAdapter();

  describe('Parameter Validation', () => {
    it('should validate and sanitize valid parameters', () => {
      const res = adapter.validateParameters(mockCapability, { flag: ' --verbose ' });
      assert.strictEqual(res.isOk, true);
      if (res.isOk) {
        assert.strictEqual(res.value['flag'], '--verbose');
      }
    });

    it('should fail if a required parameter is missing', () => {
      const res = adapter.validateParameters(mockCapability, {});
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.INVALID_PAYLOAD_SCHEMA);
      }
    });

    it('should reject parameters containing null bytes (\\0)', () => {
      const res = adapter.validateParameters(mockCapability, { flag: 'bad\0value' });
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.EXEC_COMMAND_INJECTION_REJECTED);
      }
    });

    it('should reject parameters that exceed the length ceiling', () => {
      const res = adapter.validateParameters(mockCapability, { flag: 'x'.repeat(9000) });
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.INVALID_PAYLOAD_SCHEMA);
      }
    });
  });

  describe('Target Validation', () => {
    it('should accept valid targets', () => {
      assert.strictEqual(adapter.validateTarget(mockCapability, '192.168.1.1').isOk, true);
      assert.strictEqual(adapter.validateTarget(mockCapability, 'example.com').isOk, true);
    });

    it('should reject empty or whitespace targets', () => {
      assert.strictEqual(adapter.validateTarget(mockCapability, '').isErr, true);
      assert.strictEqual(adapter.validateTarget(mockCapability, '   ').isErr, true);
    });

    it('should reject null bytes in targets', () => {
      const res = adapter.validateTarget(mockCapability, '192.168.1.1\0');
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.EXEC_COMMAND_INJECTION_REJECTED);
      }
    });

    it('should reject shell metacharacters in targets', () => {
      const malicious = [
        '127.0.0.1; whoami',
        '127.0.0.1 && cat /etc/passwd',
        '127.0.0.1 | bash',
        '127.0.0.1`id`',
        '127.0.0.1$PATH',
        '127.0.0.1\nls',
      ];
      for (const m of malicious) {
        const res = adapter.validateTarget(mockCapability, m);
        assert.strictEqual(res.isErr, true, `Expected rejection for: ${m}`);
        if (res.isErr) {
          assert.strictEqual(res.error.error_code, ErrorCode.EXEC_COMMAND_INJECTION_REJECTED);
        }
      }
    });

    it('should reject targets exceeding maximum length', () => {
      const res = adapter.validateTarget(mockCapability, 'a'.repeat(2049));
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.INVALID_PAYLOAD_SCHEMA);
      }
    });
  });

  describe('Command Construction and Execution Contracts', () => {
    it('should construct a structured command vector without shell interpolation', () => {
      const res = adapter.buildCommand(mockCapability, '10.0.0.1', { flag: '--quiet' }, 443);
      assert.strictEqual(res.isOk, true);
      if (res.isOk) {
        assert.strictEqual(res.value.executable, '/usr/bin/mock-tool');
        assert.deepStrictEqual(res.value.args, ['--target', '10.0.0.1', '--port', '443', '--quiet']);
      }
    });

    it('should classify termination reasons correctly', () => {
      assert.strictEqual(adapter.classifyError(0, ''), 'NORMAL_EXIT');
      assert.strictEqual(adapter.classifyError(1, 'failed'), 'PROCESS_CRASH');
      assert.strictEqual(adapter.classifyError(127, 'not found'), 'PROCESS_CRASH');
    });

    it('should parse output and preserve cryptographic evidence hashes', () => {
      const sha = 'e'.repeat(64);
      const res = adapter.parseOutput('sample output', '', 0, sha);
      assert.strictEqual(res.isOk, true);
      if (res.isOk) {
        assert.strictEqual(res.value.success, true);
        assert.strictEqual(res.value.artifacts.length, 1);
        assert.strictEqual(res.value.artifacts[0]?.sha256, sha);
      }
    });
  });

  describe('Concrete Reference Adapters', () => {
    describe('NetworkPortScanAdapter', () => {
      const scanAdapter = new NetworkPortScanAdapter();

      it('should be instantiated with canonical binding', () => {
        assert.strictEqual(scanAdapter.adapterId, 'adapter:network-port-scan');
        assert.strictEqual(scanAdapter.getLifecycleState(), 'AVAILABLE');
        assert.strictEqual(scanAdapter.supportedCapabilities.length, 1);
      });

      it('should build command vector with structured arguments', () => {
        const cmdRes = scanAdapter.buildCommand(mockCapability, '192.168.1.1', { mode: 'SYN' }, 80);
        assert.strictEqual(cmdRes.isOk, true);
        if (cmdRes.isOk) {
          assert.strictEqual(cmdRes.value.args.includes('192.168.1.1'), true);
          assert.strictEqual(cmdRes.value.args.includes('-p'), true);
        }
      });
    });

    describe('HttpDiscoveryAdapter', () => {
      const httpAdapter = new HttpDiscoveryAdapter();

      it('should be instantiated with canonical binding', () => {
        assert.strictEqual(httpAdapter.adapterId, 'adapter:http-discovery');
        assert.strictEqual(httpAdapter.getLifecycleState(), 'AVAILABLE');
        assert.strictEqual(httpAdapter.supportedCapabilities.length, 1);
      });

      it('should build command vector with structured target and method', () => {
        const cmdRes = httpAdapter.buildCommand(
          mockCapability,
          'https://api.example.com',
          { method: 'GET', followRedirects: true }
        );
        assert.strictEqual(cmdRes.isOk, true);
        if (cmdRes.isOk) {
          assert.strictEqual(cmdRes.value.args.includes('https://api.example.com'), true);
        }
      });
    });
  });
});
