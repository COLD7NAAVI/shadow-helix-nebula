import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateCapabilityManifest,
  validateToolAdapterManifest,
} from '../../dist/index.js';
import { ErrorCode } from '@shn/error-catalog';

describe('Manifest Validators (Unit Tests)', () => {
  const validCapabilityManifest = {
    id: 'shn://capabilities/network/scan/tcp',
    name: 'network.scan.tcp',
    version: '1.0.0',
    displayName: 'TCP Port Scanner',
    description: 'High-speed synthetic TCP port scanner with SYN detection',
    category: 'RECONNAISSANCE',
    riskLevel: 'LOW',
    supportedTargets: ['IP', 'CIDR', 'DOMAIN'],
    requiredPermissions: 1,
    requiredScopeAction: 'network:scan',
    platformCompatibility: ['linux', 'darwin', 'win32'],
    integrityDigest: 'a'.repeat(64),
    argumentSchema: { type: 'object' },
    outputSchema: { type: 'object' },
    metadata: { author: 'SHN Core' },
  };

  const validAdapterManifest = {
    id: 'adapter:nmap-scanner',
    name: 'Nmap Port Scanner Adapter',
    version: '1.0.0',
    binaryPath: '/usr/bin/nmap',
    platformSupport: ['linux', 'darwin', 'win32'],
    supportedCapabilities: [
      {
        capabilityId: 'shn://capabilities/network/scan/tcp',
        versionConstraint: '^1.0.0',
        priority: 100,
      },
    ],
    manifestDigest: 'b'.repeat(64),
    metadata: { tier: 'production' },
  };

  describe('validateCapabilityManifest', () => {
    it('should successfully validate a well-formed capability manifest', () => {
      const res = validateCapabilityManifest(validCapabilityManifest);
      assert.strictEqual(res.isOk, true);
      if (res.isOk) {
        assert.strictEqual(res.value.id, 'shn://capabilities/network/scan/tcp');
        assert.strictEqual(res.value.name, 'network.scan.tcp');
        assert.strictEqual(res.value.category, 'RECONNAISSANCE');
        assert.strictEqual(res.value.riskLevel, 'LOW');
        assert.strictEqual(res.value.lifecycleState, 'ACTIVE');
      }
    });

    it('should reject non-object or null manifests', () => {
      assert.strictEqual(validateCapabilityManifest(null).isErr, true);
      assert.strictEqual(validateCapabilityManifest('not an object').isErr, true);
      assert.strictEqual(validateCapabilityManifest([]).isErr, true);
    });

    it('should reject malformed or invalid capability IDs', () => {
      const invalid = { ...validCapabilityManifest, id: 'bad-id' };
      const res = validateCapabilityManifest(invalid);
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.CAP_MALFORMED_MANIFEST);
      }
    });

    it('should reject invalid categories', () => {
      const invalid = { ...validCapabilityManifest, category: 'NON_EXISTENT_CAT' };
      const res = validateCapabilityManifest(invalid);
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.CAP_MALFORMED_MANIFEST);
      }
    });

    it('should reject invalid risk levels', () => {
      const invalid = { ...validCapabilityManifest, riskLevel: 'EXTREME' };
      const res = validateCapabilityManifest(invalid);
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.CAP_MALFORMED_MANIFEST);
      }
    });

    it('should reject invalid target types', () => {
      const invalid = { ...validCapabilityManifest, supportedTargets: ['INVALID_TARGET'] };
      const res = validateCapabilityManifest(invalid);
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.CAP_MALFORMED_MANIFEST);
      }
    });

    it('should reject invalid platform types', () => {
      const invalid = { ...validCapabilityManifest, platformCompatibility: ['solaris'] };
      const res = validateCapabilityManifest(invalid);
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.CAP_MALFORMED_MANIFEST);
      }
    });

    it('should reject invalid integrity digest', () => {
      const invalid = { ...validCapabilityManifest, integrityDigest: 'not-a-valid-sha256' };
      const res = validateCapabilityManifest(invalid);
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.CAP_MALFORMED_MANIFEST);
      }
    });

    it('should reject empty or missing scope action', () => {
      const invalid = { ...validCapabilityManifest, requiredScopeAction: '' };
      const res = validateCapabilityManifest(invalid);
      assert.strictEqual(res.isErr, true);
      if (res.isErr) {
        assert.strictEqual(res.error.error_code, ErrorCode.CAP_MALFORMED_MANIFEST);
      }
    });
  });

  describe('validateToolAdapterManifest', () => {
    it('should successfully validate a well-formed adapter manifest', () => {
      const res = validateToolAdapterManifest(validAdapterManifest);
      assert.strictEqual(res.isOk, true);
      if (res.isOk) {
        assert.strictEqual(res.value.id, 'adapter:nmap-scanner');
        assert.strictEqual(res.value.binaryPath, '/usr/bin/nmap');
        assert.strictEqual(res.value.lifecycleState, 'REGISTERED');
      }
    });

    it('should reject shell injection attempts in binaryPath', () => {
      const injections = [
        '/usr/bin/nmap; rm -rf /',
        '/usr/bin/nmap && cat /etc/passwd',
        '/usr/bin/nmap | sh',
        '/usr/bin/nmap`whoami`',
        '/usr/bin/nmap$(id)',
        '/usr/bin/nmap\0',
        '/usr/bin/nmap\nls',
        '/usr/bin/nmap > /tmp/out',
      ];

      for (const injection of injections) {
        const manifest = { ...validAdapterManifest, binaryPath: injection };
        const res = validateToolAdapterManifest(manifest);
        assert.strictEqual(res.isErr, true, `Expected rejection for: ${injection}`);
        if (res.isErr) {
          assert.strictEqual(res.error.error_code, ErrorCode.EXEC_COMMAND_INJECTION_REJECTED);
        }
      }
    });

    it('should reject path traversal in binaryPath', () => {
      const traversals = [
        '../bin/nmap',
        '../../../../etc/shadow',
        '/usr/local/../bin/nmap',
        'tools/../../dangerous',
      ];

      for (const traversal of traversals) {
        const manifest = { ...validAdapterManifest, binaryPath: traversal };
        const res = validateToolAdapterManifest(manifest);
        assert.strictEqual(res.isErr, true, `Expected rejection for traversal: ${traversal}`);
        if (res.isErr) {
          assert.strictEqual(res.error.error_code, ErrorCode.EXEC_COMMAND_INJECTION_REJECTED);
        }
      }
    });

    it('should reject Windows batch scripts in binaryPath (.bat, .cmd)', () => {
      const batchScripts = ['nmap.bat', 'C:\\tools\\scanner.cmd', '/opt/bin/tool.BAT'];
      for (const b of batchScripts) {
        const manifest = { ...validAdapterManifest, binaryPath: b };
        const res = validateToolAdapterManifest(manifest);
        assert.strictEqual(res.isErr, true, `Expected rejection for batch script: ${b}`);
        if (res.isErr) {
          assert.strictEqual(res.error.error_code, ErrorCode.EXEC_COMMAND_INJECTION_REJECTED);
        }
      }
    });

    it('should reject invalid or missing supportedCapabilities bindings', () => {
      const invalidBindings = [
        { ...validAdapterManifest, supportedCapabilities: [] },
        { ...validAdapterManifest, supportedCapabilities: [{ capabilityId: 'bad-id' }] },
        {
          ...validAdapterManifest,
          supportedCapabilities: [
            { capabilityId: 'shn://capabilities/a/b', versionConstraint: 'invalid-semver' },
          ],
        },
      ];

      for (const inv of invalidBindings) {
        const res = validateToolAdapterManifest(inv);
        assert.strictEqual(res.isErr, true);
      }
    });
  });
});
