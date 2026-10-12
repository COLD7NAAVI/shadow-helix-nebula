/**
 * Shadow : Helix Nebula (SHN) — Target Canonicalizer Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  detectTargetType,
  canonicalizeTarget,
  normalizeTarget,
} from '../../dist/index.js';

describe('Target Canonicalizer (Pure Unit Tests)', () => {
  describe('detectTargetType', () => {
    it('should detect URLs correctly', () => {
      assert.strictEqual(detectTargetType('https://api.internal:8080/v1'), 'URL');
      assert.strictEqual(detectTargetType('http://192.168.1.1/test'), 'URL');
    });

    it('should detect IPv4 addresses', () => {
      assert.strictEqual(detectTargetType('192.168.1.1'), 'IPV4');
      assert.strictEqual(detectTargetType('10.0.0.254'), 'IPV4');
    });

    it('should detect CIDR blocks', () => {
      assert.strictEqual(detectTargetType('192.168.1.0/24'), 'CIDR');
      assert.strictEqual(detectTargetType('10.0.0.0/8'), 'CIDR');
    });

    it('should detect IPv6 addresses', () => {
      assert.strictEqual(detectTargetType('2001:db8::1'), 'IPV6');
      assert.strictEqual(detectTargetType('fe80::1ff:fe23:4567:890a'), 'IPV6');
    });

    it('should detect FQDNs', () => {
      assert.strictEqual(detectTargetType('sub.example.com'), 'FQDN');
      assert.strictEqual(detectTargetType('prod-app.corp.internal'), 'FQDN');
    });

    it('should detect standalone HOST identifiers', () => {
      assert.strictEqual(detectTargetType('web-server-01'), 'HOST');
      assert.strictEqual(detectTargetType('bastion'), 'HOST');
    });
  });

  describe('canonicalizeTarget', () => {
    it('should canonicalize valid IPv4 addresses', () => {
      const res = canonicalizeTarget('IPV4', '192.168.01.05');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value, '192.168.1.5');
    });

    it('should reject invalid IPv4 addresses', () => {
      const res = canonicalizeTarget('IPV4', '999.168.1.1');
      assert.strictEqual(res.isErr, true);
    });

    it('should canonicalize CIDR notation to network address', () => {
      const res = canonicalizeTarget('CIDR', '192.168.1.55/24');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value, '192.168.1.0/24');
    });

    it('should canonicalize FQDN to lowercase without trailing dot', () => {
      const res = canonicalizeTarget('FQDN', 'API.CORP.Internal.');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value, 'api.corp.internal');
    });

    it('should canonicalize URL removing standard ports and lowercasing hostname', () => {
      const res = canonicalizeTarget('URL', 'HTTPS://API.Corp.Internal:443/v1/users?q=1');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value, 'https://api.corp.internal/v1/users?q=1');
    });

    it('should preserve non-standard URL ports', () => {
      const res = canonicalizeTarget('URL', 'http://internal.service:8080/health');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value, 'http://internal.service:8080/health');
    });

    it('should reject non-http URL protocols fail-closed', () => {
      const res = canonicalizeTarget('URL', 'ftp://ftp.example.com/data');
      assert.strictEqual(res.isErr, true);
    });
  });

  describe('normalizeTarget auto-detection and normalization', () => {
    it('should auto-detect and normalize targets end-to-end', () => {
      const res = normalizeTarget('  10.0.0.1  ');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value.type, 'IPV4');
      assert.strictEqual(res.value.canonicalValue, '10.0.0.1');
    });
  });
});
