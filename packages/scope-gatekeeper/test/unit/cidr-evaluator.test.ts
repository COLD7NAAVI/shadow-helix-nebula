/**
 * Shadow : Helix Nebula (SHN) — CIDR Evaluator Pure Unit Tests
 *
 * Enforces SEC-INV-01, SEC-INV-08, and INV-06.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  parseIPv4Address,
  formatIPv4Address,
  parseIPv6Address,
  formatIPv6Address,
  parseCidrBlock,
  isTargetContainedInCidr,
  isBlacklistedIpOrCidr,
  getIPv4Mask,
  getIPv6Mask,
} from '../../dist/index.js';

describe('CIDR Evaluator & Bitwise Math (Pure Unit Tests)', () => {
  describe('IPv4 & IPv6 Bitwise Mask Generation', () => {
    it('should compute correct IPv4 bitwise masks', () => {
      assert.strictEqual(getIPv4Mask(0), 0);
      assert.strictEqual(getIPv4Mask(8), 0xff000000 >>> 0);
      assert.strictEqual(getIPv4Mask(16), 0xffff0000 >>> 0);
      assert.strictEqual(getIPv4Mask(24), 0xffffff00 >>> 0);
      assert.strictEqual(getIPv4Mask(32), 0xffffffff >>> 0);
    });

    it('should reject invalid IPv4 prefixes', () => {
      assert.throws(() => getIPv4Mask(-1), /Invalid IPv4 prefix/);
      assert.throws(() => getIPv4Mask(33), /Invalid IPv4 prefix/);
      assert.throws(() => getIPv4Mask(24.5), /Invalid IPv4 prefix/);
    });

    it('should compute correct IPv6 bitwise masks', () => {
      assert.strictEqual(getIPv6Mask(0), 0n);
      assert.strictEqual(getIPv6Mask(64), ((1n << 128n) - 1n) ^ ((1n << 64n) - 1n));
      assert.strictEqual(getIPv6Mask(128), (1n << 128n) - 1n);
    });

    it('should reject invalid IPv6 prefixes', () => {
      assert.throws(() => getIPv6Mask(-1), /Invalid IPv6 prefix/);
      assert.throws(() => getIPv6Mask(129), /Invalid IPv6 prefix/);
    });
  });

  describe('IPv4 Address Parsing & Formatting', () => {
    it('should parse valid IPv4 addresses', () => {
      const parsed = parseIPv4Address('192.168.1.1');
      assert.strictEqual(parsed.isOk, true);
      assert.strictEqual(parsed.value, 0xc0a80101 >>> 0);
      assert.strictEqual(formatIPv4Address(parsed.value), '192.168.1.1');
    });

    it('should reject leading zeros to prevent octal ambiguity attacks', () => {
      const res1 = parseIPv4Address('010.0.0.1');
      assert.strictEqual(res1.isErr, true);
      assert.match(res1.error, /leading zeros prohibited/i);

      const res2 = parseIPv4Address('192.168.01.1');
      assert.strictEqual(res2.isErr, true);
      assert.match(res2.error, /leading zeros prohibited/i);
    });

    it('should reject malformed IPv4 strings', () => {
      assert.strictEqual(parseIPv4Address('256.0.0.1').isErr, true);
      assert.strictEqual(parseIPv4Address('192.168.1').isErr, true);
      assert.strictEqual(parseIPv4Address('192.168.1.1.1').isErr, true);
      assert.strictEqual(parseIPv4Address('abc.def.ghi.jkl').isErr, true);
      assert.strictEqual(parseIPv4Address('-1.0.0.1').isErr, true);
      assert.strictEqual(parseIPv4Address('').isErr, true);
    });
  });

  describe('IPv6 Address Parsing & Formatting', () => {
    it('should parse and canonicalize standard IPv6 addresses', () => {
      const res = parseIPv6Address('2001:db8::1');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(formatIPv6Address(res.value), '2001:db8::1');
    });

    it('should handle IPv4-mapped IPv6 addresses', () => {
      const res = parseIPv6Address('::ffff:192.168.1.1');
      assert.strictEqual(res.isOk, true);
      // Canonical format compresses leading zeros
      assert.strictEqual(formatIPv6Address(res.value), '::ffff:c0a8:101');
    });

    it('should reject multiple :: compressions', () => {
      const res = parseIPv6Address('2001::db8::1');
      assert.strictEqual(res.isErr, true);
      assert.match(res.error, /multiple '::' compressions/i);
    });

    it('should reject invalid hextets', () => {
      assert.strictEqual(parseIPv6Address('2001:gggg::1').isErr, true);
      assert.strictEqual(parseIPv6Address('2001:12345::1').isErr, true);
    });
  });

  describe('CIDR Block Parsing & Normalization', () => {
    it('should normalize IPv4 CIDR network address', () => {
      // 192.168.1.55/24 network is 192.168.1.0/24
      const res = parseCidrBlock('192.168.1.55/24');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value.version, 4);
      assert.strictEqual(res.value.canonical, '192.168.1.0/24');
      assert.strictEqual(res.value.maskBits, 24);
    });

    it('should normalize IPv6 CIDR network address', () => {
      const res = parseCidrBlock('2001:db8:0000:0001:0000:0000:0000:0055/48');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value.version, 6);
      assert.strictEqual(res.value.canonical, '2001:db8::/48');
      assert.strictEqual(res.value.maskBits, 48);
    });

    it('should reject malformed CIDRs', () => {
      assert.strictEqual(parseCidrBlock('192.168.1.1').isErr, true);
      assert.strictEqual(parseCidrBlock('192.168.1.1/33').isErr, true);
      assert.strictEqual(parseCidrBlock('192.168.1.1/-1').isErr, true);
      assert.strictEqual(parseCidrBlock('192.168.1.1/abc').isErr, true);
      assert.strictEqual(parseCidrBlock('192.168.1.1/024').isErr, true); // leading zero in prefix
    });
  });

  describe('Subnet Containment & Boundary Verification', () => {
    it('should verify exact IP containment in /32', () => {
      assert.strictEqual(isTargetContainedInCidr('10.0.0.1', '10.0.0.1/32'), true);
      assert.strictEqual(isTargetContainedInCidr('10.0.0.2', '10.0.0.1/32'), false);
    });

    it('should verify IPv4 host containment in /24 subnet', () => {
      assert.strictEqual(isTargetContainedInCidr('192.168.1.50', '192.168.1.0/24'), true);
      assert.strictEqual(isTargetContainedInCidr('192.168.2.50', '192.168.1.0/24'), false);
    });

    it('should verify boundary addresses in IPv4 subnet', () => {
      // Network address
      assert.strictEqual(isTargetContainedInCidr('192.168.1.0', '192.168.1.0/24'), true);
      // Broadcast address
      assert.strictEqual(isTargetContainedInCidr('192.168.1.255', '192.168.1.0/24'), true);
      // First usable & last usable
      assert.strictEqual(isTargetContainedInCidr('192.168.1.1', '192.168.1.0/24'), true);
      assert.strictEqual(isTargetContainedInCidr('192.168.1.254', '192.168.1.0/24'), true);
      // Outside boundary
      assert.strictEqual(isTargetContainedInCidr('192.168.0.255', '192.168.1.0/24'), false);
      assert.strictEqual(isTargetContainedInCidr('192.168.2.0', '192.168.1.0/24'), false);
    });

    it('should verify child subnet containment in parent subnet', () => {
      assert.strictEqual(isTargetContainedInCidr('10.1.2.0/24', '10.1.0.0/16'), true);
      assert.strictEqual(isTargetContainedInCidr('10.1.2.0/28', '10.1.2.0/24'), true);
    });

    it('should reject parent subnet when tested against narrower child subnet', () => {
      assert.strictEqual(isTargetContainedInCidr('10.1.0.0/16', '10.1.2.0/24'), false);
    });

    it('should reject adjacent / sibling subnets', () => {
      assert.strictEqual(isTargetContainedInCidr('192.168.1.0/24', '192.168.2.0/24'), false);
      assert.strictEqual(isTargetContainedInCidr('192.168.2.0/24', '192.168.1.0/24'), false);
    });

    it('should verify IPv6 host and subnet containment', () => {
      assert.strictEqual(isTargetContainedInCidr('2001:db8::1', '2001:db8::/32'), true);
      assert.strictEqual(isTargetContainedInCidr('2001:db8:1::/48', '2001:db8::/32'), true);
      assert.strictEqual(isTargetContainedInCidr('2001:db9::1', '2001:db8::/32'), false);
    });

    it('should reject IPv4 vs IPv6 version mismatch fail-closed', () => {
      assert.strictEqual(isTargetContainedInCidr('192.168.1.1', '2001:db8::/32'), false);
      assert.strictEqual(isTargetContainedInCidr('2001:db8::1', '192.168.1.0/24'), false);
    });
  });

  describe('Cloud Metadata & SSRF Blacklist Enforcement', () => {
    it('should detect AWS / Azure / GCP IMDS endpoint (169.254.169.254)', () => {
      assert.strictEqual(isBlacklistedIpOrCidr('169.254.169.254'), true);
      assert.strictEqual(isBlacklistedIpOrCidr('169.254.169.254/32'), true);
    });

    it('should detect Alibaba Cloud IMDS endpoint (100.100.100.200)', () => {
      assert.strictEqual(isBlacklistedIpOrCidr('100.100.100.200'), true);
    });

    it('should detect IPv4 loopback (127.0.0.0/8)', () => {
      assert.strictEqual(isBlacklistedIpOrCidr('127.0.0.1'), true);
      assert.strictEqual(isBlacklistedIpOrCidr('127.0.0.2'), true);
      assert.strictEqual(isBlacklistedIpOrCidr('127.255.255.254'), true);
    });

    it('should detect IPv4 link-local (169.254.0.0/16)', () => {
      assert.strictEqual(isBlacklistedIpOrCidr('169.254.1.1'), true);
      assert.strictEqual(isBlacklistedIpOrCidr('169.254.254.254'), true);
    });

    it('should detect IPv6 loopback (::1)', () => {
      assert.strictEqual(isBlacklistedIpOrCidr('::1'), true);
    });

    it('should detect AWS IMDSv6 (fd00:ec2::254)', () => {
      assert.strictEqual(isBlacklistedIpOrCidr('fd00:ec2::254'), true);
    });

    it('should detect IPv6 link-local (fe80::/10)', () => {
      assert.strictEqual(isBlacklistedIpOrCidr('fe80::1'), true);
      assert.strictEqual(isBlacklistedIpOrCidr('fe80::abcd:ef01'), true);
    });

    it('should allow legitimate public and private targets', () => {
      assert.strictEqual(isBlacklistedIpOrCidr('10.0.0.1'), false);
      assert.strictEqual(isBlacklistedIpOrCidr('172.16.0.1'), false);
      assert.strictEqual(isBlacklistedIpOrCidr('192.168.1.1'), false);
      assert.strictEqual(isBlacklistedIpOrCidr('8.8.8.8'), false);
      assert.strictEqual(isBlacklistedIpOrCidr('2001:db8::1'), false);
    });
  });
});
