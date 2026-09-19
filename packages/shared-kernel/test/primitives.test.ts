import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateUUIDv7,
  isValidUUID,
  createWorkspaceId,
  parseIPv4,
  parseCidr,
  parsePort,
  parsePortRange,
  parseHostname,
  isProhibitedTarget,
} from '../dist/index.js';

describe('Domain Primitives & Target Validation', () => {
  it('should generate valid time-ordered UUIDv7', () => {
    const id = generateUUIDv7();
    assert.equal(isValidUUID(id), true);
    // UUIDv7 has '7' at character 14 (0-indexed: index 14)
    assert.equal(id.charAt(14), '7');
  });

  it('should brand valid WorkspaceId and reject malformed UUID', () => {
    const valid = createWorkspaceId('550e8400-e29b-41d4-a716-446655440000');
    assert.equal(valid.isOk, true);

    const invalid = createWorkspaceId('not-a-uuid');
    assert.equal(invalid.isErr, true);
  });

  it('should parse valid IPv4 and reject invalid formats', () => {
    const valid = parseIPv4('192.168.1.1');
    assert.equal(valid.isOk, true);

    const outOfBounds = parseIPv4('256.0.0.1');
    assert.equal(outOfBounds.isErr, true);
  });

  it('should permanently block cloud metadata and loopback addresses (SEC-INV-08)', () => {
    assert.equal(isProhibitedTarget('169.254.169.254'), true);
    assert.equal(isProhibitedTarget('127.0.0.1'), true);
    assert.equal(isProhibitedTarget('localhost'), true);
    assert.equal(isProhibitedTarget('169.254.10.20'), true);

    const metadataAttempt = parseIPv4('169.254.169.254');
    assert.equal(metadataAttempt.isErr, true);
    if (metadataAttempt.isErr) {
      assert.match(metadataAttempt.error, /blacklisted/);
    }
  });

  it('should parse valid CIDR blocks and validate mask limits (0..32)', () => {
    const valid = parseCidr('10.0.0.0/24');
    assert.equal(valid.isOk, true);

    const invalidMask = parseCidr('10.0.0.0/33');
    assert.equal(invalidMask.isErr, true);

    const negativeMask = parseCidr('10.0.0.0/-1');
    assert.equal(negativeMask.isErr, true);
  });

  it('should validate Port and PortRange boundaries (1..65535)', () => {
    const validPort = parsePort(443);
    assert.equal(validPort.isOk, true);

    const zeroPort = parsePort(0);
    assert.equal(zeroPort.isErr, true);

    const highPort = parsePort(70000);
    assert.equal(highPort.isErr, true);

    const validRange = parsePortRange(80, 443);
    assert.equal(validRange.isOk, true);

    const invertedRange = parsePortRange(443, 80);
    assert.equal(invertedRange.isErr, true);
  });

  it('should validate FQDN hostnames and block metadata hostnames', () => {
    const valid = parseHostname('target.example.com');
    assert.equal(valid.isOk, true);

    const blocked = parseHostname('metadata.google.internal');
    assert.equal(blocked.isErr, true);
  });
});
