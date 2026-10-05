/**
 * Shadow : Helix Nebula (SHN) — Hostname Evaluator Pure Unit Tests
 *
 * Enforces SEC-INV-01, SEC-INV-08, and INV-06:
 * - RFC 1123 canonicalization & trailing-dot normalization
 * - Suffix-confusion attack defense (evil-example.com vs example.com)
 * - Controlled wildcard (*.example.com) and dot-prefix (.example.com) subdomain containment
 * - Cloud metadata and loopback hostname blacklist
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  canonicalizeHostname,
  isHostnameContainedInScope,
  isBlacklistedHostname,
} from '../../dist/index.js';

describe('Hostname & Domain Evaluator (Pure Unit Tests)', () => {
  describe('Canonicalization & Normalization', () => {
    it('should lowercase mixed-case hostnames', () => {
      const res = canonicalizeHostname('ExAmPlE.CoM');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value, 'example.com');
    });

    it('should strip trailing root dots', () => {
      const res = canonicalizeHostname('api.example.com.');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value, 'api.example.com');
    });

    it('should strip port if passed as host:port', () => {
      const res = canonicalizeHostname('api.example.com:8080');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value, 'api.example.com');
    });

    it('should reject hostnames containing userinfo separator (@)', () => {
      const res = canonicalizeHostname('user:pass@example.com');
      assert.strictEqual(res.isErr, true);
      assert.match(res.error, /contains '@' userinfo separator/i);
    });

    it('should reject hostnames exceeding 253 characters', () => {
      const longLabel = 'a'.repeat(60);
      const longHost = `${longLabel}.${longLabel}.${longLabel}.${longLabel}.${longLabel}.com`;
      const res = canonicalizeHostname(longHost);
      assert.strictEqual(res.isErr, true);
      assert.match(res.error, /maximum length of 253/i);
    });

    it('should reject labels exceeding 63 characters', () => {
      const longLabel = 'a'.repeat(64);
      const res = canonicalizeHostname(`${longLabel}.com`);
      assert.strictEqual(res.isErr, true);
      assert.match(res.error, /exceeds 63 characters/i);
    });

    it('should reject consecutive dots and empty labels', () => {
      assert.strictEqual(canonicalizeHostname('example..com').isErr, true);
      assert.strictEqual(canonicalizeHostname('.example.com').isErr, true);
    });

    it('should reject labels with leading or trailing hyphens', () => {
      assert.strictEqual(canonicalizeHostname('-example.com').isErr, true);
      assert.strictEqual(canonicalizeHostname('example-.com').isErr, true);
    });
  });

  describe('Suffix-Confusion & Domain Containment Defense', () => {
    it('should authorize exact match', () => {
      assert.strictEqual(isHostnameContainedInScope('example.com', 'example.com'), true);
      assert.strictEqual(isHostnameContainedInScope('EXAMPLE.COM.', 'example.com'), true);
    });

    it('CRITICAL: should NEVER authorize suffix-confusion domains (evil-example.com)', () => {
      // An attacker registers evil-example.com or badexample.com
      assert.strictEqual(isHostnameContainedInScope('evil-example.com', 'example.com'), false);
      assert.strictEqual(isHostnameContainedInScope('notexample.com', 'example.com'), false);
      assert.strictEqual(isHostnameContainedInScope('badexample.com', 'example.com'), false);
      assert.strictEqual(isHostnameContainedInScope('myexample.com', 'example.com'), false);
    });

    it('should NOT automatically authorize subdomains under exact scope', () => {
      // exact scope "example.com" does not match "api.example.com"
      assert.strictEqual(isHostnameContainedInScope('api.example.com', 'example.com'), false);
    });

    it('should authorize subdomains under wildcard scope (*.example.com)', () => {
      assert.strictEqual(isHostnameContainedInScope('api.example.com', '*.example.com'), true);
      assert.strictEqual(isHostnameContainedInScope('internal.dev.example.com', '*.example.com'), true);
      // Wildcard does not authorize base domain itself
      assert.strictEqual(isHostnameContainedInScope('example.com', '*.example.com'), false);
      // Wildcard NEVER authorizes suffix confusion
      assert.strictEqual(isHostnameContainedInScope('evil-example.com', '*.example.com'), false);
      assert.strictEqual(isHostnameContainedInScope('bad-example.com', '*.example.com'), false);
    });

    it('should authorize base and subdomains under dot-prefix scope (.example.com)', () => {
      assert.strictEqual(isHostnameContainedInScope('example.com', '.example.com'), true);
      assert.strictEqual(isHostnameContainedInScope('api.example.com', '.example.com'), true);
      assert.strictEqual(isHostnameContainedInScope('a.b.c.example.com', '.example.com'), true);
      // Dot-prefix NEVER authorizes suffix confusion
      assert.strictEqual(isHostnameContainedInScope('evil-example.com', '.example.com'), false);
      assert.strictEqual(isHostnameContainedInScope('notexample.com', '.example.com'), false);
    });
  });

  describe('Cloud Metadata & Loopback Hostname Blacklist', () => {
    it('should blacklist localhost variations', () => {
      assert.strictEqual(isBlacklistedHostname('localhost'), true);
      assert.strictEqual(isBlacklistedHostname('localhost.localdomain'), true);
      assert.strictEqual(isBlacklistedHostname('app.localhost'), true);
    });

    it('should blacklist cloud provider metadata endpoints', () => {
      assert.strictEqual(isBlacklistedHostname('metadata.google.internal'), true);
      assert.strictEqual(isBlacklistedHostname('metadata.internal'), true);
      assert.strictEqual(isBlacklistedHostname('instance-data'), true);
      assert.strictEqual(isBlacklistedHostname('foo.metadata.google.internal'), true);
    });

    it('should allow legitimate domain hostnames', () => {
      assert.strictEqual(isBlacklistedHostname('example.com'), false);
      assert.strictEqual(isBlacklistedHostname('api.github.com'), false);
      assert.strictEqual(isBlacklistedHostname('target-system.internal.net'), false);
    });
  });
});
