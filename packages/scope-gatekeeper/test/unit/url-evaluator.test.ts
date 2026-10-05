/**
 * Shadow : Helix Nebula (SHN) — URL Evaluator Pure Unit Tests
 *
 * Enforces SEC-INV-01, SEC-INV-08, and INV-06:
 * - Scheme enforcement & downgrade defense
 * - Userinfo SSRF bypass prevention (@ tricks)
 * - Port normalization & non-standard port isolation
 * - Path traversal defense & segment-aware containment
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  parseAndNormalizeUrl,
  isUrlContainedInScope,
} from '../../dist/index.js';

describe('URL Evaluator & Scope Containment (Pure Unit Tests)', () => {
  describe('URL Parsing & Normalization', () => {
    it('should parse and normalize standard https URLs', () => {
      const res = parseAndNormalizeUrl('HTTPS://API.EXAMPLE.COM:443/v1/users?page=1#frag');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value.scheme, 'https:');
      assert.strictEqual(res.value.host, 'api.example.com');
      assert.strictEqual(res.value.port, 443);
      assert.strictEqual(res.value.path, '/v1/users');
      assert.strictEqual(res.value.query, 'page=1');
      // Fragment stripped, default 443 port omitted in canonical form
      assert.strictEqual(res.value.canonical, 'https://api.example.com/v1/users?page=1');
    });

    it('should normalize default http port 80', () => {
      const res = parseAndNormalizeUrl('http://example.com:80/status');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value.port, 80);
      assert.strictEqual(res.value.canonical, 'http://example.com/status');
    });

    it('should preserve non-default port in canonical URL', () => {
      const res = parseAndNormalizeUrl('https://example.com:8443/api');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value.port, 8443);
      assert.strictEqual(res.value.canonical, 'https://example.com:8443/api');
    });

    it('should normalize path dot-segments', () => {
      const res = parseAndNormalizeUrl('https://example.com/api/v1/../v2/./users');
      assert.strictEqual(res.isOk, true);
      assert.strictEqual(res.value.path, '/api/v2/users');
    });

    it('should reject path traversal escaping root (.. past /)', () => {
      const res = parseAndNormalizeUrl('https://example.com/../../etc/passwd');
      assert.strictEqual(res.isErr, true);
      assert.match(res.error, /path traversal detected/i);
    });

    it('should reject null-byte injections in path segments', () => {
      const res = parseAndNormalizeUrl('https://example.com/api/v1%00admin');
      assert.strictEqual(res.isErr, true);
      assert.match(res.error, /null byte injection/i);
    });

    it('should reject URLs with userinfo (@) to prevent SSRF bypass attacks', () => {
      // Attacker payload: http://safe.example.com@169.254.169.254/
      const res1 = parseAndNormalizeUrl('http://user:pass@example.com/api');
      assert.strictEqual(res1.isErr, true);
      assert.match(res1.error, /userinfo \(@\) is prohibited/i);

      const res2 = parseAndNormalizeUrl('http://trusted.com@169.254.169.254/latest/meta-data/');
      assert.strictEqual(res2.isErr, true);
      assert.match(res2.error, /userinfo \(@\) is prohibited/i);
    });

    it('should reject dangerous and non-http schemes fail-closed', () => {
      assert.strictEqual(parseAndNormalizeUrl('file:///etc/shadow').isErr, true);
      assert.strictEqual(parseAndNormalizeUrl('javascript:alert(1)').isErr, true);
      assert.strictEqual(parseAndNormalizeUrl('ftp://ftp.example.com').isErr, true);
      assert.strictEqual(parseAndNormalizeUrl('data:text/html;base64,PHNjcmlwdD4=').isErr, true);
      assert.strictEqual(parseAndNormalizeUrl('gopher://127.0.0.1:6379').isErr, true);
    });
  });

  describe('Segment-Aware Path & URL Containment', () => {
    it('should match identical URLs', () => {
      assert.strictEqual(
        isUrlContainedInScope('https://example.com/api/v1', 'https://example.com/api/v1'),
        true
      );
    });

    it('should match child paths under parent scope path', () => {
      assert.strictEqual(
        isUrlContainedInScope('https://example.com/api/v1/users', 'https://example.com/api/v1'),
        true
      );
      assert.strictEqual(
        isUrlContainedInScope('https://example.com/api/v1/users/profile', 'https://example.com/api/v1/'),
        true
      );
    });

    it('CRITICAL: should NOT match prefix collisions without segment boundary (/api vs /api-evil)', () => {
      // Scope authorizes /api
      // Target is /api-evil or /api_admin
      assert.strictEqual(
        isUrlContainedInScope('https://example.com/api-evil/test', 'https://example.com/api'),
        false
      );
      assert.strictEqual(
        isUrlContainedInScope('https://example.com/api_admin', 'https://example.com/api'),
        false
      );
    });

    it('should reject scheme mismatch / downgrade attempt', () => {
      // Scope requires https, target is http
      assert.strictEqual(
        isUrlContainedInScope('http://example.com/api', 'https://example.com/api'),
        false
      );
      assert.strictEqual(
        isUrlContainedInScope('https://example.com/api', 'http://example.com/api'),
        false
      );
    });

    it('should reject port mismatch', () => {
      assert.strictEqual(
        isUrlContainedInScope('https://example.com:8443/api', 'https://example.com:443/api'),
        false
      );
      assert.strictEqual(
        isUrlContainedInScope('https://example.com/api', 'https://example.com:8443/api'),
        false
      );
    });

    it('should reject host mismatch', () => {
      assert.strictEqual(
        isUrlContainedInScope('https://evil.com/api', 'https://example.com/api'),
        false
      );
      assert.strictEqual(
        isUrlContainedInScope('https://evil-example.com/api', 'https://example.com/api'),
        false
      );
    });

    it('should authorize subdomains when scope host uses wildcard or dot-prefix', () => {
      assert.strictEqual(
        isUrlContainedInScope('https://api.example.com/v1', 'https://*.example.com/v1'),
        true
      );
      assert.strictEqual(
        isUrlContainedInScope('https://auth.example.com/v1', 'https://.example.com/v1'),
        true
      );
      assert.strictEqual(
        isUrlContainedInScope('https://evil-example.com/v1', 'https://*.example.com/v1'),
        false
      );
    });
  });
});
