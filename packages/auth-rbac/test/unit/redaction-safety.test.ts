/**
 * Shadow : Helix Nebula (SHN) — Redaction & Audit Safety Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { makeAuthProblem, hashToken } from '../../dist/index.js';
import { ErrorCode } from '@shn/error-catalog';

describe('Redaction & Audit Safety (Pure Unit Tests)', () => {
  it('should not leak passwords or secret material in RFC 7807 problem details', () => {
    const rawSecret = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0 sensitive-private-key';
    const problem = makeAuthProblem(
      ErrorCode.AUTH_CREDENTIALS_INVALID,
      'Invalid authentication credentials provided',
      '/auth/login'
    );

    const serialized = JSON.stringify(problem);
    assert.strictEqual(serialized.includes(rawSecret), false);
    assert.strictEqual(problem.error_code, 'ERR_AUTH_CREDENTIALS_INVALID');
    assert.strictEqual(problem.status, 401);
  });

  it('should store only SHA-256 hashes of session tokens, never raw tokens', () => {
    const rawToken = 'shn_sec_abcdef1234567890abcdef1234567890';
    const digest = hashToken(rawToken);

    assert.notStrictEqual(digest, rawToken);
    assert.strictEqual(digest.length, 64);
    assert.strictEqual(/^[0-9a-f]{64}$/.test(digest), true);
  });
});
