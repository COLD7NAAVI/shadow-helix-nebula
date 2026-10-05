/**
 * Shadow : Helix Nebula (SHN) — Security Context Signer Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  SecurityContextSigner,
  DEFAULT_CONTEXT_TTL_SECONDS,
  PermissionBit,
} from '../../dist/index.js';
import type { WorkspaceId } from '@shn/shared-kernel';

const TEST_SECRET_KEY = 'test-security-context-secret-key-32b-long!!';
const TEST_SUBJECT_ID = '00000000-0000-7000-8000-000000000001';
const TEST_WORKSPACE_ID = '00000000-0000-7000-8000-000000000002' as WorkspaceId;

describe('Security Context Token Signer & Verifier (Pure Unit Tests)', () => {
  const signer = new SecurityContextSigner(TEST_SECRET_KEY);

  it('should issue a valid HMAC-signed SecurityContextToken with expected claims', () => {
    const token = signer.createToken({
      subjectId: TEST_SUBJECT_ID,
      subjectType: 'OPERATOR',
      workspaceId: TEST_WORKSPACE_ID,
      roles: ['OPERATOR', 'ANALYST'],
      permissionMask: PermissionBit.SCOPE_READ | PermissionBit.WORKFLOW_READ,
    });

    assert.strictEqual(token.subject_id, TEST_SUBJECT_ID);
    assert.strictEqual(token.subject_type, 'OPERATOR');
    assert.strictEqual(token.workspace_id, TEST_WORKSPACE_ID);
    assert.deepEqual(token.roles, ['OPERATOR', 'ANALYST']);
    assert.strictEqual(token.permission_mask, PermissionBit.SCOPE_READ | PermissionBit.WORKFLOW_READ);
    assert.ok(typeof token.signature === 'string' && token.signature.length === 64);
    assert.ok(token.issued_at.endsWith('Z'));
    assert.ok(token.expires_at.endsWith('Z'));

    const issuedMs = new Date(token.issued_at).getTime();
    const expiresMs = new Date(token.expires_at).getTime();
    assert.strictEqual(Math.round((expiresMs - issuedMs) / 1000), DEFAULT_CONTEXT_TTL_SECONDS);
  });

  it('should verify a valid token and return ok Result', () => {
    const token = signer.createToken({
      subjectId: TEST_SUBJECT_ID,
      workspaceId: TEST_WORKSPACE_ID,
      roles: ['WORKSPACE_ADMIN'],
      permissionMask: PermissionBit.SCOPE_ADMIN,
    });

    const verifyRes = signer.verifyToken(token);
    assert.strictEqual(verifyRes.isOk, true);
    if (verifyRes.isOk) {
      assert.strictEqual(verifyRes.value.subject_id, TEST_SUBJECT_ID);
      assert.strictEqual(verifyRes.value.permission_mask, PermissionBit.SCOPE_ADMIN);
    }
  });

  it('should reject tampered roles or permission mask fail-closed', () => {
    const token = signer.createToken({
      subjectId: TEST_SUBJECT_ID,
      workspaceId: TEST_WORKSPACE_ID,
      roles: ['OBSERVER'],
      permissionMask: PermissionBit.SCOPE_READ,
    });

    // Tamper with permission mask (privilege escalation attempt)
    const escalatedToken = {
      ...token,
      permission_mask: PermissionBit.SCOPE_ADMIN | PermissionBit.IAM_ADMIN,
    };

    const verifyRes = signer.verifyToken(escalatedToken);
    assert.strictEqual(verifyRes.isOk, false);
    if (!verifyRes.isOk) {
      assert.strictEqual(verifyRes.error.error_code, 'ERR_AUTH_TOKEN_INVALID');
      assert.strictEqual(verifyRes.error.status, 401);
    }
  });

  it('should reject tampered signature fail-closed', () => {
    const token = signer.createToken({
      subjectId: TEST_SUBJECT_ID,
      workspaceId: TEST_WORKSPACE_ID,
      roles: ['OPERATOR'],
      permissionMask: PermissionBit.SCOPE_READ,
    });

    const forgedToken = {
      ...token,
      signature: '0'.repeat(64),
    };

    const verifyRes = signer.verifyToken(forgedToken);
    assert.strictEqual(verifyRes.isOk, false);
    if (!verifyRes.isOk) {
      assert.strictEqual(verifyRes.error.error_code, 'ERR_AUTH_TOKEN_INVALID');
    }
  });

  it('should reject expired tokens fail-closed', () => {
    const shortTtlSigner = new SecurityContextSigner(TEST_SECRET_KEY);
    const token = shortTtlSigner.createToken({
      subjectId: TEST_SUBJECT_ID,
      workspaceId: TEST_WORKSPACE_ID,
      roles: ['OPERATOR'],
      permissionMask: PermissionBit.SCOPE_READ,
      ttlSeconds: 1, // 1 second TTL
    });

    // Verify at 5 seconds in the future
    const futureTime = Date.now() + 5000;
    const verifyRes = shortTtlSigner.verifyToken(token, futureTime);

    assert.strictEqual(verifyRes.isOk, false);
    if (!verifyRes.isOk) {
      assert.strictEqual(verifyRes.error.error_code, 'ERR_AUTH_TOKEN_EXPIRED');
    }
  });

  it('should produce canonical signatures invariant to role order in inputs', () => {
    const token1 = signer.createToken({
      subjectId: TEST_SUBJECT_ID,
      workspaceId: TEST_WORKSPACE_ID,
      roles: ['OPERATOR', 'ANALYST', 'AUDITOR'],
      permissionMask: 1,
    });

    const sig2 = signer.computeSignature({
      subject_id: token1.subject_id,
      subject_type: token1.subject_type,
      workspace_id: token1.workspace_id,
      roles: ['AUDITOR', 'OPERATOR', 'ANALYST'], // Different array order
      permission_mask: token1.permission_mask,
      issued_at: token1.issued_at,
      expires_at: token1.expires_at,
    });

    assert.strictEqual(token1.signature, sig2);
  });
});
