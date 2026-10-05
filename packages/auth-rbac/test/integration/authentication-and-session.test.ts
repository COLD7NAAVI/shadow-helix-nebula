/**
 * Shadow : Helix Nebula (SHN) — Authentication & Session Lifecycle Integration Tests
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  createAuthTestPool,
  setupAuthTestDatabase,
  cleanAuthAndSecretsTables,
  createTestServices,
  createTestOrgAndWorkspace,
  createTestUserWithCredentials,
  type TestServices,
} from './auth-test-helper.ts';
import type { DatabasePool } from '@shn/data-access';
import { hashToken } from '../../dist/index.js';

describe('Authentication, Account Governance & Session Lifecycle (Integration)', () => {
  let pool: DatabasePool;
  let services: TestServices;

  before(async () => {
    pool = createAuthTestPool();
    await setupAuthTestDatabase(pool);
    services = createTestServices(pool);
  });

  after(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    await cleanAuthAndSecretsTables(pool);
  });

  it('should authenticate valid user credentials, issue session and HMAC-signed security context', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const email = 'alice.operator@shadow-helix.io';
    const password = 'CorrectHorseBatteryStaple!2026';
    const { userId } = await createTestUserWithCredentials(services, orgId, email, password, ['OPERATOR'], workspaceId);

    const authRes = await services.authService.authenticateSession(orgId, email, password, workspaceId);
    assert.strictEqual(authRes.isOk, true);
    if (!authRes.isOk) return;

    const result = authRes.value;
    assert.strictEqual(result.user_id, userId);
    assert.strictEqual(result.organization_id, orgId);
    assert.strictEqual(result.workspace_id, workspaceId);
    assert.ok(result.bearer_token.startsWith('shn_sec_'));
    assert.ok(result.refresh_token.startsWith('shn_ref_'));

    // Verify session record in DB stores SHA-256 digest, NEVER raw bearer token
    const dbSession = await services.sessionRepo.findByTokenHash(hashToken(result.bearer_token));
    assert.ok(dbSession !== null);
    assert.strictEqual(dbSession?.token_hash, hashToken(result.bearer_token));
    assert.strictEqual(dbSession?.user_id, userId);
    assert.strictEqual(dbSession?.status, 'ACTIVE');

    // Verify SecurityContextToken is signed and claims match
    const secToken = result.security_context_token;
    assert.strictEqual(secToken.subject_id, userId);
    assert.strictEqual(secToken.workspace_id, workspaceId);
    assert.deepEqual(secToken.roles, ['OPERATOR']);
    assert.ok(secToken.permission_mask > 0);

    const verifyRes = services.signer.verifyToken(secToken);
    assert.strictEqual(verifyRes.isOk, true);
  });

  it('should track failed attempts and lock account for 15 minutes after 5 consecutive failures', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const email = 'victim.user@shadow-helix.io';
    const correctPassword = 'StrongPassword!2026';
    const wrongPassword = 'WrongPasswordValue!';
    await createTestUserWithCredentials(services, orgId, email, correctPassword, ['ANALYST'], workspaceId);

    // 4 failed attempts: should return 401 ERR_AUTH_CREDENTIALS_INVALID
    for (let i = 1; i <= 4; i++) {
      const res = await services.authService.authenticateSession(orgId, email, wrongPassword, workspaceId);
      assert.strictEqual(res.isOk, false);
      if (!res.isOk) {
        assert.strictEqual(res.error.error_code, 'ERR_AUTH_CREDENTIALS_INVALID');
        assert.strictEqual(res.error.status, 401);
      }
    }

    // 5th failed attempt: should trigger account lockout (423 ERR_AUTH_ACCOUNT_LOCKED)
    const fifthRes = await services.authService.authenticateSession(orgId, email, wrongPassword, workspaceId);
    assert.strictEqual(fifthRes.isOk, false);
    if (!fifthRes.isOk) {
      assert.strictEqual(fifthRes.error.error_code, 'ERR_AUTH_ACCOUNT_LOCKED');
      assert.strictEqual(fifthRes.error.status, 423);
    }

    // Subsequent login attempt even with CORRECT password is now blocked by lock
    const lockedRes = await services.authService.authenticateSession(orgId, email, correctPassword, workspaceId);
    assert.strictEqual(lockedRes.isOk, false);
    if (!lockedRes.isOk) {
      assert.strictEqual(lockedRes.error.error_code, 'ERR_AUTH_ACCOUNT_LOCKED');
      assert.strictEqual(lockedRes.error.status, 423);
    }
  });

  it('should reject authentication for disabled or suspended user accounts fail-closed', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const email = 'disabled.user@shadow-helix.io';
    const password = 'AnyPassword123!';
    await createTestUserWithCredentials(
      services,
      orgId,
      email,
      password,
      ['OBSERVER'],
      workspaceId,
      'DISABLED' // Account disabled status
    );

    const authRes = await services.authService.authenticateSession(orgId, email, password, workspaceId);
    assert.strictEqual(authRes.isOk, false);
    if (!authRes.isOk) {
      assert.strictEqual(authRes.error.error_code, 'ERR_AUTH_ACCOUNT_DISABLED');
      assert.strictEqual(authRes.error.status, 403);
    }
  });

  it('should refresh session with token rotation and update security context', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const email = 'rotator@shadow-helix.io';
    const password = 'PasswordForRotation!2026';
    await createTestUserWithCredentials(services, orgId, email, password, ['WORKSPACE_ADMIN'], workspaceId);

    const initialAuth = await services.authService.authenticateSession(orgId, email, password, workspaceId);
    assert.strictEqual(initialAuth.isOk, true);
    if (!initialAuth.isOk) return;

    const initialRefreshToken = initialAuth.value.refresh_token;
    const initialBearerToken = initialAuth.value.bearer_token;

    // Refresh session
    const refreshRes = await services.authService.refreshSession(initialRefreshToken);
    assert.strictEqual(refreshRes.isOk, true);
    if (!refreshRes.isOk) return;

    const refreshed = refreshRes.value;
    assert.notStrictEqual(refreshed.bearer_token, initialBearerToken);
    assert.notStrictEqual(refreshed.refresh_token, initialRefreshToken);

    // Old refresh token is no longer valid (token rotation)
    const replayRes = await services.authService.refreshSession(initialRefreshToken);
    assert.strictEqual(replayRes.isOk, false);
    if (!replayRes.isOk) {
      assert.strictEqual(replayRes.error.error_code, 'ERR_AUTH_SESSION_REVOKED');
    }
  });

  it('should revoke session immediately and deny further access', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const email = 'revokee@shadow-helix.io';
    const password = 'PasswordForRevoke!2026';
    await createTestUserWithCredentials(services, orgId, email, password, ['OPERATOR'], workspaceId);

    const authRes = await services.authService.authenticateSession(orgId, email, password, workspaceId);
    assert.strictEqual(authRes.isOk, true);
    if (!authRes.isOk) return;

    const sessionId = authRes.value.session.id;
    const refreshToken = authRes.value.refresh_token;

    // Revoke session
    const revokeRes = await services.authService.revokeToken(sessionId, 'Security team forced logout');
    assert.strictEqual(revokeRes.isOk, true);

    // Refresh should now fail
    const refreshRes = await services.authService.refreshSession(refreshToken);
    assert.strictEqual(refreshRes.isOk, false);
    if (!refreshRes.isOk) {
      assert.strictEqual(refreshRes.error.error_code, 'ERR_AUTH_SESSION_REVOKED');
    }
  });
});
