/**
 * Shadow : Helix Nebula (SHN) — Concurrency, Race Condition & Stress Tests
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

describe('Concurrency, Race Condition & Lockout Atomicity (Integration)', () => {
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

  it('should handle concurrent login authentications without race condition', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const email = 'concurrent.user@shn.io';
    const password = 'StrongPassword!2026';
    await createTestUserWithCredentials(services, orgId, email, password, ['OPERATOR'], workspaceId);

    // Launch 10 concurrent authentications
    const authPromises = Array.from({ length: 10 }, () =>
      services.authService.authenticateSession(orgId, email, password, workspaceId)
    );

    const results = await Promise.all(authPromises);
    for (const res of results) {
      assert.strictEqual(res.isOk, true);
      if (res.isOk) {
        assert.ok(res.value.bearer_token.startsWith('shn_sec_'));
      }
    }
  });

  it('should atomically increment failed attempts under concurrent brute-force race', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const email = 'victim.bruteforce@shn.io';
    const correctPassword = 'StrongPassword!2026';
    const wrongPassword = 'WrongPassword!';
    const { userId } = await createTestUserWithCredentials(services, orgId, email, correctPassword, ['OPERATOR'], workspaceId);

    // Launch 8 concurrent failed login attempts
    const failedPromises = Array.from({ length: 8 }, () =>
      services.authService.authenticateSession(orgId, email, wrongPassword, workspaceId)
    );

    await Promise.all(failedPromises);

    // Verify account is locked in database
    const creds = await services.credentialRepo.findByUserId(userId);
    assert.ok(creds !== null);
    assert.ok(creds.failed_attempts >= 5);
    assert.ok(creds.locked_until !== null);
    assert.ok(new Date(creds.locked_until).getTime() > Date.now());
  });

  it('should handle sequential secret rotations under high load cleanly', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const { userId } = await createTestUserWithCredentials(services, orgId, 'rotator-stress@shn.io', 'Pass12345!', ['WORKSPACE_ADMIN'], workspaceId);

    const createRes = await services.secretsVault.createSecret({
      organization_id: orgId,
      workspace_id: workspaceId,
      name: 'ROTATION_STRESS_SECRET',
      plaintext: 'version-1',
      created_by: userId,
    });
    assert.strictEqual(createRes.isOk, true);
    if (!createRes.isOk) return;

    const secretId = createRes.value.id;

    // Rotate 5 times sequentially
    for (let v = 2; v <= 6; v++) {
      const rotRes = await services.secretsVault.rotateSecret({
        secret_id: secretId,
        workspace_id: workspaceId,
        new_plaintext: `version-${v}`,
        rotated_by: userId,
      });
      assert.strictEqual(rotRes.isOk, true);
      if (rotRes.isOk) {
        assert.strictEqual(rotRes.value.current_version, v);
      }
    }

    const finalGet = await services.secretsVault.getSecret(secretId, workspaceId);
    assert.strictEqual(finalGet.isOk, true);
    if (finalGet.isOk) {
      assert.strictEqual(finalGet.value.version, 6);
      assert.strictEqual(finalGet.value.plaintext.toString('utf8'), 'version-6');
    }
  });
});
