/**
 * Shadow : Helix Nebula (SHN) — Adversarial Defense & Multi-Tenant Isolation Integration Tests
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

describe('Adversarial Defense, Multi-Tenant Hermeticity & Tamper Detection (Integration)', () => {
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

  it('should enforce strict multi-tenant workspace isolation for secrets', async () => {
    // Org has two distinct workspaces
    const { orgId, workspaceId: wsAlpha } = await createTestOrgAndWorkspace(services, 'org-multi', 'ws-alpha');
    const { workspaceId: wsBeta } = await createTestOrgAndWorkspace(services, 'org-multi-2', 'ws-beta');

    const { userId } = await createTestUserWithCredentials(services, orgId, 'alpha.operator@shn.io', 'Pass12345!', ['OPERATOR'], wsAlpha);

    // Create secret strictly in Workspace Alpha
    const createRes = await services.secretsVault.createSecret({
      organization_id: orgId,
      workspace_id: wsAlpha,
      name: 'ALPHA_TARGET_CREDENTIAL',
      plaintext: 'alpha-only-token-data',
      created_by: userId,
    });
    assert.strictEqual(createRes.isOk, true);
    if (!createRes.isOk) return;

    const secretId = createRes.value.id;

    // Cross-workspace query attempt using Workspace Beta identifier
    const breachAttempt = await services.secretsVault.getSecret(secretId, wsBeta);
    assert.strictEqual(breachAttempt.isOk, false);
    if (!breachAttempt.isOk) {
      assert.strictEqual(breachAttempt.error.error_code, 'ERR_VAULT_SECRET_NOT_FOUND');
      assert.strictEqual(breachAttempt.error.status, 404);
    }
  });

  it('should safely store and retrieve hostile SQL injection vectors in parameters', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const sqliPayload = "'; DROP TABLE iam.users; SELECT * FROM '1";
    const { userId } = await createTestUserWithCredentials(services, orgId, 'sqli-tester@shn.io', 'Pass12345!', ['OPERATOR'], workspaceId);

    const createRes = await services.secretsVault.createSecret({
      organization_id: orgId,
      workspace_id: workspaceId,
      name: 'SQLI_TEST_SECRET',
      description: sqliPayload,
      plaintext: sqliPayload,
      created_by: userId,
    });
    assert.strictEqual(createRes.isOk, true);
    if (!createRes.isOk) return;

    // Verify table was NOT dropped and secret was retrieved intact
    const getRes = await services.secretsVault.getSecret(createRes.value.id, workspaceId);
    assert.strictEqual(getRes.isOk, true);
    if (getRes.isOk) {
      assert.strictEqual(getRes.value.plaintext.toString('utf8'), sqliPayload);
    }
  });

  it('should fail-closed when database ciphertext is tampered at rest', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const { userId } = await createTestUserWithCredentials(services, orgId, 'tamper-victim@shn.io', 'Pass12345!', ['OPERATOR'], workspaceId);

    const createRes = await services.secretsVault.createSecret({
      organization_id: orgId,
      workspace_id: workspaceId,
      name: 'INTEGRITY_TEST_SECRET',
      plaintext: 'original-unmodified-material',
      created_by: userId,
    });
    assert.strictEqual(createRes.isOk, true);
    if (!createRes.isOk) return;

    // Direct database tampering simulation: corrupt the ciphertext BYTEA column
    await pool.query(
      `UPDATE secrets.versions
       SET ciphertext = set_byte(ciphertext, 0, get_byte(ciphertext, 0) # 255)
       WHERE secret_id = $1;`,
      [createRes.value.id]
    );

    const getRes = await services.secretsVault.getSecret(createRes.value.id, workspaceId);
    assert.strictEqual(getRes.isOk, false);
    if (!getRes.isOk) {
      assert.strictEqual(getRes.error.error_code, 'ERR_VAULT_DECRYPTION_FAILED');
      assert.strictEqual(getRes.error.status, 500);
    }
  });

  it('should fail-closed when auth tag is tampered in PostgreSQL', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const { userId } = await createTestUserWithCredentials(services, orgId, 'tag-tamper@shn.io', 'Pass12345!', ['OPERATOR'], workspaceId);

    const createRes = await services.secretsVault.createSecret({
      organization_id: orgId,
      workspace_id: workspaceId,
      name: 'AUTH_TAG_TEST_SECRET',
      plaintext: 'tag-protected-material',
      created_by: userId,
    });
    assert.strictEqual(createRes.isOk, true);
    if (!createRes.isOk) return;

    // Direct database tampering simulation: corrupt the auth_tag BYTEA column
    await pool.query(
      `UPDATE secrets.versions
       SET auth_tag = set_byte(auth_tag, 0, get_byte(auth_tag, 0) # 1)
       WHERE secret_id = $1;`,
      [createRes.value.id]
    );

    const getRes = await services.secretsVault.getSecret(createRes.value.id, workspaceId);
    assert.strictEqual(getRes.isOk, false);
    if (!getRes.isOk) {
      assert.strictEqual(getRes.error.error_code, 'ERR_VAULT_DECRYPTION_FAILED');
    }
  });
});
