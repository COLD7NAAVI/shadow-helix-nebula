/**
 * Shadow : Helix Nebula (SHN) — Secrets Vault Lifecycle Integration Tests
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
import { PermissionBit } from '../../dist/index.js';

describe('Secrets Vault Envelope Encryption & Secret Lifecycle (Integration)', () => {
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

  it('should store secret with AES-256-GCM envelope encryption and retrieve decrypted material', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const { userId } = await createTestUserWithCredentials(services, orgId, 'creator@shn.io', 'Pass12345!', ['WORKSPACE_ADMIN'], workspaceId);

    const secretPlaintext = 'super-secret-target-api-key-998877';

    // 1. Create secret in vault
    const createRes = await services.secretsVault.createSecret({
      organization_id: orgId,
      workspace_id: workspaceId,
      name: 'PROD_SCANNER_API_KEY',
      description: 'Production target scanner API credentials',
      secret_type: 'API_KEY',
      plaintext: secretPlaintext,
      created_by: userId,
    });

    assert.strictEqual(createRes.isOk, true);
    if (!createRes.isOk) return;

    const meta = createRes.value;
    assert.strictEqual(meta.name, 'PROD_SCANNER_API_KEY');
    assert.strictEqual(meta.current_version, 1);
    assert.strictEqual(meta.status, 'ACTIVE');

    // Verify database row in secrets.versions stores ciphertext and wrapped DEK
    const versionRecord = await services.secretsVersionRepo.findActiveVersion(meta.id);
    assert.ok(versionRecord !== null);
    assert.strictEqual(versionRecord?.version, 1);
    assert.strictEqual(versionRecord?.status, 'ACTIVE');
    assert.strictEqual(versionRecord?.algorithm, 'AES-256-GCM');
    assert.notStrictEqual(versionRecord?.ciphertext.toString('utf8'), secretPlaintext);

    // 2. Retrieve decrypted secret material
    const getRes = await services.secretsVault.getSecret(meta.id, workspaceId);
    assert.strictEqual(getRes.isOk, true);
    if (!getRes.isOk) return;

    assert.strictEqual(getRes.value.plaintext.toString('utf8'), secretPlaintext);
    assert.strictEqual(getRes.value.version, 1);

    // 3. Test zeroize callback
    getRes.value.zeroize();
    assert.strictEqual(getRes.value.plaintext.toString('hex'), '00'.repeat(secretPlaintext.length));
  });

  it('should retrieve secret metadata without loading or exposing secret ciphertext', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const { userId } = await createTestUserWithCredentials(services, orgId, 'analyst@shn.io', 'Pass12345!', ['ANALYST'], workspaceId);

    const createRes = await services.secretsVault.createSecret({
      organization_id: orgId,
      workspace_id: workspaceId,
      name: 'SSH_TARGET_KEY',
      description: 'Bastion host SSH credential',
      secret_type: 'SSH_KEY',
      plaintext: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB...',
      created_by: userId,
    });
    assert.strictEqual(createRes.isOk, true);
    if (!createRes.isOk) return;

    const metaRes = await services.secretsVault.getSecretMetadata(createRes.value.id, workspaceId);
    assert.strictEqual(metaRes.isOk, true);
    if (!metaRes.isOk) return;

    assert.strictEqual(metaRes.value.name, 'SSH_TARGET_KEY');
    assert.strictEqual(metaRes.value.current_version, 1);
    // Ciphertext and DEK are not present in metadata
    assert.strictEqual((metaRes.value as any).ciphertext, undefined);
  });

  it('should rotate secret to version 2, superseding version 1 and maintaining audit trail', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const { userId } = await createTestUserWithCredentials(services, orgId, 'admin@shn.io', 'Pass12345!', ['WORKSPACE_ADMIN'], workspaceId);

    const secretV1 = 'initial-secret-material-version-1';
    const secretV2 = 'rotated-secret-material-version-2';

    const createRes = await services.secretsVault.createSecret({
      organization_id: orgId,
      workspace_id: workspaceId,
      name: 'DATABASE_PASSWORD',
      plaintext: secretV1,
      created_by: userId,
    });
    assert.strictEqual(createRes.isOk, true);
    if (!createRes.isOk) return;

    const secretId = createRes.value.id;

    // Rotate secret
    const rotateRes = await services.secretsVault.rotateSecret({
      secret_id: secretId,
      workspace_id: workspaceId,
      new_plaintext: secretV2,
      rotated_by: userId,
    });
    assert.strictEqual(rotateRes.isOk, true);
    if (!rotateRes.isOk) return;

    assert.strictEqual(rotateRes.value.current_version, 2);

    // Active version should now be Version 2 with new material
    const getRes = await services.secretsVault.getSecret(secretId, workspaceId);
    assert.strictEqual(getRes.isOk, true);
    if (!getRes.isOk) return;

    assert.strictEqual(getRes.value.version, 2);
    assert.strictEqual(getRes.value.plaintext.toString('utf8'), secretV2);

    // Prior version 1 is SUPERSEDED in DB
    const v1Record = await services.secretsVersionRepo.findByVersion(secretId, 1);
    assert.strictEqual(v1Record?.status, 'SUPERSEDED');
  });

  it('should revoke secret, mark all versions REVOKED, and deny subsequent retrieval', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const { userId } = await createTestUserWithCredentials(services, orgId, 'revoker@shn.io', 'Pass12345!', ['ORG_ADMIN'], workspaceId);

    const createRes = await services.secretsVault.createSecret({
      organization_id: orgId,
      workspace_id: workspaceId,
      name: 'REVOKED_API_TOKEN',
      plaintext: 'token-to-be-revoked-immediately',
      created_by: userId,
    });
    assert.strictEqual(createRes.isOk, true);
    if (!createRes.isOk) return;

    const secretId = createRes.value.id;

    // Revoke secret
    const revokeRes = await services.secretsVault.revokeSecret({
      secret_id: secretId,
      workspace_id: workspaceId,
      reason: 'Key compromised in incident INC-2026-001',
      revoked_by: userId,
    });
    assert.strictEqual(revokeRes.isOk, true);

    // Subsequent retrieval attempts fail with 410 ERR_VAULT_SECRET_REVOKED
    const getRes = await services.secretsVault.getSecret(secretId, workspaceId);
    assert.strictEqual(getRes.isOk, false);
    if (!getRes.isOk) {
      assert.strictEqual(getRes.error.error_code, 'ERR_VAULT_SECRET_REVOKED');
      assert.strictEqual(getRes.error.status, 410);
    }
  });

  it('should enforce security context permission checks on vault operations', async () => {
    const { orgId, workspaceId } = await createTestOrgAndWorkspace(services);
    const { userId } = await createTestUserWithCredentials(services, orgId, 'observer@shn.io', 'Pass12345!', ['OBSERVER'], workspaceId);

    // Create secret as system
    const createRes = await services.secretsVault.createSecret({
      organization_id: orgId,
      workspace_id: workspaceId,
      name: 'RESTRICTED_SECRET',
      plaintext: 'privileged-data',
      created_by: userId,
    });
    assert.strictEqual(createRes.isOk, true);
    if (!createRes.isOk) return;

    // Create OBSERVER security context (has only SCOPE_READ / WORKFLOW_READ, lacking SECRETS_READ_MATERIAL)
    const observerToken = services.signer.createToken({
      subjectId: userId,
      workspaceId,
      roles: ['OBSERVER'],
      permissionMask: PermissionBit.SCOPE_READ | PermissionBit.WORKFLOW_READ,
    });

    const getRes = await services.secretsVault.getSecret(createRes.value.id, workspaceId, observerToken);
    assert.strictEqual(getRes.isOk, false);
    if (!getRes.isOk) {
      assert.strictEqual(getRes.error.error_code, 'ERR_AUTH_FORBIDDEN');
      assert.strictEqual(getRes.error.status, 403);
    }
  });
});
