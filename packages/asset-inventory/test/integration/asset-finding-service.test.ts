/**
 * Shadow : Helix Nebula (SHN) — Asset & Finding Service Integration Tests
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  generateUUIDv7,
  createOrganizationId,
  createWorkspaceId,
  createUserId,
  type WorkspaceId,
  type OrganizationId,
  type UserId,
} from '@shn/shared-kernel';
import {
  runMigrations,
  closeDatabasePool,
  type DatabasePool,
  OrganizationRepository,
  WorkspaceRepository,
  UserRepository,
  AssetRepository,
  FindingRepository,
} from '@shn/data-access';
import {
  AssetInventoryService,
  FindingLifecycleService,
} from '../../dist/index.js';
import { createTestPool, resetDatabase, ensureDatabase } from '../../../data-access/test/test-helper.ts';

describe('AssetInventoryService & FindingLifecycleService (Integration)', () => {
  let pool: DatabasePool;
  let assetRepo: AssetRepository;
  let findingRepo: FindingRepository;
  let assetService: AssetInventoryService;
  let findingService: FindingLifecycleService;

  let testOrgId: OrganizationId;
  let testWorkspaceId: WorkspaceId;
  let foreignWorkspaceId: WorkspaceId;
  let testUserId: UserId;

  before(async () => {
    await ensureDatabase('shn_test_asset_inventory_pkg');
    pool = createTestPool('shn_test_asset_inventory_pkg');
    await resetDatabase(pool);
    const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
    await runMigrations(pool, migrationsDir);

    const orgRepo = new OrganizationRepository(pool);
    const workspaceRepo = new WorkspaceRepository(pool);
    const userRepo = new UserRepository(pool);

    assetRepo = new AssetRepository(pool);
    findingRepo = new FindingRepository(pool);

    assetService = new AssetInventoryService({ assetRepository: assetRepo });
    findingService = new FindingLifecycleService({
      findingRepository: findingRepo,
      assetRepository: assetRepo,
    });

    testOrgId = createOrganizationId(generateUUIDv7()).value;
    testWorkspaceId = createWorkspaceId(generateUUIDv7()).value;
    foreignWorkspaceId = createWorkspaceId(generateUUIDv7()).value;
    testUserId = createUserId(generateUUIDv7()).value;

    await orgRepo.create({
      id: testOrgId,
      name: 'Integration Org',
      slug: `int-org-${Date.now()}`,
    });

    await workspaceRepo.create({
      id: testWorkspaceId,
      organization_id: testOrgId,
      name: 'Primary Security Workspace',
      slug: `wks-prim-${Date.now()}`,
    });

    await workspaceRepo.create({
      id: foreignWorkspaceId,
      organization_id: testOrgId,
      name: 'Foreign Security Workspace',
      slug: `wks-for-${Date.now()}`,
    });

    await userRepo.create({
      id: testUserId,
      organization_id: testOrgId,
      email: 'analyst@sec.internal',
      display_name: 'Lead Analyst',
    });
  });

  after(async () => {
    await closeDatabasePool(pool);
  });

  it('should register asset and persist canonical format in PostgreSQL', async () => {
    const res = await assetService.registerAsset({
      workspaceId: testWorkspaceId,
      organizationId: testOrgId,
      rawTarget: 'https://APP.Internal:443/login',
      name: 'Auth Service',
      criticality: 'CRITICAL',
    });

    assert.strictEqual(res.isOk, true);
    if (res.isOk) {
      assert.strictEqual(res.value.type, 'URL');
      assert.strictEqual(res.value.canonicalValue, 'https://app.internal/login');
      assert.strictEqual(res.value.criticality, 'CRITICAL');
    }
  });

  it('should record finding with evidence SHA-256 and execute state transitions', async () => {
    // 1. Register asset
    const assetRes = await assetService.registerAsset({
      workspaceId: testWorkspaceId,
      organizationId: testOrgId,
      rawTarget: '192.168.10.5',
      type: 'IPV4',
    });
    assert.strictEqual(assetRes.isOk, true);
    if (!assetRes.isOk) return;
    const asset = assetRes.value;

    const sha256 = 'b'.repeat(64);

    // 2. Record finding
    const findingRes = await findingService.recordFinding({
      workspaceId: testWorkspaceId,
      organizationId: testOrgId,
      assetId: asset.id,
      title: 'Unencrypted Telnet Port 23',
      description: 'Cleartext protocol active on internal node.',
      category: 'NETWORK_EXPOSURE',
      severity: 'HIGH',
      cvssScore: 7.5,
      rawEvidenceSha256: sha256,
    });

    assert.strictEqual(findingRes.isOk, true);
    if (!findingRes.isOk) return;
    const finding = findingRes.value;
    assert.strictEqual(finding.status, 'DRAFT');
    assert.strictEqual(finding.rawEvidenceSha256, sha256);

    // 3. Transition DRAFT -> UNDER_REVIEW -> CONFIRMED
    const reviewRes = await findingService.transitionStatus({
      findingId: finding.id,
      workspaceId: testWorkspaceId,
      toStatus: 'UNDER_REVIEW',
      changedBy: testUserId,
      reason: 'Triaged by Tier 1 analyst',
    });
    assert.strictEqual(reviewRes.isOk, true);

    const confirmRes = await findingService.transitionStatus({
      findingId: finding.id,
      workspaceId: testWorkspaceId,
      toStatus: 'CONFIRMED',
      changedBy: testUserId,
      reason: 'Verified active listener on port 23',
    });
    assert.strictEqual(confirmRes.isOk, true);
    if (!confirmRes.isOk) return;
    assert.strictEqual(confirmRes.value.status, 'CONFIRMED');

    // 4. Verify audit history in database
    const historyRes = await findingService.getStatusHistory(finding.id, testWorkspaceId);
    assert.strictEqual(historyRes.isOk, true);
    if (!historyRes.isOk) return;
    assert.strictEqual(historyRes.value.length, 2);
  });

  it('should enforce multi-tenant isolation against cross-workspace operations', async () => {
    const assetRes = await assetService.registerAsset({
      workspaceId: testWorkspaceId,
      organizationId: testOrgId,
      rawTarget: '10.50.0.1',
    });
    assert.strictEqual(assetRes.isOk, true);
    if (!assetRes.isOk) return;
    const asset = assetRes.value;

    const findingRes = await findingService.recordFinding({
      workspaceId: testWorkspaceId,
      organizationId: testOrgId,
      assetId: asset.id,
      title: 'Confidential Finding',
      description: 'Internal secret issue',
      category: 'MISCONFIG',
      severity: 'LOW',
      rawEvidenceSha256: 'c'.repeat(64),
    });
    assert.strictEqual(findingRes.isOk, true);
    if (!findingRes.isOk) return;
    const finding = findingRes.value;

    // Query from foreign workspace
    const foreignLookup = await findingService.getFinding(finding.id, foreignWorkspaceId);
    assert.strictEqual(foreignLookup.isErr, true);
    if (foreignLookup.isErr) {
      assert.strictEqual(foreignLookup.error.status, 404);
    }

    // Transition from foreign workspace
    const foreignTrans = await findingService.transitionStatus({
      findingId: finding.id,
      workspaceId: foreignWorkspaceId,
      toStatus: 'UNDER_REVIEW',
      changedBy: testUserId,
    });
    assert.strictEqual(foreignTrans.isErr, true);
    if (foreignTrans.isErr) {
      assert.strictEqual(foreignTrans.error.status, 404);
    }
  });
});
