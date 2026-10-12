/**
 * Shadow : Helix Nebula (SHN) — Asset & Finding Repositories Integration Tests
 *
 * Validates Migration 007 schema, AssetRepository, FindingRepository,
 * formal lifecycle state transitions, evidence hash enforcement (INV-05),
 * and multi-tenant hermeticity (INV-01, DATA-INV-08).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  generateUUIDv7,
  createOrganizationId,
  createWorkspaceId,
  createUserId,
  createAssetId,
  createFindingId,
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
} from '../../dist/index.js';
import { createTestPool, resetDatabase, ensureDatabase } from '../test-helper.ts';

describe('AssetRepository & FindingRepository Persistence (Integration)', () => {
  let pool: DatabasePool;
  let orgRepo: OrganizationRepository;
  let workspaceRepo: WorkspaceRepository;
  let userRepo: UserRepository;
  let assetRepo: AssetRepository;
  let findingRepo: FindingRepository;

  let testOrgId: OrganizationId;
  let testWorkspaceId: WorkspaceId;
  let foreignWorkspaceId: WorkspaceId;
  let testUserId: UserId;

  before(async () => {
    await ensureDatabase('shn_test_asset_finding_repo');
    pool = createTestPool('shn_test_asset_finding_repo');
    await resetDatabase(pool);
    const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
    await runMigrations(pool, migrationsDir);

    orgRepo = new OrganizationRepository(pool);
    workspaceRepo = new WorkspaceRepository(pool);
    userRepo = new UserRepository(pool);
    assetRepo = new AssetRepository(pool);
    findingRepo = new FindingRepository(pool);

    testOrgId = createOrganizationId(generateUUIDv7()).value;
    testWorkspaceId = createWorkspaceId(generateUUIDv7()).value;
    foreignWorkspaceId = createWorkspaceId(generateUUIDv7()).value;
    testUserId = createUserId(generateUUIDv7()).value;

    await orgRepo.create({
      id: testOrgId,
      name: 'Asset Finding Test Org',
      slug: `asset-org-${Date.now()}`,
    });

    await workspaceRepo.create({
      id: testWorkspaceId,
      organization_id: testOrgId,
      name: 'Primary Security Workspace',
      slug: `sec-wks-${Date.now()}`,
    });

    await workspaceRepo.create({
      id: foreignWorkspaceId,
      organization_id: testOrgId,
      name: 'Foreign Security Workspace',
      slug: `foreign-wks-${Date.now()}`,
    });

    await userRepo.create({
      id: testUserId,
      organization_id: testOrgId,
      email: 'security.analyst@example.internal',
      display_name: 'Security Analyst',
    });
  });

  after(async () => {
    await closeDatabasePool(pool);
  });

  describe('Asset Inventory Lifecycle', () => {
    it('should register an asset and retrieve by id and canonical value', async () => {
      const assetId = createAssetId(generateUUIDv7()).value;
      const asset = await assetRepo.createAsset({
        id: assetId,
        workspaceId: testWorkspaceId,
        organizationId: testOrgId,
        type: 'IPV4',
        canonicalValue: '192.168.1.50',
        name: 'Internal Gateway',
        criticality: 'HIGH',
        status: 'ACTIVE',
        tags: ['gateway', 'infrastructure'],
        metadata: { os: 'linux', subnet: '192.168.1.0/24' },
      });

      assert.strictEqual(asset.id, assetId);
      assert.strictEqual(asset.canonicalValue, '192.168.1.50');
      assert.strictEqual(asset.criticality, 'HIGH');
      assert.strictEqual(asset.status, 'ACTIVE');
      assert.deepStrictEqual(asset.tags, ['gateway', 'infrastructure']);

      // Fetch by ID
      const fetchedById = await assetRepo.findById(assetId, testWorkspaceId);
      assert.strictEqual(fetchedById !== null, true);
      assert.strictEqual(fetchedById?.name, 'Internal Gateway');

      // Fetch by canonical value
      const fetchedByCanonical = await assetRepo.findByCanonicalValue(
        testWorkspaceId,
        'IPV4',
        '192.168.1.50'
      );
      assert.strictEqual(fetchedByCanonical !== null, true);
      assert.strictEqual(fetchedByCanonical?.id, assetId);
    });

    it('should reject duplicate asset within same workspace (deduplication constraint)', async () => {
      await assert.rejects(
        async () => {
          await assetRepo.createAsset({
            workspaceId: testWorkspaceId,
            organizationId: testOrgId,
            type: 'IPV4',
            canonicalValue: '192.168.1.50', // Same canonical value
            name: 'Duplicate Gateway',
          });
        },
        /duplicate key value violates unique constraint/
      );
    });

    it('should allow same canonical value in a different workspace (tenant isolation)', async () => {
      const foreignAsset = await assetRepo.createAsset({
        workspaceId: foreignWorkspaceId,
        organizationId: testOrgId,
        type: 'IPV4',
        canonicalValue: '192.168.1.50', // Same IP, different workspace
        name: 'Foreign Gateway',
      });

      assert.strictEqual(foreignAsset.workspaceId, foreignWorkspaceId);
      assert.strictEqual(foreignAsset.canonicalValue, '192.168.1.50');
    });

    it('should update asset details and list assets with filters', async () => {
      const asset = await assetRepo.createAsset({
        workspaceId: testWorkspaceId,
        organizationId: testOrgId,
        type: 'FQDN',
        canonicalValue: 'api.corp.internal',
        name: 'API Server',
        criticality: 'CRITICAL',
      });

      const updated = await assetRepo.updateAsset(asset.id, testWorkspaceId, {
        name: 'Production API Gateway',
        tags: ['production', 'pci-dss'],
      });

      assert.strictEqual(updated?.name, 'Production API Gateway');
      assert.deepStrictEqual(updated?.tags, ['production', 'pci-dss']);

      const fqdnList = await assetRepo.listAssets(testWorkspaceId, { type: 'FQDN' });
      assert.strictEqual(fqdnList.length, 1);
      assert.strictEqual(fqdnList[0].canonicalValue, 'api.corp.internal');
    });
  });

  describe('Finding Lifecycle & State Transitions', () => {
    let targetAssetId: any;
    const testEvidenceSha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    before(async () => {
      const asset = await assetRepo.createAsset({
        workspaceId: testWorkspaceId,
        organizationId: testOrgId,
        type: 'URL',
        canonicalValue: 'https://api.corp.internal:443/v1',
        name: 'Vulnerable Endpoint',
        criticality: 'HIGH',
      });
      targetAssetId = asset.id;
    });

    it('should create a finding with raw evidence SHA-256 and initial DRAFT state', async () => {
      const findingId = createFindingId(generateUUIDv7()).value;
      const finding = await findingRepo.createFinding({
        id: findingId,
        workspaceId: testWorkspaceId,
        organizationId: testOrgId,
        assetId: targetAssetId,
        title: 'TLS 1.0 Weak Cipher Suite Enabled',
        description: 'Server supports deprecated TLS 1.0 protocol with 3DES ciphers.',
        category: 'CRYPTOGRAPHY',
        severity: 'MEDIUM',
        cve_id: 'CVE-2014-3566',
        cwe_id: 'CWE-326',
        cvssScore: 4.3,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        status: 'DRAFT',
        rawEvidenceSha256: testEvidenceSha,
        remediationGuidance: 'Disable TLS 1.0 and enable TLS 1.3 only.',
      });

      assert.strictEqual(finding.id, findingId);
      assert.strictEqual(finding.status, 'DRAFT');
      assert.strictEqual(finding.severity, 'MEDIUM');
      assert.strictEqual(finding.cvssScore, 4.3);
      assert.strictEqual(finding.rawEvidenceSha256, testEvidenceSha);
    });

    it('should transition finding status atomically and maintain audit history (MOD-INV-04)', async () => {
      const finding = await findingRepo.createFinding({
        workspaceId: testWorkspaceId,
        organizationId: testOrgId,
        assetId: targetAssetId,
        title: 'Open SSH Port 22',
        description: 'Port 22 is reachable from the public internet.',
        category: 'NETWORK_EXPOSURE',
        severity: 'LOW',
        rawEvidenceSha256: testEvidenceSha,
      });

      // 1. Transition DRAFT -> UNDER_REVIEW
      const reviewTransition = await findingRepo.transitionStatus({
        findingId: finding.id,
        workspaceId: testWorkspaceId,
        toStatus: 'UNDER_REVIEW',
        changedBy: testUserId,
        reason: 'Triaged by analyst for team review',
      });
      assert.strictEqual(reviewTransition?.status, 'UNDER_REVIEW');

      // 2. Transition UNDER_REVIEW -> CONFIRMED
      const confirmedTransition = await findingRepo.transitionStatus({
        findingId: finding.id,
        workspaceId: testWorkspaceId,
        toStatus: 'CONFIRMED',
        changedBy: testUserId,
        reason: 'Confirmed reachable in production penetration test',
      });
      assert.strictEqual(confirmedTransition?.status, 'CONFIRMED');

      // Verify audit transitions log
      const history = await findingRepo.listStatusTransitions(finding.id, testWorkspaceId);
      assert.strictEqual(history.length, 2);
      assert.strictEqual(history[0].fromStatus, 'DRAFT');
      assert.strictEqual(history[0].toStatus, 'UNDER_REVIEW');
      assert.strictEqual(history[0].changedBy, testUserId);
      assert.strictEqual(history[1].fromStatus, 'UNDER_REVIEW');
      assert.strictEqual(history[1].toStatus, 'CONFIRMED');
    });

    it('should enforce multi-tenant isolation: cannot view or transition finding across workspaces', async () => {
      const finding = await findingRepo.createFinding({
        workspaceId: testWorkspaceId,
        organizationId: testOrgId,
        assetId: targetAssetId,
        title: 'Isolated Vulnerability',
        description: 'Confidential vulnerability in test workspace.',
        category: 'APPLICATION_SECURITY',
        severity: 'HIGH',
        rawEvidenceSha256: testEvidenceSha,
      });

      // Query from foreign workspace
      const foreignLookup = await findingRepo.findById(finding.id, foreignWorkspaceId);
      assert.strictEqual(foreignLookup, null);

      // Attempt transition from foreign workspace
      const crossTransition = await findingRepo.transitionStatus({
        findingId: finding.id,
        workspaceId: foreignWorkspaceId, // Wrong workspace
        toStatus: 'CONFIRMED',
        changedBy: testUserId,
      });
      assert.strictEqual(crossTransition, null);
    });
  });
});
