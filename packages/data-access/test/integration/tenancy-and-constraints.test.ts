import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  generateUUIDv7,
} from '@shn/shared-kernel';
import {
  runMigrations,
  OrganizationRepository,
  WorkspaceRepository,
  UserRepository,
  closeDatabasePool,
  type DatabasePool,
} from '../../dist/index.js';
import {
  createTestPool,
  resetDatabase,
  validOrgId,
  validWorkspaceId,
} from '../test-helper.ts';

describe('Tenancy Isolation & Relational Constraints (Integration)', () => {
  let pool: DatabasePool;
  let orgRepo: OrganizationRepository;
  let workspaceRepo: WorkspaceRepository;
  let userRepo: UserRepository;

  before(async () => {
    pool = createTestPool('shn_test_tenancy');
    await resetDatabase(pool);
    const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
    await runMigrations(pool, migrationsDir);

    orgRepo = new OrganizationRepository(pool);
    workspaceRepo = new WorkspaceRepository(pool);
    userRepo = new UserRepository(pool);
  });

  after(async () => {
    await closeDatabasePool(pool);
  });

  it('should enforce organization slug uniqueness', async () => {
    const orgId1 = validOrgId();
    const org1 = await orgRepo.create({
      id: orgId1,
      name: 'Cyber Corp',
      slug: 'cyber-corp',
    });

    assert.equal(org1.id, orgId1);
    assert.equal(org1.name, 'Cyber Corp');
    assert.equal(org1.slug, 'cyber-corp');

    const orgId2 = validOrgId();
    await assert.rejects(
      async () => {
        await orgRepo.create({
          id: orgId2,
          name: 'Cyber Corp Duplicate',
          slug: 'cyber-corp', // duplicate slug
        });
      },
      (error: { code?: string }) => {
        return error.code === '23505';
      }
    );
  });

  it('should enforce workspace scoping and unique slug within organization', async () => {
    const orgId = validOrgId();
    await orgRepo.create({
      id: orgId,
      name: 'Alpha Defense',
      slug: 'alpha-defense',
    });

    const wsId1 = validWorkspaceId();
    const ws1 = await workspaceRepo.create({
      id: wsId1,
      organization_id: orgId,
      name: 'Red Team Ops',
      slug: 'red-team',
      environment: 'production',
    });

    assert.equal(ws1.id, wsId1);
    assert.equal(ws1.organization_id, orgId);
    assert.equal(ws1.slug, 'red-team');

    // Duplicate slug in SAME organization must fail
    const wsId2 = validWorkspaceId();
    await assert.rejects(
      async () => {
        await workspaceRepo.create({
          id: wsId2,
          organization_id: orgId,
          name: 'Another Red Team',
          slug: 'red-team',
        });
      },
      (error: { code?: string }) => error.code === '23505'
    );

    // SAME slug in DIFFERENT organization must SUCCEED (tenant isolation)
    const orgId2 = validOrgId();
    await orgRepo.create({
      id: orgId2,
      name: 'Beta Security',
      slug: 'beta-security',
    });

    const wsId3 = validWorkspaceId();
    const ws3 = await workspaceRepo.create({
      id: wsId3,
      organization_id: orgId2,
      name: 'Beta Red Team',
      slug: 'red-team', // same slug as in orgId
    });
    assert.equal(ws3.id, wsId3);
    assert.equal(ws3.organization_id, orgId2);
  });

  it('should enforce strict tenant-scoped workspace queries', async () => {
    const orgIdA = validOrgId();
    const orgIdB = validOrgId();

    await orgRepo.create({ id: orgIdA, name: 'Tenant A', slug: 'tenant-a' });
    await orgRepo.create({ id: orgIdB, name: 'Tenant B', slug: 'tenant-b' });

    const wsIdA = validWorkspaceId();
    await workspaceRepo.create({
      id: wsIdA,
      organization_id: orgIdA,
      name: 'Workspace A',
      slug: 'ws-a',
    });

    // Querying with matching org succeeds
    const found = await workspaceRepo.findByIdAndOrganization(wsIdA, orgIdA);
    assert.ok(found !== null);
    assert.equal(found.id, wsIdA);

    // Querying with WRONG org returns null (fail-closed tenant isolation)
    const crossTenant = await workspaceRepo.findByIdAndOrganization(wsIdA, orgIdB);
    assert.equal(crossTenant, null);
  });

  it('should enforce user scoping to organization and unique email within organization', async () => {
    const orgId = validOrgId();
    await orgRepo.create({
      id: orgId,
      name: 'Delta Security',
      slug: 'delta-security',
    });

    const userId1 = generateUUIDv7();
    const user1 = await userRepo.create({
      id: userId1,
      organization_id: orgId,
      email: 'analyst@delta.com',
      display_name: 'Lead Analyst',
    });

    assert.equal(user1.id, userId1);
    assert.equal(user1.email, 'analyst@delta.com');

    // Duplicate email in same org fails
    const userId2 = generateUUIDv7();
    await assert.rejects(
      async () => {
        await userRepo.create({
          id: userId2,
          organization_id: orgId,
          email: 'analyst@delta.com',
          display_name: 'Duplicate Analyst',
        });
      },
      (error: { code?: string }) => error.code === '23505'
    );
  });

  it('should enforce foreign key restrict on parent organization deletion', async () => {
    const orgId = validOrgId();
    await orgRepo.create({
      id: orgId,
      name: 'Protected Org',
      slug: 'protected-org',
    });

    const wsId = validWorkspaceId();
    await workspaceRepo.create({
      id: wsId,
      organization_id: orgId,
      name: 'Protected Workspace',
      slug: 'protected-ws',
    });

    // Attempting to delete organization must fail due to ON DELETE RESTRICT
    await assert.rejects(
      async () => {
        await pool.query('DELETE FROM iam.organizations WHERE id = $1;', [orgId]);
      },
      (error: { code?: string }) => {
        // PostgreSQL foreign key violation code 23503
        return error.code === '23503';
      }
    );
  });
});
