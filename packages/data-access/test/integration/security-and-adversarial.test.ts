import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
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

describe('Persistence Security & Adversarial Defense (Integration)', () => {
  let pool: DatabasePool;
  let orgRepo: OrganizationRepository;
  let workspaceRepo: WorkspaceRepository;
  let userRepo: UserRepository;

  before(async () => {
    pool = createTestPool('shn_test_security');
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

  it('should resist SQL injection in search parameters and string inputs', async () => {
    const orgId = validOrgId();
    await orgRepo.create({
      id: orgId,
      name: 'Legit Org',
      slug: 'legit-org',
    });

    // Malicious SQL injection payloads
    const injectionSlugs = [
      "legit-org' OR '1'='1",
      "'; DROP TABLE iam.organizations CASCADE; --",
      "legit-org' UNION SELECT id, name, slug, created_at, updated_at FROM iam.organizations --",
    ];

    for (const payload of injectionSlugs) {
      // Must query parameterized without error or unexpected results
      const found = await orgRepo.findBySlug(payload);
      assert.equal(found, null, `Injection payload "${payload}" must not return data or alter SQL query`);
    }

    // Verify table was not dropped
    const legit = await orgRepo.findBySlug('legit-org');
    assert.ok(legit !== null);
  });

  it('should reject malformed and non-UUID identifiers fail-closed', async () => {
    const malformedIds = [
      'not-a-uuid',
      '00000000-0000-0000-0000-00000000000g', // invalid hex
      '123e4567-e89b-12d3-a456-42661417400', // too short
      "'; DROP TABLE workspace.workspaces; --",
    ];

    for (const badId of malformedIds) {
      await assert.rejects(
        async () => {
          await orgRepo.findById(badId as unknown as ReturnType<typeof validOrgId>);
        },
        (error: Error) => error.message.includes('must be a valid UUID string')
      );

      await assert.rejects(
        async () => {
          await workspaceRepo.findById(badId as unknown as ReturnType<typeof validWorkspaceId>);
        },
        (error: Error) => error.message.includes('must be a valid UUID string')
      );

      await assert.rejects(
        async () => {
          await userRepo.findById(badId);
        },
        (error: Error) => error.message.includes('must be a valid UUID string')
      );
    }
  });

  it('should reject cross-tenant foreign key linkages', async () => {
    const nonExistentOrgId = validOrgId();
    const wsId = validWorkspaceId();

    // Linking a workspace to a non-existent organization must violate foreign key constraint (23503)
    await assert.rejects(
      async () => {
        await workspaceRepo.create({
          id: wsId,
          organization_id: nonExistentOrgId,
          name: 'Orphan Workspace',
          slug: 'orphan-ws',
        });
      },
      (error: { code?: string }) => error.code === '23503'
    );
  });

  it('should ensure connection checkout and release does not leak session transaction state', async () => {
    const client = await pool.connect();
    try {
      // Abort a query inside client
      try {
        await client.query('SELECT * FROM non_existent_table;');
      } catch {
        // Expected query error
      }
    } finally {
      client.release();
    }

    // Subsequent client acquired from pool should be completely clean and usable
    const nextClient = await pool.connect();
    try {
      const res = await nextClient.query<{ result: number }>('SELECT 100 AS result;');
      assert.equal(res.rows[0]?.result, 100);
    } finally {
      nextClient.release();
    }
  });
});
