import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  runMigrations,
  runInTransaction,
  closeDatabasePool,
  type DatabasePool,
} from '../../dist/index.js';
import {
  createTestPool,
  resetDatabase,
  validOrgId,
} from '../test-helper.ts';

describe('Transaction Boundary & Rollback Abstraction (Integration)', () => {
  let pool: DatabasePool;

  before(async () => {
    pool = createTestPool('shn_test_transactions');
    await resetDatabase(pool);
    const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
    await runMigrations(pool, migrationsDir);
  });

  after(async () => {
    await closeDatabasePool(pool);
  });

  it('should commit operations executed within runInTransaction', async () => {
    const orgId = validOrgId();

    await runInTransaction(pool, async client => {
      await client.query(
        `INSERT INTO iam.organizations (id, name, slug) VALUES ($1, $2, $3);`,
        [orgId, 'Committed Org', 'committed-org']
      );
    });

    const result = await pool.query<{ id: string }>(
      `SELECT id FROM iam.organizations WHERE id = $1;`,
      [orgId]
    );
    assert.equal(result.rows.length, 1);
    assert.equal(result.rows[0]?.id, orgId);
  });

  it('should roll back operations when an error is thrown inside runInTransaction', async () => {
    const orgId = validOrgId();

    await assert.rejects(
      async () => {
        await runInTransaction(pool, async client => {
          await client.query(
            `INSERT INTO iam.organizations (id, name, slug) VALUES ($1, $2, $3);`,
            [orgId, 'Rolled Back Org', 'rolled-back-org']
          );
          throw new Error('Simulated intentional transaction failure');
        });
      },
      (error: Error) => error.message === 'Simulated intentional transaction failure'
    );

    // Row should NOT exist in database due to rollback
    const result = await pool.query<{ id: string }>(
      `SELECT id FROM iam.organizations WHERE id = $1;`,
      [orgId]
    );
    assert.equal(result.rows.length, 0);
  });

  it('should support nested transactions via savepoints', async () => {
    const outerOrgId = validOrgId();
    const innerOrgId = validOrgId();

    await runInTransaction(pool, async client => {
      // Outer operation
      await client.query(
        `INSERT INTO iam.organizations (id, name, slug) VALUES ($1, $2, $3);`,
        [outerOrgId, 'Outer Org', 'outer-org']
      );

      // Inner nested transaction that fails and rolls back to savepoint
      try {
        await runInTransaction(client, async innerClient => {
          await innerClient.query(
            `INSERT INTO iam.organizations (id, name, slug) VALUES ($1, $2, $3);`,
            [innerOrgId, 'Inner Rolled Back Org', 'inner-rolled-back-org']
          );
          throw new Error('Inner failure');
        });
      } catch {
        // Handled inner error
      }
    });

    // Outer org committed
    const outerRes = await pool.query<{ id: string }>(
      `SELECT id FROM iam.organizations WHERE id = $1;`,
      [outerOrgId]
    );
    assert.equal(outerRes.rows.length, 1);

    // Inner org was rolled back by savepoint
    const innerRes = await pool.query<{ id: string }>(
      `SELECT id FROM iam.organizations WHERE id = $1;`,
      [innerOrgId]
    );
    assert.equal(innerRes.rows.length, 0);
  });

  it('should support explicit isolation levels (READ COMMITTED, REPEATABLE READ, SERIALIZABLE)', async () => {
    const levels = ['READ COMMITTED', 'REPEATABLE READ', 'SERIALIZABLE'] as const;

    for (const level of levels) {
      const orgId = validOrgId();
      await runInTransaction(
        pool,
        async client => {
          await client.query(
            `INSERT INTO iam.organizations (id, name, slug) VALUES ($1, $2, $3);`,
            [orgId, `Org ${level}`, `org-${level.toLowerCase().replace(/\s+/g, '-')}`]
          );
        },
        { isolationLevel: level }
      );

      const res = await pool.query<{ id: string }>(
        `SELECT id FROM iam.organizations WHERE id = $1;`,
        [orgId]
      );
      assert.equal(res.rows.length, 1);
    }
  });

  it('should reject invalid isolation levels fail-closed', async () => {
    await assert.rejects(
      async () => {
        await runInTransaction(
          pool,
          async () => {},
          { isolationLevel: 'UNCOMMITTED' as unknown as 'READ COMMITTED' }
        );
      },
      (error: Error) => error.message.includes('Invalid transaction isolation level')
    );
  });
});
