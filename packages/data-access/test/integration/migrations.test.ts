import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  runMigrations,
  getAppliedMigrations,
  getMigrationStatus,
  closeDatabasePool,
  type DatabasePool,
} from '../../dist/index.js';
import { createTestPool, resetDatabase } from '../test-helper.ts';

describe('Deterministic Migration Engine (Integration)', () => {
  let pool: DatabasePool;

  before(async () => {
    pool = createTestPool('shn_test_migrations');
    await resetDatabase(pool);
  });

  after(async () => {
    await closeDatabasePool(pool);
  });

  it('should run migrations cleanly from empty database', async () => {
    const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
    const report = await runMigrations(pool, migrationsDir);

    assert.ok(report.applied.length >= 1);
    assert.equal(report.applied[0]!.version, '001');
    assert.equal(report.alreadyApplied.length, 0);

    // Verify bounded context schemas were created
    const schemaResult = await pool.query<{ schema_name: string }>(
      `SELECT schema_name FROM information_schema.schemata
       WHERE schema_name IN ('iam', 'workspace', 'audit')
       ORDER BY schema_name ASC;`
    );
    const schemas = schemaResult.rows.map(r => r.schema_name);
    assert.deepEqual(schemas, ['audit', 'iam', 'workspace']);

    // Verify domain tables exist
    const tablesResult = await pool.query<{ table_schema: string; table_name: string }>(
      `SELECT table_schema, table_name FROM information_schema.tables
       WHERE table_schema IN ('iam', 'workspace', 'audit')
       ORDER BY table_schema, table_name;`
    );
    const tableKeys = tablesResult.rows.map(r => `${r.table_schema}.${r.table_name}`);
    assert.ok(tableKeys.includes('iam.organizations'));
    assert.ok(tableKeys.includes('iam.users'));
    assert.ok(tableKeys.includes('workspace.workspaces'));
    assert.ok(tableKeys.includes('audit.events'));
  });

  it('should be deterministic and idempotent on subsequent runs', async () => {
    const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
    const report = await runMigrations(pool, migrationsDir);

    assert.equal(report.applied.length, 0, 'No pending migrations should be applied');
    assert.ok(report.alreadyApplied.length >= 1, 'Previous migrations should be detected as applied');
    assert.equal(report.alreadyApplied[0]!.version, '001');

    const appliedInDb = await getAppliedMigrations(pool);
    assert.equal(appliedInDb.length, report.alreadyApplied.length);
  });

  it('should provide accurate read-only migration status reports', async () => {
    const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
    const status = await getMigrationStatus(pool, migrationsDir);

    assert.ok(status.totalAvailable >= 1);
    assert.equal(status.appliedCount, status.totalAvailable);
    assert.equal(status.pendingCount, 0);
    assert.equal(status.records[0]?.status, 'APPLIED');
  });

  it('should safely serialize concurrent migration invocations via advisory locks', async () => {
    const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');

    // Run 5 simultaneous migration attempts in parallel
    const results = await Promise.all([
      runMigrations(pool, migrationsDir),
      runMigrations(pool, migrationsDir),
      runMigrations(pool, migrationsDir),
      runMigrations(pool, migrationsDir),
      runMigrations(pool, migrationsDir),
    ]);

    // All should succeed without race conditions or unique constraint collisions
    for (const res of results) {
      assert.equal(res.applied.length, 0);
      assert.ok(res.alreadyApplied.length >= 1);
    }
  });

  it('should detect and reject tampered historical migration checksums', async () => {
    // Create temporary migration directory with tampered migration 001
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shn-tamper-test-'));
    try {
      const tamperedFile = path.join(tmpDir, '001_initial_schema.sql');
      fs.writeFileSync(tamperedFile, '-- Tampered SQL content modifying historical migration\n', 'utf8');

      await assert.rejects(
        async () => {
          await runMigrations(pool, tmpDir);
        },
        (error: Error) => {
          return error.message.includes('Checksum mismatch for migration 001_initial_schema');
        }
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
