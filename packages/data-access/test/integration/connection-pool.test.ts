import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkDatabaseHealth,
  closeDatabasePool,
  createDatabasePool,
} from '../../dist/index.js';
import { createTestPool, getTestDatabaseConfig } from '../test-helper.ts';

describe('PostgreSQL Connection Pool & Lifecycle (Integration)', () => {
  it('should connect, query, and report UP health with server version', async () => {
    const pool = createTestPool('shn_test_pool');
    try {
      const healthResult = await checkDatabaseHealth(pool);
      assert.equal(healthResult.isOk, true);
      if (healthResult.isOk) {
        const health = healthResult.value;
        assert.equal(health.status, 'UP');
        assert.ok(health.version.length > 0, 'PostgreSQL version must be non-empty');
        assert.ok(health.latencyMs >= 0, 'Latency must be non-negative');
        assert.ok(health.checkedAt.length > 0, 'CheckedAt timestamp must be present');
      }
    } finally {
      await closeDatabasePool(pool);
    }
  });

  it('should acquire client, execute query, and deterministically release client', async () => {
    const pool = createTestPool('shn_test_pool');
    try {
      const client = await pool.connect();
      const result = await client.query<{ num: number }>('SELECT 42 AS num;');
      assert.equal(result.rows[0]?.num, 42);
      client.release();

      // Double release should be safe and idempotent
      assert.doesNotThrow(() => client.release());
    } finally {
      await closeDatabasePool(pool);
    }
  });

  it('should report DOWN health without credential leakage when connecting to unavailable host', async () => {
    const badConfig = {
      ...getTestDatabaseConfig('shn_test_pool'),
      host: '127.0.0.1',
      port: 54399, // Unused port
      password: 'super_secret_test_password',
      connectionTimeoutMs: 500,
    };
    const deadPool = createDatabasePool(badConfig);

    try {
      const healthResult = await checkDatabaseHealth(deadPool, 800);
      assert.equal(healthResult.isErr, true);
      if (healthResult.isErr) {
        const problem = healthResult.error;
        assert.equal(problem.status, 503);
        // Guarantee password is never leaked into detail string
        assert.equal(JSON.stringify(problem).includes('super_secret_test_password'), false);
      }
    } finally {
      await closeDatabasePool(deadPool);
    }
  });

  it('should safely and idempotently close database pool', async () => {
    const pool = createTestPool('shn_test_pool');
    await closeDatabasePool(pool);
    // Repeated shutdown should not throw
    await assert.doesNotReject(async () => {
      await closeDatabasePool(pool);
    });
  });
});
