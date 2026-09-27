/**
 * Shadow : Helix Nebula (SHN) — Transaction Boundary Abstraction
 *
 * Provides transactional boundary management ensuring atomic operations,
 * automated rollback on failure, deterministic client release, and explicit isolation levels
 * (DATA-INV-01, DATA-INV-07, MOD-INV-01).
 */

import type { DatabasePool, DatabaseClient } from './pool.js';

export type IsolationLevel = 'READ COMMITTED' | 'REPEATABLE READ' | 'SERIALIZABLE';

export interface TransactionOptions {
  readonly isolationLevel?: IsolationLevel;
  readonly readOnly?: boolean;
}

const VALID_ISOLATION_LEVELS = new Set<IsolationLevel>([
  'READ COMMITTED',
  'REPEATABLE READ',
  'SERIALIZABLE',
]);

let savepointCounter = 0;

/**
 * Checks whether target has a `connect` method (DatabasePool) or is an already checked-out DatabaseClient.
 */
function isDatabasePool(target: DatabasePool | DatabaseClient): target is DatabasePool {
  return typeof (target as DatabasePool).connect === 'function';
}

/**
 * Executes a callback within a managed database transaction.
 *
 * If passed a DatabasePool: Acquires a client, begins a transaction, sets isolation level,
 * commits on success, rolls back on error, and deterministically releases the client in finally.
 *
 * If passed an existing DatabaseClient: Utilizes a nested SAVEPOINT, rolling back only
 * the savepoint on error and releasing the savepoint on success.
 */
export async function runInTransaction<T>(
  poolOrClient: DatabasePool | DatabaseClient,
  fn: (client: DatabaseClient) => Promise<T>,
  options?: TransactionOptions
): Promise<T> {
  if (options?.isolationLevel && !VALID_ISOLATION_LEVELS.has(options.isolationLevel)) {
    throw new Error(
      `Invalid transaction isolation level: "${options.isolationLevel}". Supported: ${Array.from(VALID_ISOLATION_LEVELS).join(', ')}`
    );
  }

  // Nested transaction on an existing client: utilize SAVEPOINT
  if (!isDatabasePool(poolOrClient)) {
    const client = poolOrClient;
    const savepointName = `shn_sp_${Date.now()}_${++savepointCounter}`;
    await client.query(`SAVEPOINT ${savepointName};`);

    try {
      const result = await fn(client);
      await client.query(`RELEASE SAVEPOINT ${savepointName};`);
      return result;
    } catch (error) {
      try {
        await client.query(`ROLLBACK TO SAVEPOINT ${savepointName};`);
      } catch (rollbackErr) {
        console.error('[DB] Rollback to savepoint failed:', rollbackErr);
      }
      throw error;
    }
  }

  // Root transaction on a DatabasePool
  const client = await poolOrClient.connect();
  let inTransaction = false;

  try {
    let beginSql = 'BEGIN';
    if (options?.isolationLevel) {
      beginSql += ` ISOLATION LEVEL ${options.isolationLevel}`;
    }
    if (options?.readOnly) {
      beginSql += ' READ ONLY';
    }

    await client.query(beginSql);
    inTransaction = true;

    const result = await fn(client);

    await client.query('COMMIT');
    inTransaction = false;

    return result;
  } catch (error) {
    if (inTransaction) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackError) {
        console.error('[DB] Transaction rollback failed:', rollbackError);
      }
    }
    throw error;
  } finally {
    client.release();
  }
}
