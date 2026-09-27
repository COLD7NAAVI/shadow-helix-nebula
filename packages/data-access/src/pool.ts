/**
 * Shadow : Helix Nebula (SHN) — Database Connection Pool & Health Substrate
 *
 * Implements connection pooling, query execution, and readiness/liveness health probes.
 */

import pg from 'pg';
import {
  type Result,
  ok,
  err,
  nowIso,
  type IsoTimestamp,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
  type ProblemDetails,
} from '@shn/error-catalog';
import type { DatabaseConfig } from './config.js';

const { Pool } = pg;

export interface QueryResult<R = Record<string, unknown>> {
  readonly rows: R[];
  readonly rowCount: number | null;
  readonly command: string;
}

export interface DatabaseClient {
  query<R = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ): Promise<QueryResult<R>>;
  release(): void;
}

export interface DatabasePool {
  query<R = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ): Promise<QueryResult<R>>;
  connect(): Promise<DatabaseClient>;
  end(): Promise<void>;
  readonly totalCount: number;
  readonly idleCount: number;
  readonly waitingCount: number;
}

export interface DatabaseHealth {
  readonly status: 'UP' | 'DOWN';
  readonly version: string;
  readonly latencyMs: number;
  readonly checkedAt: IsoTimestamp;
  readonly totalConnections: number;
  readonly idleConnections: number;
  readonly waitingClients: number;
}

class PgPoolWrapper implements DatabasePool {
  private readonly innerPool: pg.Pool;
  private isEnded: boolean = false;

  constructor(config: DatabaseConfig) {
    this.innerPool = new Pool({
      host: config.host,
      port: config.port,
      database: config.database,
      user: config.user,
      password: config.password,
      ssl: config.ssl,
      max: config.maxConnections,
      min: config.minConnections,
      idleTimeoutMillis: config.idleTimeoutMs,
      connectionTimeoutMillis: config.connectionTimeoutMs,
    });
  }

  get totalCount(): number {
    return this.innerPool.totalCount;
  }

  get idleCount(): number {
    return this.innerPool.idleCount;
  }

  get waitingCount(): number {
    return this.innerPool.waitingCount;
  }

  async query<R = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ): Promise<QueryResult<R>> {
    const result = await this.innerPool.query<pg.QueryResultRow>(
      sql,
      params ? [...params] : undefined
    );
    return {
      rows: result.rows as R[],
      rowCount: result.rowCount,
      command: result.command,
    };
  }

  async connect(): Promise<DatabaseClient> {
    const client = await this.innerPool.connect();
    let released = false;

    return {
      query: async <R = Record<string, unknown>>(
        sql: string,
        params?: readonly unknown[]
      ): Promise<QueryResult<R>> => {
        const result = await client.query<pg.QueryResultRow>(
          sql,
          params ? [...params] : undefined
        );
        return {
          rows: result.rows as R[],
          rowCount: result.rowCount,
          command: result.command,
        };
      },
      release: () => {
        if (!released) {
          released = true;
          client.release();
        }
      },
    };
  }

  async end(): Promise<void> {
    if (this.isEnded) {
      return;
    }
    this.isEnded = true;
    await this.innerPool.end();
  }
}

export function createDatabasePool(config: DatabaseConfig): DatabasePool {
  return new PgPoolWrapper(config);
}

export async function checkDatabaseHealth(
  pool: DatabasePool,
  timeoutMs: number = 3000
): Promise<Result<DatabaseHealth, ProblemDetails>> {
  const start = Date.now();

  try {
    const queryPromise = pool.query<{ healthy: number; version: string }>(
      'SELECT 1 AS healthy, current_setting($1) AS version;',
      ['server_version']
    );

    let timer: NodeJS.Timeout | undefined;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(new Error(`Database health check timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    });

    const result = await Promise.race([queryPromise, timeoutPromise]).finally(() => {
      if (timer) clearTimeout(timer);
    });

    const latencyMs = Date.now() - start;
    const row = result.rows[0];

    return ok({
      status: 'UP',
      version: row?.version ?? 'unknown',
      latencyMs,
      checkedAt: nowIso(),
      totalConnections: pool.totalCount,
      idleConnections: pool.idleCount,
      waitingClients: pool.waitingCount,
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : 'Unknown database error';
    return err(
      createProblemDetails({
        errorCode: ErrorCode.STORAGE_NOT_FOUND,
        detail: `Database health check failed: ${detail}`,
        instance: '/health/database',
        correlationId: 'system.health.probe',
        customStatus: 503,
      })
    );
  }
}

export async function closeDatabasePool(pool: DatabasePool): Promise<void> {
  await pool.end();
}
