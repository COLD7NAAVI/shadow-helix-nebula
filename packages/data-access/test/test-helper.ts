/**
 * Shadow : Helix Nebula (SHN) — Test Helper & Database Fixtures
 */

import {
  generateUUIDv7,
  createOrganizationId,
  createWorkspaceId,
  createEventId,
  createCorrelationId,
  createCausationId,
  type OrganizationId,
  type WorkspaceId,
  type EventId,
  type CorrelationId,
  type CausationId,
} from '@shn/shared-kernel';
import {
  createDatabasePool,
  type DatabasePool,
  type DatabaseConfig,
} from '../dist/index.js';

export function getTestDatabaseConfig(dbName: string = 'shn_test'): DatabaseConfig {
  return {
    host: process.env.SHN_TEST_DB_HOST || '127.0.0.1',
    port: parseInt(process.env.SHN_TEST_DB_PORT || '54329', 10),
    database: process.env.SHN_TEST_DB_NAME || dbName,
    user: process.env.SHN_TEST_DB_USER || 'postgres',
    password: process.env.SHN_TEST_DB_PASSWORD || undefined,
    ssl: false,
    maxConnections: 10,
    minConnections: 1,
    idleTimeoutMs: 5000,
    connectionTimeoutMs: 5000,
  };
}

export async function ensureDatabase(dbName: string): Promise<void> {
  const rootPool = createDatabasePool(getTestDatabaseConfig('postgres'));
  try {
    const res = await rootPool.query(
      `SELECT 1 FROM pg_database WHERE datname = $1;`,
      [dbName]
    );
    if (res.rows.length === 0) {
      await rootPool.query(`CREATE DATABASE ${dbName};`);
    }
  } finally {
    await rootPool.end();
  }
}

export function createTestPool(dbName: string = 'shn_test'): DatabasePool {
  return createDatabasePool(getTestDatabaseConfig(dbName));
}

export async function resetDatabase(pool: DatabasePool): Promise<void> {
  await pool.query('DROP SCHEMA IF EXISTS secrets CASCADE;');
  await pool.query('DROP SCHEMA IF EXISTS events CASCADE;');
  await pool.query('DROP SCHEMA IF EXISTS audit CASCADE;');
  await pool.query('DROP SCHEMA IF EXISTS workspace CASCADE;');
  await pool.query('DROP SCHEMA IF EXISTS iam CASCADE;');
  await pool.query('DROP TABLE IF EXISTS public.schema_migrations CASCADE;');
}

export function validOrgId(): OrganizationId {
  const result = createOrganizationId(generateUUIDv7());
  if (result.isErr) throw new Error(`Failed to create valid OrganizationId: ${result.error}`);
  return result.value;
}

export function validWorkspaceId(): WorkspaceId {
  const result = createWorkspaceId(generateUUIDv7());
  if (result.isErr) throw new Error(`Failed to create valid WorkspaceId: ${result.error}`);
  return result.value;
}

export function validEventId(): EventId {
  const result = createEventId(generateUUIDv7());
  if (result.isErr) throw new Error(`Failed to create valid EventId: ${result.error}`);
  return result.value;
}

export function validCorrelationId(): CorrelationId {
  const result = createCorrelationId(generateUUIDv7());
  if (result.isErr) throw new Error(`Failed to create valid CorrelationId: ${result.error}`);
  return result.value;
}

export function validCausationId(): CausationId {
  const result = createCausationId(generateUUIDv7());
  if (result.isErr) throw new Error(`Failed to create valid CausationId: ${result.error}`);
  return result.value;
}
