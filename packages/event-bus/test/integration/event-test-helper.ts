/**
 * Shadow : Helix Nebula (SHN) — Event Bus Integration Test Helper
 */

import path from 'node:path';
import {
  generateUUIDv7,
  nowIso,
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
  type CanonicalEventEnvelope,
} from '@shn/shared-kernel';
import {
  createDatabasePool,
  closeDatabasePool,
  runMigrations,
  getDefaultMigrationsDir,
  OrganizationRepository,
  WorkspaceRepository,
  type OrganizationRecord,
  type WorkspaceRecord,
  type DatabasePool,
  type DatabaseConfig,
} from '@shn/data-access';

export async function ensureDatabase(dbName: string): Promise<void> {
  const rootPool = createDatabasePool(getEventTestDatabaseConfig('postgres'));
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

export function getEventTestDatabaseConfig(dbName = 'shn_test'): DatabaseConfig {
  return {
    host: process.env.SHN_TEST_DB_HOST || '127.0.0.1',
    port: parseInt(process.env.SHN_TEST_DB_PORT || '54329', 10),
    database: process.env.SHN_TEST_DB_NAME || dbName,
    user: process.env.SHN_TEST_DB_USER || 'postgres',
    password: process.env.SHN_TEST_DB_PASSWORD || undefined,
    ssl: false,
    maxConnections: 15,
    minConnections: 1,
    idleTimeoutMs: 5000,
    connectionTimeoutMs: 5000,
  };
}

export function createEventTestPool(dbName = 'shn_test'): DatabasePool {
  return createDatabasePool(getEventTestDatabaseConfig(dbName));
}

export async function setupEventTestDatabase(pool: DatabasePool, dbName = 'shn_test'): Promise<void> {
  await ensureDatabase(dbName);
  const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
  await runMigrations(pool, migrationsDir);
}

export async function cleanEventTables(pool: DatabasePool): Promise<void> {
  await pool.query('TRUNCATE TABLE events.dead_letter CASCADE;');
  await pool.query('TRUNCATE TABLE events.deduplication_log CASCADE;');
  await pool.query('TRUNCATE TABLE events.outbox CASCADE;');
}

export function validOrgId(): OrganizationId {
  const r = createOrganizationId(generateUUIDv7());
  if (r.isErr) throw new Error(r.error);
  return r.value;
}

export function validWorkspaceId(): WorkspaceId {
  const r = createWorkspaceId(generateUUIDv7());
  if (r.isErr) throw new Error(r.error);
  return r.value;
}

export function validEventId(): EventId {
  const r = createEventId(generateUUIDv7());
  if (r.isErr) throw new Error(r.error);
  return r.value;
}

export function validCorrelationId(): CorrelationId {
  const r = createCorrelationId(generateUUIDv7());
  if (r.isErr) throw new Error(r.error);
  return r.value;
}

export function validCausationId(): CausationId {
  const r = createCausationId(generateUUIDv7());
  if (r.isErr) throw new Error(r.error);
  return r.value;
}

export function createValidEnvelope<TPayload = Record<string, unknown>>(
  overrides?: Partial<CanonicalEventEnvelope<TPayload>>
): CanonicalEventEnvelope<TPayload> {
  const workspaceId = overrides?.workspace_id ?? validWorkspaceId();
  const correlationId = overrides?.correlation_id ?? validCorrelationId();
  const eventId = overrides?.event_id ?? validEventId();
  const causationId = overrides?.causation_id ?? validCausationId();

  return {
    event_id: eventId,
    event_type: overrides?.event_type ?? 'scan.target.created',
    schema_version: overrides?.schema_version ?? '1.0.0',
    occurred_at: overrides?.occurred_at ?? nowIso(),
    producer: overrides?.producer ?? {
      module_name: 'mod_scanner',
      node_id: 'test-node-1',
      environment: 'test',
      build_version: '0.1.0',
    },
    workspace_id: workspaceId,
    correlation_id: correlationId,
    causation_id: causationId,
    trace_id: overrides?.trace_id ?? '4bf92f3577b34da6a3ce929d0e0e4736',
    authorization_context: overrides?.authorization_context ?? {
      principal_id: 'usr-operator-1',
      token_id: generateUUIDv7(),
      roles: ['operator', 'tenant_admin'],
      signature: 'valid-test-sig',
      expires_at: nowIso(),
    },
    scope_reference: overrides?.scope_reference ?? {
      scope_id: 'scope-test-1',
      scope_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    },
    payload: (overrides?.payload ?? { target: '192.168.1.1', profile: 'stealth' }) as TPayload,
    integrity: overrides?.integrity ?? {
      algorithm: 'HMAC-SHA256',
      signature: 'integrity-signature-test',
      key_id: 'test-key-1',
    },
  };
}

export async function createTestWorkspaceFixture(pool: DatabasePool): Promise<{ org: OrganizationRecord; workspace: WorkspaceRecord }> {
  const orgRepo = new OrganizationRepository(pool);
  const wsRepo = new WorkspaceRepository(pool);

  const orgId = validOrgId();
  const org = await orgRepo.create({
    id: orgId,
    name: 'Test Org',
    slug: `test-org-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
  });

  const wsId = validWorkspaceId();
  const workspace = await wsRepo.create({
    id: wsId,
    organization_id: orgId,
    name: 'Test Workspace',
    slug: `test-ws-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
  });

  return { org, workspace };
}
