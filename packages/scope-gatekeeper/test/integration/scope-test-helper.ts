/**
 * Shadow : Helix Nebula (SHN) — Scope Gatekeeper Integration Test Helper
 */

import path from 'node:path';
import process from 'node:process';
import {
  type OrganizationId,
  type WorkspaceId,
  type UserId,
  type ScopeId,
  type SecurityContextToken,
  type IsoTimestamp,
  generateUUIDv7,
  createOrganizationId,
  createWorkspaceId,
  createUserId,
  createScopeId,
} from '@shn/shared-kernel';
import {
  createDatabasePool,
  runMigrations,
  type DatabasePool,
  type DatabaseConfig,
  OrganizationRepository,
  WorkspaceRepository,
  ScopeRepository,
  type ScopeRecord,
  type CreateScopeInput,
} from '@shn/data-access';
import {
  SecurityContextSigner,
  PermissionBit,
} from '@shn/auth-rbac';
import {
  ScopeGatekeeper,
  ScopeTokenSigner,
  TenancyValidator,
  calculateCanonicalScopeSha256,
} from '../../dist/index.js';

export const TEST_SCOPE_SIGNING_KEY = 'shn-test-scope-token-signing-key-32b-long!!';
export const TEST_AUTH_SIGNING_KEY = 'shn-test-auth-context-signing-key-32b-long!!';

export function getScopeTestDatabaseConfig(dbName = 'shn_test'): DatabaseConfig {
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

export async function ensureDatabase(dbName: string): Promise<void> {
  const rootPool = createDatabasePool(getScopeTestDatabaseConfig('postgres'));
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

export function createScopeTestPool(dbName = 'shn_test'): DatabasePool {
  return createDatabasePool(getScopeTestDatabaseConfig(dbName));
}

export async function setupScopeTestDatabase(pool: DatabasePool, dbName = 'shn_test'): Promise<void> {
  await ensureDatabase(dbName);
  const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
  await runMigrations(pool, migrationsDir);
}

export async function cleanScopeTables(pool: DatabasePool): Promise<void> {
  await pool.query('TRUNCATE TABLE workspace.scopes CASCADE;');
}

export interface ScopeTestServices {
  pool: DatabasePool;
  orgRepo: OrganizationRepository;
  workspaceRepo: WorkspaceRepository;
  scopeRepo: ScopeRepository;
  authSigner: SecurityContextSigner;
  tokenSigner: ScopeTokenSigner;
  tenancyValidator: TenancyValidator;
  gatekeeper: ScopeGatekeeper;
}

export function createScopeTestServices(pool: DatabasePool): ScopeTestServices {
  const orgRepo = new OrganizationRepository(pool);
  const workspaceRepo = new WorkspaceRepository(pool);
  const scopeRepo = new ScopeRepository(pool);
  const authSigner = new SecurityContextSigner(TEST_AUTH_SIGNING_KEY);
  const tokenSigner = new ScopeTokenSigner(TEST_SCOPE_SIGNING_KEY);
  const tenancyValidator = new TenancyValidator(workspaceRepo, orgRepo);

  const gatekeeper = new ScopeGatekeeper({
    scopeRepo,
    workspaceRepo,
    orgRepo,
    tokenSigner,
    tenancyValidator,
  });

  return {
    pool,
    orgRepo,
    workspaceRepo,
    scopeRepo,
    authSigner,
    tokenSigner,
    tenancyValidator,
    gatekeeper,
  };
}

export async function createTestOrgAndWorkspace(services: ScopeTestServices): Promise<{
  orgId: OrganizationId;
  workspaceId: WorkspaceId;
}> {
  const orgId = createOrganizationId(generateUUIDv7()).value;
  const workspaceId = createWorkspaceId(generateUUIDv7()).value;

  await services.orgRepo.create({
    id: orgId,
    name: 'Gatekeeper Test Org',
    slug: `org-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
  });

  await services.workspaceRepo.create({
    id: workspaceId,
    organization_id: orgId,
    name: 'Gatekeeper Test Workspace',
    slug: `ws-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
    environment: 'production',
  });

  return { orgId, workspaceId };
}

export function createTestSecurityContext(
  services: ScopeTestServices,
  workspaceId: WorkspaceId,
  actorId: UserId = createUserId(generateUUIDv7()).value,
  permissionMask: number = PermissionBit.SCOPE_READ |
    PermissionBit.SCOPE_ADMIN |
    PermissionBit.RECON_PASSIVE |
    PermissionBit.PROBING_ACTIVE |
    PermissionBit.SCAN_INVASIVE |
    PermissionBit.WORKFLOW_EXECUTE
): SecurityContextToken {
  return services.authSigner.createToken({
    subjectId: actorId,
    subjectType: 'OPERATOR',
    workspaceId,
    roles: ['OPERATOR'],
    permissionMask,
    ttlSeconds: 900,
  });
}

export async function createPersistedScope(
  services: ScopeTestServices,
  workspaceId: WorkspaceId,
  organizationId: OrganizationId,
  overrides: Partial<CreateScopeInput> = {}
): Promise<ScopeRecord> {
  const scopeId = createScopeId(generateUUIDv7()).value;
  const validFrom = new Date(Date.now() - 60000).toISOString() as IsoTimestamp;
  const validUntil = new Date(Date.now() + 3600000).toISOString() as IsoTimestamp;

  const inclusions = overrides.inclusions ?? [
    '10.0.0.0/16',
    '*.example.com',
    'https://example.com/api',
  ];
  const exclusions = overrides.exclusions ?? ['10.0.99.0/24'];
  const allowedActions = overrides.allowed_actions ?? ['recon_passive', 'probing_active', 'scan_invasive'];
  const disallowedActions = overrides.disallowed_actions ?? ['destructive_exploit'];
  const portRanges = overrides.port_ranges ?? [{ start: 80, end: 443 }];

  const scopeSha256 = calculateCanonicalScopeSha256({
    inclusions: {
      cidrs: inclusions.filter((i) => typeof i === 'string' && (i.includes('/') || /^\d+\./.test(i))) as string[],
      hostnames: inclusions.filter((i) => typeof i === 'string' && !i.includes('/') && !i.startsWith('http')) as string[],
      urls: inclusions.filter((i) => typeof i === 'string' && i.startsWith('http')) as string[],
    },
    exclusions: {
      cidrs: exclusions.filter((i) => typeof i === 'string' && (i.includes('/') || /^\d+\./.test(i))) as string[],
    },
    allowedActions,
    disallowedActions,
    portRanges,
    validFrom,
    validUntil,
  });

  return services.scopeRepo.createScope({
    id: scopeId,
    workspace_id: workspaceId,
    organization_id: organizationId,
    name: overrides.name ?? 'Integration Test Scope',
    description: 'Integration test scope description',
    status: 'ACTIVE',
    inclusions,
    exclusions,
    allowed_actions: allowedActions,
    disallowed_actions: disallowedActions,
    port_ranges: portRanges,
    valid_from: validFrom,
    valid_until: validUntil,
    rate_limits: {},
    scope_sha256: scopeSha256,
  });
}
