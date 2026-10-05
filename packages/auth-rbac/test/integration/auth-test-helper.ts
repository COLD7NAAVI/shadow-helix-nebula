/**
 * Shadow : Helix Nebula (SHN) — Auth & Secrets Test Helper
 */

import path from 'node:path';
import process from 'node:process';
import {
  type OrganizationId,
  type WorkspaceId,
  type UserId,
  generateUUIDv7,
  createOrganizationId,
  createWorkspaceId,
  createUserId,
} from '@shn/shared-kernel';
import {
  createDatabasePool,
  runMigrations,
  type DatabasePool,
  type DatabaseConfig,
  OrganizationRepository,
  WorkspaceRepository,
  UserRepository,
  CredentialRepository,
  SessionRepository,
  RoleRepository,
  PermissionRepository,
  SecretsMetadataRepository,
  SecretsVersionRepository,
} from '@shn/data-access';

import {
  SecurityContextSigner,
  AuthorizationService,
  SecretsVault,
  defaultPasswordHasher,
} from '../../dist/index.js';

export const TEST_MASTER_KEY = Buffer.alloc(32, 0x5a); // 32-byte deterministic master key
export const TEST_SIGNING_KEY = 'shn-test-context-token-signing-key-32b!';

export function getAuthTestDatabaseConfig(dbName = 'shn_test'): DatabaseConfig {
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
  const rootPool = createDatabasePool(getAuthTestDatabaseConfig('postgres'));
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

export function createAuthTestPool(dbName = 'shn_test'): DatabasePool {
  return createDatabasePool(getAuthTestDatabaseConfig(dbName));
}

export async function setupAuthTestDatabase(pool: DatabasePool, dbName = 'shn_test'): Promise<void> {
  await ensureDatabase(dbName);
  const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
  await runMigrations(pool, migrationsDir);
}

export async function cleanAuthAndSecretsTables(pool: DatabasePool): Promise<void> {
  await pool.query('TRUNCATE TABLE secrets.versions CASCADE;');
  await pool.query('TRUNCATE TABLE secrets.metadata CASCADE;');
  await pool.query('TRUNCATE TABLE iam.user_roles CASCADE;');
  await pool.query('TRUNCATE TABLE iam.sessions CASCADE;');
  await pool.query('TRUNCATE TABLE iam.user_credentials CASCADE;');
  await pool.query('TRUNCATE TABLE iam.users CASCADE;');
  await pool.query('DELETE FROM workspace.workspaces WHERE id NOT IN (SELECT workspace_id FROM audit.events);');
  await pool.query('DELETE FROM iam.organizations WHERE id NOT IN (SELECT organization_id FROM workspace.workspaces);');
}

export interface TestServices {
  pool: DatabasePool;
  orgRepo: OrganizationRepository;
  workspaceRepo: WorkspaceRepository;
  userRepo: UserRepository;
  credentialRepo: CredentialRepository;
  sessionRepo: SessionRepository;
  roleRepo: RoleRepository;
  permissionRepo: PermissionRepository;
  secretsMetaRepo: SecretsMetadataRepository;
  secretsVersionRepo: SecretsVersionRepository;
  signer: SecurityContextSigner;
  authService: AuthorizationService;
  secretsVault: SecretsVault;
}

export function createTestServices(pool: DatabasePool): TestServices {
  const orgRepo = new OrganizationRepository(pool);
  const workspaceRepo = new WorkspaceRepository(pool);
  const userRepo = new UserRepository(pool);
  const credentialRepo = new CredentialRepository(pool);
  const sessionRepo = new SessionRepository(pool);
  const roleRepo = new RoleRepository(pool);
  const permissionRepo = new PermissionRepository(pool);
  const secretsMetaRepo = new SecretsMetadataRepository(pool);
  const secretsVersionRepo = new SecretsVersionRepository(pool);

  const signer = new SecurityContextSigner(TEST_SIGNING_KEY);

  const authService = new AuthorizationService({
    userRepo,
    credentialRepo,
    sessionRepo,
    roleRepo,
    permissionRepo,
    workspaceRepo,
    signer,
  });

  const secretsVault = new SecretsVault({
    metadataRepo: secretsMetaRepo,
    versionRepo: secretsVersionRepo,
    masterKey: TEST_MASTER_KEY,
    authService,
  });

  return {
    pool,
    orgRepo,
    workspaceRepo,
    userRepo,
    credentialRepo,
    sessionRepo,
    roleRepo,
    permissionRepo,
    secretsMetaRepo,
    secretsVersionRepo,
    signer,
    authService,
    secretsVault,
  };
}

export async function createTestOrgAndWorkspace(
  services: TestServices,
  orgSlug = `org-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
  wsSlug = `ws-default`
): Promise<{ orgId: OrganizationId; workspaceId: WorkspaceId }> {
  const orgIdRes = createOrganizationId(generateUUIDv7());
  const orgId = orgIdRes.isOk ? orgIdRes.value : ('00000000-0000-7000-8000-000000000001' as OrganizationId);

  const wsIdRes = createWorkspaceId(generateUUIDv7());
  const workspaceId = wsIdRes.isOk ? wsIdRes.value : ('00000000-0000-7000-8000-000000000002' as WorkspaceId);

  await services.orgRepo.create({
    id: orgId,
    name: `Test Org ${orgSlug}`,
    slug: orgSlug,
  });

  await services.workspaceRepo.create({
    id: workspaceId,
    organization_id: orgId,
    name: `Test Workspace ${wsSlug}`,
    slug: wsSlug,
  });

  return { orgId, workspaceId };
}

export async function createTestUserWithCredentials(
  services: TestServices,
  orgId: OrganizationId,
  email: string,
  password: string,
  roles: string[] = ['OPERATOR'],
  workspaceId: WorkspaceId | null = null,
  status = 'ACTIVE'
): Promise<{ userId: UserId; email: string }> {
  const userIdRes = createUserId(generateUUIDv7());
  const userId = userIdRes.isOk ? userIdRes.value : ('00000000-0000-7000-8000-000000000003' as UserId);

  await services.userRepo.create({
    id: userId,
    organization_id: orgId,
    email: email.toLowerCase(),
    display_name: 'Test Operator',
    status,
  });

  const passwordHash = await defaultPasswordHasher.hashPassword(password);
  await services.credentialRepo.saveCredential(userId, passwordHash);

  for (const roleName of roles) {
    const role = await services.roleRepo.findRoleByName(roleName);
    if (role) {
      await services.roleRepo.assignUserRole(userId, role.id, orgId, workspaceId);
    }
  }

  return { userId, email };
}
