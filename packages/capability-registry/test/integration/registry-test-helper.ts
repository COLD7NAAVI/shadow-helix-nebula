/**
 * Shadow : Helix Nebula (SHN) — Capability Registry Integration Test Helper
 */

import path from 'node:path';
import {
  generateUUIDv7,
  generateUUIDv4,
  createOrganizationId,
  createWorkspaceId,
  createUserId,
  createScopeId,
  type OrganizationId,
  type WorkspaceId,
  type UserId,
  type ScopeId,
  type SecurityContextToken,
} from '@shn/shared-kernel';
import {
  runMigrations,
  type DatabasePool,
  CapabilityRepository,
  OrganizationRepository,
  WorkspaceRepository,
  UserRepository,
  ExecutionRepository,
  ScopeRepository,
} from '@shn/data-access';
import { SecurityContextSigner } from '@shn/auth-rbac';
import { ScopeGatekeeper, TenancyValidator } from '@shn/scope-gatekeeper';
import { ExecutionSupervisor } from '@shn/execution-supervisor';
import { createMeter, type IMeter } from '@shn/telemetry';
import { createTestPool, resetDatabase, ensureDatabase } from '../../../data-access/test/test-helper.ts';
import {
  CapabilityRegistry,
  CapabilityDispatcher,
  NetworkPortScanAdapter,
  HttpDiscoveryAdapter,
  type CapabilityDefinition,
} from '../../dist/index.js';

export const TEST_AUTH_SECRET = 'test-shn-auth-secret-key-32b-length!!';
export const TEST_SCOPE_SIGNING_KEY = 'test-shn-scope-secret-key-32b-len!';

export interface RegistryTestEnvironment {
  pool: DatabasePool;
  capRepo: CapabilityRepository;
  orgRepo: OrganizationRepository;
  workspaceRepo: WorkspaceRepository;
  userRepo: UserRepository;
  executionRepo: ExecutionRepository;
  scopeRepo: ScopeRepository;
  registry: CapabilityRegistry;
  dispatcher: CapabilityDispatcher;
  supervisor: ExecutionSupervisor;
  gatekeeper: ScopeGatekeeper;
  tenancyValidator: TenancyValidator;
  authSigner: SecurityContextSigner;
  meter: IMeter;
  orgId: OrganizationId;
  workspaceId: WorkspaceId;
  foreignOrgId: OrganizationId;
  foreignWorkspaceId: WorkspaceId;
  userId: UserId;
  scopeId: ScopeId;
  mintToken: (workspaceId: WorkspaceId, overrides?: Partial<SecurityContextToken>) => SecurityContextToken;
  cleanup: () => Promise<void>;
}

export async function setupRegistryTestEnv(
  dbName = 'shn_test_capability_registry'
): Promise<RegistryTestEnvironment> {
  await ensureDatabase(dbName);
  const pool = createTestPool(dbName);
  await resetDatabase(pool);
  const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
  await runMigrations(pool, migrationsDir);

  const orgRepo = new OrganizationRepository(pool);
  const workspaceRepo = new WorkspaceRepository(pool);
  const userRepo = new UserRepository(pool);
  const executionRepo = new ExecutionRepository(pool);
  const scopeRepo = new ScopeRepository(pool);
  const capRepo = new CapabilityRepository(pool);

  const authSigner = new SecurityContextSigner(TEST_AUTH_SECRET);
  const tenancyValidator = new TenancyValidator(workspaceRepo, orgRepo);
  const gatekeeper = new ScopeGatekeeper({
    scopeRepo,
    workspaceRepo,
    orgRepo,
    signingSecret: TEST_SCOPE_SIGNING_KEY,
    tenancyValidator,
  });

  const meter = createMeter();

  const supervisor = new ExecutionSupervisor({
    gatekeeper,
    executionRepo,
    authSigner,
    tenancyValidator,
    meter,
    maxConcurrentExecutions: 10,
  });

  const registry = new CapabilityRegistry({
    repository: capRepo,
  });

  const dispatcher = new CapabilityDispatcher({
    registry,
    supervisor,
    scopeGatekeeper: gatekeeper,
    tenancyValidator,
    meter,
  });

  // Base entities
  const orgId = createOrganizationId(generateUUIDv7()).value;
  await orgRepo.create({
    id: orgId,
    name: 'Registry Test Org',
    slug: 'reg-org-' + Math.random().toString(36).substring(2, 8),
  });

  const workspaceId = createWorkspaceId(generateUUIDv7()).value;
  await workspaceRepo.create({
    id: workspaceId,
    organization_id: orgId,
    name: 'Registry Main Workspace',
    slug: 'reg-ws-' + Math.random().toString(36).substring(2, 8),
  });

  const foreignOrgId = createOrganizationId(generateUUIDv7()).value;
  await orgRepo.create({
    id: foreignOrgId,
    name: 'Foreign Org',
    slug: 'foreign-org-' + Math.random().toString(36).substring(2, 8),
  });

  const foreignWorkspaceId = createWorkspaceId(generateUUIDv7()).value;
  await workspaceRepo.create({
    id: foreignWorkspaceId,
    organization_id: foreignOrgId,
    name: 'Foreign Workspace',
    slug: 'foreign-ws-' + Math.random().toString(36).substring(2, 8),
  });

  const userId = createUserId(generateUUIDv4()).value;
  await userRepo.create({
    id: userId,
    organization_id: orgId,
    email: 'operator@registry.test',
    display_name: 'Registry Operator',
  });

  // Default broad scope in workspaceId
  const scopeId = createScopeId(generateUUIDv7()).value;
  const now = Date.now();
  await scopeRepo.createScope({
    id: scopeId,
    organization_id: orgId,
    workspace_id: workspaceId,
    name: 'Broad Recon Scope',
    description: 'Permits 192.168.0.0/16 and test domain targets',
    status: 'ACTIVE',
    valid_from: new Date(now - 60_000).toISOString(),
    valid_until: new Date(now + 86400_000).toISOString(),
    inclusions: {
      cidrs: ['192.168.0.0/16', '10.0.0.1/32'],
      hostnames: ['example.com'],
      urls: [],
    },
    exclusions: {
      cidrs: [],
      hostnames: [],
      urls: [],
    },
    allowed_actions: ['network:scan', 'web:discover', 'recon:http', 'SCAN_TCP_PORT', 'HTTP_GET', 'PROBING_ACTIVE'],
    disallowed_actions: [],
    port_ranges: [{ start: 1, end: 65535 }],
    rate_limits: {},
    scope_sha256: '0'.repeat(64),
    created_by: userId,
  });

  function mintToken(
    wsId: WorkspaceId,
    overrides?: Partial<SecurityContextToken>
  ): SecurityContextToken {
    const token = authSigner.createToken({
      subjectId: (overrides?.subject_id ?? userId) as any,
      subjectType: overrides?.subject_type ?? 'OPERATOR',
      workspaceId: wsId,
      roles: (overrides?.roles as string[]) ?? ['OPERATOR', 'ADMIN'],
      permissionMask: overrides?.permission_mask ?? 0xffffffff,
      ttlSeconds: 3600,
    });
    if (overrides) {
      return {
        ...token,
        ...overrides,
        signature: overrides.signature ?? token.signature,
      };
    }
    return token;
  }

  return {
    pool,
    capRepo,
    orgRepo,
    workspaceRepo,
    userRepo,
    executionRepo,
    scopeRepo,
    registry,
    dispatcher,
    supervisor,
    gatekeeper,
    tenancyValidator,
    authSigner,
    meter,
    orgId,
    workspaceId,
    foreignOrgId,
    foreignWorkspaceId,
    userId,
    scopeId,
    mintToken,
    cleanup: async () => {
      await pool.end();
    },
  };
}
