/**
 * Shadow : Helix Nebula (SHN) — Execution Supervisor Test Helper
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
  type ExecutionRequest,
} from '@shn/shared-kernel';
import {
  runMigrations,
  closeDatabasePool,
  type DatabasePool,
  OrganizationRepository,
  WorkspaceRepository,
  UserRepository,
  ExecutionRepository,
  ScopeRepository,
} from '@shn/data-access';
import { SecurityContextSigner, PermissionBit } from '@shn/auth-rbac';
import { ScopeGatekeeper, TenancyValidator } from '@shn/scope-gatekeeper';
import { createMeter, type IMeter } from '@shn/telemetry';
import { createTestPool, resetDatabase, ensureDatabase } from '../../../data-access/test/test-helper.ts';
import { ExecutionSupervisor } from '../../dist/index.js';

export const TEST_AUTH_SECRET = 'test-shn-auth-secret-key-32b-length!!';
export const TEST_SCOPE_SIGNING_KEY = 'test-shn-scope-secret-key-32b-len!';

export interface SupervisorTestEnvironment {
  pool: DatabasePool;
  orgRepo: OrganizationRepository;
  workspaceRepo: WorkspaceRepository;
  userRepo: UserRepository;
  executionRepo: ExecutionRepository;
  scopeRepo: ScopeRepository;
  authSigner: SecurityContextSigner;
  gatekeeper: ScopeGatekeeper;
  tenancyValidator: TenancyValidator;
  supervisor: ExecutionSupervisor;
  meter: IMeter;
  orgId: OrganizationId;
  workspaceId: WorkspaceId;
  otherWorkspaceId: WorkspaceId;
  otherOrgId: OrganizationId;
  userId: UserId;
  scopeId: ScopeId;
  mintToken: (overrides?: Partial<SecurityContextToken>) => SecurityContextToken;
  createRequest: (overrides?: Partial<ExecutionRequest>) => ExecutionRequest;
  cleanup: () => Promise<void>;
}

export async function setupSupervisorTestEnv(dbName = 'shn_test_supervisor'): Promise<SupervisorTestEnvironment> {
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

  // Base entities
  const orgId = createOrganizationId(generateUUIDv7()).value;
  await orgRepo.create({
    id: orgId,
    name: 'Primary Security Org',
    slug: 'prim-sec-' + Math.random().toString(36).substring(2, 8),
  });

  const workspaceId = createWorkspaceId(generateUUIDv7()).value;
  await workspaceRepo.create({
    id: workspaceId,
    organization_id: orgId,
    name: 'Ops Workspace',
    slug: 'ops-ws-' + Math.random().toString(36).substring(2, 8),
  });

  const otherWorkspaceId = createWorkspaceId(generateUUIDv7()).value;
  await workspaceRepo.create({
    id: otherWorkspaceId,
    organization_id: orgId,
    name: 'Isolated Workspace',
    slug: 'iso-ws-' + Math.random().toString(36).substring(2, 8),
  });

  const otherOrgId = createOrganizationId(generateUUIDv7()).value;
  await orgRepo.create({
    id: otherOrgId,
    name: 'Foreign Org',
    slug: 'foreign-org-' + Math.random().toString(36).substring(2, 8),
  });

  const userId = createUserId(generateUUIDv4()).value;
  await userRepo.create({
    id: userId,
    organization_id: orgId,
    email: 'operator@sec.test',
    display_name: 'Security Operator',
  });

  // Setup default wildcard authorized scope in primary workspace
  const scopeId = createScopeId(generateUUIDv7()).value;
  const now = Date.now();
  const validFrom = new Date(now - 60_000).toISOString();
  const validUntil = new Date(now + 86400_000).toISOString();

  await scopeRepo.createScope({
    id: scopeId,
    workspace_id: workspaceId,
    organization_id: orgId,
    name: 'Default Test Scope',
    description: 'Permits 192.168.1.0/24 and scan actions',
    status: 'ACTIVE',
    inclusions: {
      cidrs: ['192.168.1.0/24'],
      hostnames: ['example.com'],
      urls: [],
    },
    exclusions: {
      cidrs: ['192.168.1.254/32'],
      hostnames: [],
      urls: [],
    },
    allowed_actions: ['scan', 'probe', 'recon', 'execute'],
    disallowed_actions: [],
    port_ranges: [{ start: 1, end: 65535 }],
    valid_from: validFrom,
    valid_until: validUntil,
    rate_limits: {},
    scope_sha256: '0000000000000000000000000000000000000000000000000000000000000000',
  });

  const mintToken = (overrides?: Partial<SecurityContextToken>): SecurityContextToken => {
    return authSigner.createToken({
      subjectId: (overrides?.subject_id ?? userId) as any,
      workspaceId: (overrides?.workspace_id ?? workspaceId) as any,
      roles: (overrides?.roles as string[]) ?? ['OPERATOR'],
      permissionMask:
        overrides?.permission_mask ??
        (PermissionBit.SCAN_INVASIVE |
          PermissionBit.PROBING_ACTIVE |
          PermissionBit.RECON_PASSIVE |
          PermissionBit.SCOPE_READ |
          PermissionBit.WORKFLOW_EXECUTE),
      ttlSeconds: 600,
    });
  };

  const createRequest = (overrides?: Partial<ExecutionRequest>): ExecutionRequest => {
    const token = overrides?.securityContext ?? mintToken();
    return {
      workspaceId,
      organizationId: orgId,
      requestedBy: userId,
      securityContext: token,
      scopeId,
      action: 'scan',
      target: '192.168.1.50',
      port: 80,
      capabilityUri: 'urn:shn:tool:echo',
      command: {
        executable: process.execPath,
        args: ['-e', 'process.stdout.write("Execution finished successfully\\n");'],
      },
      resourceLimits: {
        timeoutMs: 10_000,
        startupTimeoutMs: 5_000,
        maxStdoutBytes: 1024 * 1024,
      },
      ...overrides,
    };
  };

  const cleanup = async () => {
    await closeDatabasePool(pool);
  };

  return {
    pool,
    orgRepo,
    workspaceRepo,
    userRepo,
    executionRepo,
    scopeRepo,
    authSigner,
    gatekeeper,
    tenancyValidator,
    supervisor,
    meter,
    orgId,
    workspaceId,
    otherWorkspaceId,
    otherOrgId,
    userId,
    scopeId,
    mintToken,
    createRequest,
    cleanup,
  };
}
