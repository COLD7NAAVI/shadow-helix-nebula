/**
 * Shadow : Helix Nebula (SHN) — Ingress Gateway End-to-End Integration Tests
 *
 * Exercises real HTTP requests over TCP, authentication, RBAC, tenancy isolation,
 * asset & finding operations, capability execution, and CLI parity.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  generateUUIDv7,
  createOrganizationId,
  createWorkspaceId,
  type OrganizationId,
  type WorkspaceId,
} from '@shn/shared-kernel';
import {
  runMigrations,
  closeDatabasePool,
  type DatabasePool,
  OrganizationRepository,
  UserRepository,
  WorkspaceRepository,
  CredentialRepository,
  RoleRepository,
  AssetRepository,
  FindingRepository,
  CapabilityRepository,
  ExecutionRepository,
  ScopeRepository,
} from '@shn/data-access';
import { SecurityContextSigner } from '@shn/auth-rbac';
import { ScopeGatekeeper, TenancyValidator } from '@shn/scope-gatekeeper';
import { ExecutionSupervisor } from '@shn/execution-supervisor';
import {
  CapabilityRegistry,
  CapabilityDispatcher,
  NetworkPortScanAdapter,
  HttpDiscoveryAdapter,
} from '@shn/capability-registry';
import { AssetInventoryService, FindingLifecycleService } from '@shn/asset-inventory';
import { createIngressApplication, IngressServer, CliRunner } from '../../dist/index.js';
import { createTestPool, resetDatabase, ensureDatabase } from '../../../data-access/test/test-helper.ts';

describe('Ingress Gateway & CLI End-to-End (Integration)', () => {
  let pool: DatabasePool;
  let server: IngressServer;
  let serverUrl: string;
  let authToken: string;
  let primaryWorkspaceId: string;
  let foreignWorkspaceId: string;

  before(async () => {
    await ensureDatabase('shn_test_gateway_e2e');
    pool = createTestPool('shn_test_gateway_e2e');
    await resetDatabase(pool);
    const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
    await runMigrations(pool, migrationsDir);

    const orgRepo = new OrganizationRepository(pool);
    const userRepo = new UserRepository(pool);
    const workspaceRepo = new WorkspaceRepository(pool);
    const credentialRepo = new CredentialRepository(pool);
    const roleRepo = new RoleRepository(pool);
    const assetRepo = new AssetRepository(pool);
    const findingRepo = new FindingRepository(pool);
    const capabilityRepo = new CapabilityRepository(pool);
    const executionRepo = new ExecutionRepository(pool);
    const scopeRepo = new ScopeRepository(pool);

    const signerSecret = 'shn-test-signer-secret-key-32b!';
    const signer = new SecurityContextSigner(signerSecret);
    const tenancyValidator = new TenancyValidator(workspaceRepo);
    const scopeGatekeeper = new ScopeGatekeeper({
      scopeRepository: scopeRepo,
      signerSecret: 'shn-test-scope-secret-key-32b!!',
    });

    const assetService = new AssetInventoryService({ assetRepository: assetRepo });
    const findingService = new FindingLifecycleService({
      findingRepository: findingRepo,
      assetRepository: assetRepo,
    });

    const capabilityRegistry = new CapabilityRegistry({ repository: capabilityRepo });
    const executionSupervisor = new ExecutionSupervisor({ repository: executionRepo });

    // Register reference tool adapters
    await capabilityRegistry.registerAdapter(new NetworkPortScanAdapter());
    await capabilityRegistry.registerAdapter(new HttpDiscoveryAdapter());

    const capabilityDispatcher = new CapabilityDispatcher({
      registry: capabilityRegistry,
      supervisor: executionSupervisor,
      scopeGatekeeper,
      tenancyValidator,
    });

    server = createIngressApplication({
      pool,
      orgRepo,
      userRepo,
      workspaceRepo,
      credentialRepo,
      roleRepo,
      assetRepo,
      findingRepo,
      executionRepo,
      scopeRepo,
      assetService,
      findingService,
      capabilityRegistry,
      capabilityDispatcher,
      signer,
      tenancyValidator,
      config: {
        port: 0, // OS assigns an ephemeral available port
        host: '127.0.0.1',
      },
    });

    const started = await server.start();
    serverUrl = `http://127.0.0.1:${started.port}`;
  });

  after(async () => {
    await server.stop();
    await closeDatabasePool(pool);
  });

  it('1. Health and readiness endpoints return 200 UP', async () => {
    const liveRes = await fetch(`${serverUrl}/health/live`);
    assert.strictEqual(liveRes.status, 200);
    const liveJson = await liveRes.json();
    assert.strictEqual(liveJson.status, 'UP');

    const readyRes = await fetch(`${serverUrl}/health/ready`);
    assert.strictEqual(readyRes.status, 200);
    const readyJson = await readyRes.json();
    assert.strictEqual(readyJson.status, 'UP');
    assert.strictEqual(readyJson.checks.database, 'UP');

    const metricsRes = await fetch(`${serverUrl}/metrics`);
    assert.strictEqual(metricsRes.status, 200);
    const metricsText = await metricsRes.text();
    assert.match(metricsText, /shn_gateway_up 1/);
  });

  it('2. Auth registration and login issue valid SecurityContextToken', async () => {
    const regRes = await fetch(`${serverUrl}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        organizationName: 'Global Defense Corp',
        adminEmail: 'secops@defense.corp',
        adminPassword: 'Password123!',
        adminName: 'Chief Security Officer',
      }),
    });

    assert.strictEqual(regRes.status, 201);
    const regData = await regRes.json();
    assert.strictEqual(regData.organization.name, 'Global Defense Corp');
    assert.strictEqual(regData.user.email, 'secops@defense.corp');
    primaryWorkspaceId = regData.workspace.id;

    // Login
    const loginRes = await fetch(`${serverUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'secops@defense.corp',
        password: 'Password123!',
      }),
    });

    assert.strictEqual(loginRes.status, 200);
    const loginData = await loginRes.json();
    assert.strictEqual(typeof loginData.token, 'string');
    assert.strictEqual(loginData.roles.includes('ADMIN'), true);
    authToken = loginData.token;

    // Verify /api/v1/auth/me
    const meRes = await fetch(`${serverUrl}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    assert.strictEqual(meRes.status, 200);
    const meData = await meRes.json();
    assert.strictEqual(meData.actor.roles.includes('ADMIN'), true);
  });

  it('3. Workspace management creates and lists workspaces', async () => {
    const createRes = await fetch(`${serverUrl}/api/v1/workspaces`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({ name: 'Secondary Red Team Workspace' }),
    });

    assert.strictEqual(createRes.status, 201);
    const createData = await createRes.json();
    foreignWorkspaceId = createData.id;

    const listRes = await fetch(`${serverUrl}/api/v1/workspaces`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    assert.strictEqual(listRes.status, 200);
    const listData = await listRes.json();
    assert.strictEqual(listData.length >= 2, true);
  });

  let createdAssetId: string;

  it('4. Asset registration canonicalizes targets and enforces workspace isolation', async () => {
    const regRes = await fetch(`${serverUrl}/api/v1/workspaces/${primaryWorkspaceId}/assets`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        rawTarget: 'https://API.Corp.Internal:443/v1',
        name: 'Core Payment Gateway',
        criticality: 'CRITICAL',
      }),
    });

    assert.strictEqual(regRes.status, 201);
    const assetData = await regRes.json();
    assert.strictEqual(assetData.type, 'URL');
    assert.strictEqual(assetData.canonicalValue, 'https://api.corp.internal/v1');
    createdAssetId = assetData.id;

    // List assets
    const listRes = await fetch(`${serverUrl}/api/v1/workspaces/${primaryWorkspaceId}/assets`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    assert.strictEqual(listRes.status, 200);
    const listData = await listRes.json();
    assert.strictEqual(listData.length, 1);
    assert.strictEqual(listData[0].id, createdAssetId);
  });

  it('5. Finding lifecycle manages evidence hashing, creation, and status transitions', async () => {
    const evidenceSha = 'd'.repeat(64);

    const recordRes = await fetch(`${serverUrl}/api/v1/workspaces/${primaryWorkspaceId}/findings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({
        assetId: createdAssetId,
        title: 'Remote Code Execution in Ingress Endpoint',
        description: 'Command injection via unsanitized header value.',
        category: 'INJECTION',
        severity: 'CRITICAL',
        cvssScore: 9.8,
        rawEvidenceSha256: evidenceSha,
      }),
    });

    assert.strictEqual(recordRes.status, 201);
    const findingData = await recordRes.json();
    assert.strictEqual(findingData.status, 'DRAFT');
    assert.strictEqual(findingData.rawEvidenceSha256, evidenceSha);

    // Transition status to UNDER_REVIEW
    const transRes = await fetch(
      `${serverUrl}/api/v1/workspaces/${primaryWorkspaceId}/findings/${findingData.id}/transitions`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          toStatus: 'UNDER_REVIEW',
          reason: 'Analyst assigned for verification',
        }),
      }
    );

    assert.strictEqual(transRes.status, 200);
    const transData = await transRes.json();
    assert.strictEqual(transData.status, 'UNDER_REVIEW');

    // Retrieve audit history
    const historyRes = await fetch(
      `${serverUrl}/api/v1/workspaces/${primaryWorkspaceId}/findings/${findingData.id}/history`,
      {
        headers: { Authorization: `Bearer ${authToken}` },
      }
    );
    assert.strictEqual(historyRes.status, 200);
    const historyData = await historyRes.json();
    assert.strictEqual(historyData.length, 1);
    assert.strictEqual(historyData[0].fromStatus, 'DRAFT');
    assert.strictEqual(historyData[0].toStatus, 'UNDER_REVIEW');
  });

  it('6. Cross-workspace isolation fails closed with 404 (anti-IDOR)', async () => {
    // Attempt to access primary workspace's asset using foreign workspace path
    const crossRes = await fetch(
      `${serverUrl}/api/v1/workspaces/${foreignWorkspaceId}/assets/${createdAssetId}`,
      {
        headers: { Authorization: `Bearer ${authToken}` },
      }
    );

    // Must return 404 Not Found to prevent enumeration per Phase 0.14 Section 21
    assert.strictEqual(crossRes.status, 404);
  });

  it('7. Unauthenticated request fails closed with 401 RFC 7807 Problem Details', async () => {
    const unauthRes = await fetch(`${serverUrl}/api/v1/workspaces/${primaryWorkspaceId}/assets`);
    assert.strictEqual(unauthRes.status, 401);
    const problem = await unauthRes.json();
    assert.strictEqual(problem.error_code, 'ERR_AUTH_UNAUTHENTICATED');
  });

  it('8. CLI Runner interacts seamlessly with live API Gateway', async () => {
    const cli = new CliRunner();

    // CLI health check
    const healthResult = await cli.run({
      argv: ['health', '--url', serverUrl],
    });
    assert.strictEqual(healthResult.exitCode, 0);
    assert.match(healthResult.output, /Gateway Status: UP/);

    // CLI auth me check
    const meResult = await cli.run({
      argv: ['auth', 'me', '--url', serverUrl, '--token', authToken],
    });
    assert.strictEqual(meResult.exitCode, 0);
    assert.match(meResult.output, /Principal ID:/);

    // CLI workspace list check
    const wksResult = await cli.run({
      argv: ['workspace', 'list', '--url', serverUrl, '--token', authToken],
    });
    assert.strictEqual(wksResult.exitCode, 0);
    assert.match(wksResult.output, /Workspaces/);

    // CLI JSON output mode
    const jsonResult = await cli.run({
      argv: ['health', '--url', serverUrl, '--json'],
    });
    assert.strictEqual(jsonResult.exitCode, 0);
    const parsedJson = JSON.parse(jsonResult.output);
    assert.strictEqual(parsedJson.status, 'UP');
  });

  it('9. Persisted scope policies appear in the correct workspace after startup and refresh', async () => {
    // 1. Create a scope policy in primary workspace
    const createScopeRes = await fetch(`${serverUrl}/api/v1/workspaces/${primaryWorkspaceId}/scopes`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${authToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Perimeter Alpha Boundary',
        description: 'Authorized scope boundary for primary workspace',
        inclusions: [
          { type: 'URL', value: 'https://16-16-143-137.sslip.io' },
          { type: 'DOMAIN', value: '16-16-143-137.sslip.io' },
        ],
        exclusions: [
          { type: 'IPV4', value: '169.254.169.254' },
          { type: 'CIDR', value: '127.0.0.0/8' },
        ],
        allowedActions: ['RECON_PASSIVE', 'PROBING_ACTIVE', 'PORT_SCAN'],
        portRanges: [{ start: 80, end: 443 }],
      }),
    });

    assert.strictEqual(createScopeRes.status, 201, 'Scope creation must return 201 Created');
    const createdScope = await createScopeRes.json();
    assert.strictEqual(createdScope.name, 'Perimeter Alpha Boundary');
    assert.strictEqual(createdScope.workspace_id, primaryWorkspaceId);

    // 2. Query scope policies for primary workspace (initial load)
    const listRes1 = await fetch(`${serverUrl}/api/v1/workspaces/${primaryWorkspaceId}/scopes`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    assert.strictEqual(listRes1.status, 200);
    const scopesList1 = await listRes1.json();
    assert.strictEqual(scopesList1.length, 1);
    assert.strictEqual(scopesList1[0].id, createdScope.id);
    assert.strictEqual(scopesList1[0].name, 'Perimeter Alpha Boundary');

    // 3. Simulate UI refresh: subsequent query returns the exact persisted scope
    const listRes2 = await fetch(`${serverUrl}/api/v1/workspaces/${primaryWorkspaceId}/scopes`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    assert.strictEqual(listRes2.status, 200);
    const scopesList2 = await listRes2.json();
    assert.strictEqual(scopesList2.length, 1);
    assert.strictEqual(scopesList2[0].id, createdScope.id);
    assert.strictEqual(scopesList2[0].scope_sha256, createdScope.scope_sha256);

    // 4. Verify cross-workspace isolation: access with mismatched workspace token fails closed with 404 (anti-IDOR)
    const foreignListRes = await fetch(`${serverUrl}/api/v1/workspaces/${foreignWorkspaceId}/scopes`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    assert.strictEqual(foreignListRes.status, 404, 'Foreign workspace must fail closed with 404 anti-IDOR to prevent scope enumeration');

    // 5. Verify direct database persistence: query ScopeRepository directly
    const directRepo = new ScopeRepository(pool);
    const persistedDirect = await directRepo.findActiveByWorkspace(primaryWorkspaceId as any);
    assert.strictEqual(persistedDirect.length, 1);
    assert.strictEqual(persistedDirect[0].id, createdScope.id);
  });
});
