/**
 * Shadow : Helix Nebula (SHN) — Execution Repository Integration Tests
 *
 * Validates Migration 005 schema, ExecutionRepository CRUD, state transitions,
 * attempt tracking, artifact registration, worker leases, and multi-tenant hermeticity (INV-01, DATA-INV-08).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  generateUUIDv7,
  generateUUIDv4,
  createExecutionId,
  createOrganizationId,
  createWorkspaceId,
  createUserId,
  type ExecutionId,
  type WorkspaceId,
  type OrganizationId,
  type UserId,
} from '@shn/shared-kernel';
import {
  runMigrations,
  closeDatabasePool,
  type DatabasePool,
  OrganizationRepository,
  WorkspaceRepository,
  UserRepository,
  ExecutionRepository,
} from '../../dist/index.js';
import { createTestPool, resetDatabase, ensureDatabase } from '../test-helper.ts';

describe('ExecutionRepository & Sandboxed Worker Persistence (Integration)', () => {
  let pool: DatabasePool;
  let orgRepo: OrganizationRepository;
  let workspaceRepo: WorkspaceRepository;
  let userRepo: UserRepository;
  let executionRepo: ExecutionRepository;

  let testOrgId: OrganizationId;
  let testWorkspaceId: WorkspaceId;
  let testWorkspaceId2: WorkspaceId;
  let testUserId: UserId;

  before(async () => {
    await ensureDatabase('shn_test_execution_repo');
    pool = createTestPool('shn_test_execution_repo');
    await resetDatabase(pool);
    const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
    await runMigrations(pool, migrationsDir);

    orgRepo = new OrganizationRepository(pool);
    workspaceRepo = new WorkspaceRepository(pool);
    userRepo = new UserRepository(pool);
    executionRepo = new ExecutionRepository(pool);

    // Setup base organization, workspaces, and user
    testOrgId = createOrganizationId(generateUUIDv7()).value;
    await orgRepo.create({
      id: testOrgId,
      name: 'Helix Defense Corp',
      slug: 'helix-defense-' + Math.random().toString(36).substring(2, 8),
    });

    testWorkspaceId = createWorkspaceId(generateUUIDv7()).value;
    await workspaceRepo.create({
      id: testWorkspaceId,
      organization_id: testOrgId,
      name: 'Primary Workspace',
      slug: 'ws-primary-' + Math.random().toString(36).substring(2, 8),
    });

    testWorkspaceId2 = createWorkspaceId(generateUUIDv7()).value;
    await workspaceRepo.create({
      id: testWorkspaceId2,
      organization_id: testOrgId,
      name: 'Secondary Workspace',
      slug: 'ws-secondary-' + Math.random().toString(36).substring(2, 8),
    });

    testUserId = createUserId(generateUUIDv4()).value;
    await userRepo.create({
      id: testUserId,
      organization_id: testOrgId,
      email: 'operator@helix-defense.test',
      display_name: 'Lead Operator',
    });
  });

  after(async () => {
    await closeDatabasePool(pool);
  });

  it('should verify migration 005 created execution tables in execution schema', async () => {
    const res = await pool.query<{ table_name: string }>(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema = 'execution'
       ORDER BY table_name ASC;`
    );
    const tableNames = res.rows.map((r) => r.table_name);
    assert.ok(tableNames.includes('executions'));
    assert.ok(tableNames.includes('execution_attempts'));
    assert.ok(tableNames.includes('execution_artifacts'));
    assert.ok(tableNames.includes('worker_leases'));
  });

  it('should create and retrieve an execution record', async () => {
    const execId = createExecutionId(generateUUIDv7()).value;
    const record = await executionRepo.createExecution({
      id: execId,
      workspace_id: testWorkspaceId,
      organization_id: testOrgId,
      action: 'scan',
      target: '192.168.1.1',
      capability_uri: 'urn:shn:tool:nmap',
      state: 'AUTHORIZED',
      requested_by: testUserId,
      command: { executable: 'nmap', args: ['-sS', '192.168.1.1'] },
      resource_policy: { timeoutMs: 30000 },
      execution_policy: { failOnNonZeroExit: true },
    });

    assert.equal(record.id, execId);
    assert.equal(record.workspace_id, testWorkspaceId);
    assert.equal(record.organization_id, testOrgId);
    assert.equal(record.action, 'scan');
    assert.equal(record.target, '192.168.1.1');
    assert.equal(record.capability_uri, 'urn:shn:tool:nmap');
    assert.equal(record.state, 'AUTHORIZED');
    assert.equal(record.version, 1);

    const fetched = await executionRepo.findById(execId, testWorkspaceId);
    assert.ok(fetched);
    assert.equal(fetched.id, execId);
    assert.equal(fetched.state, 'AUTHORIZED');
  });

  it('should strictly enforce multi-tenant workspace hermeticity on findById', async () => {
    const execId = createExecutionId(generateUUIDv7()).value;
    await executionRepo.createExecution({
      id: execId,
      workspace_id: testWorkspaceId,
      organization_id: testOrgId,
      action: 'probe',
      target: '10.0.0.1',
      capability_uri: 'urn:shn:tool:ping',
      state: 'AUTHORIZED',
      requested_by: testUserId,
      command: { executable: 'ping', args: ['-c', '1', '10.0.0.1'] },
    });

    // Querying with another workspace must return null fail-closed
    const unauthorizedQuery = await executionRepo.findById(execId, testWorkspaceId2);
    assert.equal(unauthorizedQuery, null);
  });

  it('should deterministically transition execution states and increment versions', async () => {
    const execId = createExecutionId(generateUUIDv7()).value;
    await executionRepo.createExecution({
      id: execId,
      workspace_id: testWorkspaceId,
      organization_id: testOrgId,
      action: 'recon',
      target: 'example.com',
      capability_uri: 'urn:shn:tool:dns',
      state: 'AUTHORIZED',
      requested_by: testUserId,
      command: { executable: 'dig', args: ['example.com'] },
    });

    // AUTHORIZED -> STARTING
    const started = await executionRepo.transitionState(
      execId,
      testWorkspaceId,
      'AUTHORIZED',
      'STARTING'
    );
    assert.ok(started);
    assert.equal(started.state, 'STARTING');
    assert.equal(started.version, 2);

    // STARTING -> RUNNING
    const running = await executionRepo.transitionState(
      execId,
      testWorkspaceId,
      'STARTING',
      'RUNNING'
    );
    assert.ok(running);
    assert.equal(running.state, 'RUNNING');
    assert.equal(running.version, 3);

    // RUNNING -> SUCCEEDED with result payload
    const succeeded = await executionRepo.transitionState(
      execId,
      testWorkspaceId,
      'RUNNING',
      'SUCCEEDED',
      {
        result_payload: { output: 'success' },
        stdout_summary: 'DNS lookup complete',
        completed_at: new Date().toISOString(),
      }
    );
    assert.ok(succeeded);
    assert.equal(succeeded.state, 'SUCCEEDED');
    assert.equal(succeeded.version, 4);
    assert.deepEqual(succeeded.result_payload, { output: 'success' });
    assert.equal(succeeded.stdout_summary, 'DNS lookup complete');
  });

  it('should reject invalid state transitions when current state does not match', async () => {
    const execId = createExecutionId(generateUUIDv7()).value;
    await executionRepo.createExecution({
      id: execId,
      workspace_id: testWorkspaceId,
      organization_id: testOrgId,
      action: 'recon',
      target: 'test.local',
      capability_uri: 'urn:shn:tool:whois',
      state: 'AUTHORIZED',
      requested_by: testUserId,
      command: { executable: 'whois', args: ['test.local'] },
    });

    // Attempt invalid transition: expecting 'RUNNING', but current is 'AUTHORIZED'
    const failedTransition = await executionRepo.transitionState(
      execId,
      testWorkspaceId,
      'RUNNING',
      'SUCCEEDED'
    );
    assert.equal(failedTransition, null);

    // Verify state remained unchanged
    const current = await executionRepo.findById(execId, testWorkspaceId);
    assert.ok(current);
    assert.equal(current.state, 'AUTHORIZED');
    assert.equal(current.version, 1);
  });

  it('should record execution attempts and list them', async () => {
    const execId = createExecutionId(generateUUIDv7()).value;
    await executionRepo.createExecution({
      id: execId,
      workspace_id: testWorkspaceId,
      organization_id: testOrgId,
      action: 'scan',
      target: '192.168.1.100',
      capability_uri: 'urn:shn:tool:nmap',
      state: 'AUTHORIZED',
      requested_by: testUserId,
      command: { executable: 'nmap', args: ['192.168.1.100'] },
    });

    const attempt = await executionRepo.recordAttempt({
      execution_id: execId,
      workspace_id: testWorkspaceId,
      worker_id: 'worker-node-1',
      state: 'SUCCEEDED',
      exit_code: 0,
      termination_reason: 'NORMAL_EXIT',
      duration_ms: 1250,
    });

    assert.ok(attempt.id);
    assert.equal(attempt.execution_id, execId);
    assert.equal(attempt.attempt_number, 1);
    assert.equal(attempt.worker_id, 'worker-node-1');
    assert.equal(attempt.exit_code, 0);
    assert.equal(attempt.duration_ms, 1250);

    const attempts = await executionRepo.listAttempts(execId, testWorkspaceId);
    assert.equal(attempts.length, 1);
    assert.equal(attempts[0]!.worker_id, 'worker-node-1');
  });

  it('should register artifacts and list them with multi-tenant filtering', async () => {
    const execId = createExecutionId(generateUUIDv7()).value;
    await executionRepo.createExecution({
      id: execId,
      workspace_id: testWorkspaceId,
      organization_id: testOrgId,
      action: 'scan',
      target: '10.10.10.1',
      capability_uri: 'urn:shn:tool:nmap',
      state: 'RUNNING',
      requested_by: testUserId,
      command: { executable: 'nmap', args: ['10.10.10.1'] },
    });

    const artifact = await executionRepo.createArtifact({
      execution_id: execId,
      workspace_id: testWorkspaceId,
      name: 'scan-output.xml',
      content_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      storage_uri: 'blob://evidence/scan-output.xml',
      byte_size: 4096,
      mime_type: 'application/xml',
    });

    assert.ok(artifact.id);
    assert.equal(artifact.name, 'scan-output.xml');
    assert.equal(artifact.byte_size, 4096);

    const list = await executionRepo.listArtifacts(execId, testWorkspaceId);
    assert.equal(list.length, 1);
    assert.equal(list[0]!.name, 'scan-output.xml');

    // Cross-workspace query returns empty array
    const crossList = await executionRepo.listArtifacts(execId, testWorkspaceId2);
    assert.equal(crossList.length, 0);
  });

  it('should manage worker leases, heartbeats, renewal, and reaping', async () => {
    const workerId = 'worker-' + Math.random().toString(36).substring(2, 10);
    const execId = createExecutionId(generateUUIDv7()).value;

    await executionRepo.createExecution({
      id: execId,
      workspace_id: testWorkspaceId,
      organization_id: testOrgId,
      action: 'probe',
      target: 'target.local',
      capability_uri: 'urn:shn:tool:test',
      state: 'AUTHORIZED',
      requested_by: testUserId,
      command: { executable: 'echo', args: ['test'] },
    });

    // 1. Acquire lease
    const acquired = await executionRepo.acquireWorkerLease(
      workerId,
      execId,
      testWorkspaceId,
      10_000
    );
    assert.equal(acquired, true);

    // 2. Heartbeat / renew lease
    const renewed = await executionRepo.heartbeatWorker(workerId, 15_000);
    assert.equal(renewed, true);

    // 3. Release lease
    await executionRepo.releaseWorkerLease(workerId);

    // 4. Test lease reaping on expired lease
    const worker2 = 'worker-expired-' + Math.random().toString(36).substring(2, 10);
    await executionRepo.acquireWorkerLease(
      worker2,
      execId,
      testWorkspaceId,
      -5_000 // already expired in the past
    );

    const reaped = await executionRepo.reapExpiredLeases(new Date());
    assert.ok(reaped >= 1);
  });
});
