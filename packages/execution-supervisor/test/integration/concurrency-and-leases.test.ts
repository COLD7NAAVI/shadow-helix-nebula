import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { setupSupervisorTestEnv, type SupervisorTestEnvironment } from './supervisor-test-helper.ts';
import { ExecutionSupervisor } from '../../dist/index.js';

describe('Concurrency Limits & Worker Leases (Integration)', () => {
  let env: SupervisorTestEnvironment;

  before(async () => {
    env = await setupSupervisorTestEnv('shn_test_supervisor_concurrency');
  });

  after(async () => {
    await env.cleanup();
  });

  it('should enforce maxConcurrentExecutions ceiling and reject overflow fail-closed', async () => {
    // Supervisor with strict concurrency ceiling = 2
    const strictSupervisor = new ExecutionSupervisor({
      gatekeeper: env.gatekeeper,
      executionRepo: env.executionRepo,
      authSigner: env.authSigner,
      tenancyValidator: env.tenancyValidator,
      maxConcurrentExecutions: 2,
    });

    const sleepScript = 'setInterval(() => {}, 100);';

    // Spawn 1st concurrent execution
    const p1 = strictSupervisor.execute(
      env.createRequest({
        command: { executable: process.execPath, args: ['-e', sleepScript] },
        resourceLimits: { timeoutMs: 1500 },
      })
    );

    // Spawn 2nd concurrent execution
    const p2 = strictSupervisor.execute(
      env.createRequest({
        command: { executable: process.execPath, args: ['-e', sleepScript] },
        resourceLimits: { timeoutMs: 1500 },
      })
    );

    // Give them a moment to spawn and become active
    await new Promise((resolve) => setTimeout(resolve, 80));

    // Attempt 3rd execution (exceeds maxConcurrentExecutions = 2)
    const p3 = await strictSupervisor.execute(
      env.createRequest({
        command: { executable: process.execPath, args: ['-e', 'process.exit(0);'] },
      })
    );

    // 3rd request must be rejected immediately with ERR_EXEC_RESOURCE_EXHAUSTED
    assert.equal(p3.isErr, true);
    assert.equal(p3.error.error_code, 'ERR_EXEC_RESOURCE_EXHAUSTED');
    assert.ok(p3.error.detail?.includes('Maximum active sandboxed executions limit reached'));

    // Wait for the 2 active tasks to finish via their timeout
    const [r1, r2] = await Promise.all([p1, p2]);
    assert.equal(r1.isOk, true);
    assert.equal(r2.isOk, true);

    // Now that slot is freed, subsequent execution succeeds
    const p4 = await strictSupervisor.execute(
      env.createRequest({
        command: { executable: process.execPath, args: ['-e', 'process.stdout.write("slot freed\\n");'] },
      })
    );
    assert.equal(p4.isOk, true);
    assert.equal(p4.unwrapOr(null as any).state, 'SUCCEEDED');
  });

  it('should support concurrent worker leases without conflict or deadlock', async () => {
    const worker1 = 'worker-conc-1-' + Date.now();
    const worker2 = 'worker-conc-2-' + Date.now();

    const rec1 = await env.executionRepo.createExecution({
      workspace_id: env.workspaceId,
      organization_id: env.orgId,
      action: 'probe',
      target: '192.168.1.1',
      capability_uri: 'urn:shn:tool:ping',
      requested_by: env.userId,
      command: { executable: 'ping', args: [] },
    });

    const rec2 = await env.executionRepo.createExecution({
      workspace_id: env.workspaceId,
      organization_id: env.orgId,
      action: 'probe',
      target: '192.168.1.2',
      capability_uri: 'urn:shn:tool:ping',
      requested_by: env.userId,
      command: { executable: 'ping', args: [] },
    });

    const [lease1, lease2] = await Promise.all([
      env.executionRepo.acquireWorkerLease(worker1, rec1.id, env.workspaceId, 10000),
      env.executionRepo.acquireWorkerLease(worker2, rec2.id, env.workspaceId, 10000),
    ]);

    assert.equal(lease1, true);
    assert.equal(lease2, true);

    // Heartbeat both concurrently
    const [hb1, hb2] = await Promise.all([
      env.executionRepo.heartbeatWorker(worker1),
      env.executionRepo.heartbeatWorker(worker2),
    ]);

    assert.equal(hb1, true);
    assert.equal(hb2, true);

    // Release both
    await Promise.all([
      env.executionRepo.releaseWorkerLease(worker1),
      env.executionRepo.releaseWorkerLease(worker2),
    ]);
  });
});
