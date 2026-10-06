import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { setupSupervisorTestEnv, type SupervisorTestEnvironment } from './supervisor-test-helper.ts';

describe('Timeouts, Cancellation & Escalation (Integration)', () => {
  let env: SupervisorTestEnvironment;

  before(async () => {
    env = await setupSupervisorTestEnv('shn_test_supervisor_timeouts');
  });

  after(async () => {
    await env.cleanup();
  });

  it('should terminate worker and record TIMED_OUT when wall-clock ceiling is exceeded', async () => {
    const req = env.createRequest({
      command: {
        executable: process.execPath,
        args: [
          '-e',
          'setTimeout(() => { process.stdout.write("should not reach\\n"); }, 10000);',
        ],
      },
      resourceLimits: {
        timeoutMs: 400, // 400ms wall-clock ceiling
        startupTimeoutMs: 5000,
      },
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isOk, true);

    const result = res.unwrapOr(null as any);
    assert.equal(result.state, 'TIMED_OUT');
    assert.equal(result.terminationReason, 'TIMEOUT_WALL_CLOCK');
    assert.ok(result.failure);
    assert.equal(result.failure.terminationReason, 'TIMEOUT_WALL_CLOCK');
    assert.ok(result.telemetry.durationMs >= 350);

    // Verify DB record
    const dbRecord = await env.executionRepo.findById(result.executionId, env.workspaceId);
    assert.ok(dbRecord);
    assert.equal(dbRecord.state, 'TIMED_OUT');
  });

  it('should terminate worker and record TIMED_OUT when startup ceiling is breached', async () => {
    const req = env.createRequest({
      command: {
        executable: process.execPath,
        args: [
          '-e',
          'setTimeout(() => { process.stdout.write("delayed hello\\n"); }, 5000);',
        ],
      },
      resourceLimits: {
        timeoutMs: 10000,
        startupTimeoutMs: 300, // 300ms startup ceiling
      },
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isOk, true);

    const result = res.unwrapOr(null as any);
    assert.equal(result.state, 'TIMED_OUT');
    assert.equal(result.terminationReason, 'TIMEOUT_STARTUP');
    assert.ok(result.failure);
    assert.equal(result.failure.terminationReason, 'TIMEOUT_STARTUP');
  });

  it('should cancel active execution by specific ID and transition to CANCELLED', async () => {
    const customExecId = '01955ef2-2253-7c5e-85a7-d868924ff9cb' as any;
    const req = env.createRequest({
      id: customExecId,
      command: {
        executable: process.execPath,
        args: [
          '-e',
          'process.stdout.write("active\\n"); setInterval(() => {}, 1000);',
        ],
      },
      resourceLimits: {
        timeoutMs: 10000,
        startupTimeoutMs: 5000,
      },
    });

    const executePromise = env.supervisor.execute(req);

    // Wait for spawn
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Cancel execution
    const cancelRes = await env.supervisor.cancelExecution({
      executionId: customExecId,
      workspaceId: env.workspaceId,
      reason: 'Automated test operator cancellation',
    });
    assert.equal(cancelRes.isOk, true);

    const execRes = await executePromise;
    assert.equal(execRes.isOk, true);
    const result = execRes.unwrapOr(null as any);
    assert.equal(result.state, 'CANCELLED');
    assert.equal(result.terminationReason, 'OPERATOR_CANCELLED');

    // DB record should be CANCELLED
    const dbRecord = await env.executionRepo.findById(customExecId, env.workspaceId);
    assert.ok(dbRecord);
    assert.equal(dbRecord.state, 'CANCELLED');
  });

  it('should terminate worker when output byte limit is breached and failOnOutputLimit is true', async () => {
    const req = env.createRequest({
      command: {
        executable: process.execPath,
        args: [
          '-e',
          'for (let i = 0; i < 500; i++) { process.stdout.write("A".repeat(1000) + "\\n"); }',
        ],
      },
      resourceLimits: {
        timeoutMs: 10000,
        startupTimeoutMs: 5000,
        maxStdoutBytes: 5000, // 5KB limit
      },
      executionPolicy: {
        failOnOutputLimit: true,
      },
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isOk, true);

    const result = res.unwrapOr(null as any);
    assert.equal(result.state, 'FAILED');
    assert.equal(result.terminationReason, 'OUTPUT_LIMIT_EXCEEDED');
    assert.equal(result.stdoutTruncated, true);
    assert.ok(result.telemetry.stdoutBytes > 5000);
  });

  it('should record FAILED state with PROCESS_CRASH on non-zero exit code', async () => {
    const req = env.createRequest({
      command: {
        executable: process.execPath,
        args: [
          '-e',
          'process.stderr.write("Fatal syntax error in scanner\\n"); process.exit(42);',
        ],
      },
      executionPolicy: {
        failOnNonZeroExit: true,
      },
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isOk, true);

    const result = res.unwrapOr(null as any);
    assert.equal(result.state, 'FAILED');
    assert.equal(result.exitCode, 42);
    assert.equal(result.terminationReason, 'PROCESS_CRASH');
    assert.ok(result.stderr.includes('Fatal syntax error'));
  });
});
