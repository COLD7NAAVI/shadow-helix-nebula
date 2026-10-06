import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { setupSupervisorTestEnv, type SupervisorTestEnvironment } from './supervisor-test-helper.ts';

describe('Execution Supervisor Lifecycle (Integration)', () => {
  let env: SupervisorTestEnvironment;

  before(async () => {
    env = await setupSupervisorTestEnv('shn_test_supervisor_lifecycle');
  });

  after(async () => {
    await env.cleanup();
  });

  it('should execute sandboxed command to completion and record state in DB', async () => {
    const req = env.createRequest({
      command: {
        executable: process.execPath,
        args: [
          '-e',
          'process.stdout.write("Discovered open port 80 on target\\n"); process.stderr.write("info: scan complete\\n");',
        ],
      },
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isOk, true);

    const execResult = res.unwrapOr(null as any);
    assert.ok(execResult);
    assert.equal(execResult.state, 'SUCCEEDED');
    assert.equal(execResult.exitCode, 0);
    assert.equal(execResult.terminationReason, 'NORMAL_EXIT');
    assert.ok(execResult.stdout.includes('Discovered open port 80'));
    assert.ok(execResult.stderr.includes('info: scan complete'));
    assert.equal(execResult.stdoutTruncated, false);
    assert.ok(execResult.outputSha256.length === 64);
    assert.ok(execResult.telemetry.durationMs >= 0);

    // Verify persistence record in database
    const dbRecord = await env.executionRepo.findById(execResult.executionId, env.workspaceId);
    assert.ok(dbRecord);
    assert.equal(dbRecord.state, 'SUCCEEDED');
    assert.equal(dbRecord.raw_output_sha256, execResult.outputSha256);
    assert.ok(dbRecord.stdout_summary?.includes('Discovered open port 80'));

    // Verify attempt recorded
    const attempts = await env.executionRepo.listAttempts(execResult.executionId, env.workspaceId);
    assert.equal(attempts.length, 1);
    assert.equal(attempts[0]!.state, 'SUCCEEDED');
    assert.equal(attempts[0]!.exit_code, 0);
  });

  it('should execute protocol-compliant worker script and capture result payload', async () => {
    // Worker script speaks line-delimited JSON protocol
    const workerScript = `
      const readline = require('readline');
      process.stdout.write(JSON.stringify({ type: 'STARTUP', version: '1.0', workerId: 'worker-script-1' }) + '\\n');
      const rl = readline.createInterface({ input: process.stdin, terminal: false });
      rl.on('line', (line) => {
        const msg = JSON.parse(line);
        if (msg.type === 'INIT') {
          process.stdout.write(JSON.stringify({
            type: 'COMPLETED',
            exitCode: 0,
            payload: { host: msg.target, status: 'VULNERABLE', cve: 'CVE-2026-0001' }
          }) + '\\n');
          process.exit(0);
        }
      });
    `;

    const req = env.createRequest({
      command: {
        executable: process.execPath,
        args: ['-e', workerScript],
      },
    });

    const res = await env.supervisor.execute(req);
    assert.equal(res.isOk, true);

    const execResult = res.unwrapOr(null as any);
    assert.equal(execResult.state, 'SUCCEEDED');
    assert.deepEqual(execResult.payload, {
      host: req.target,
      status: 'VULNERABLE',
      cve: 'CVE-2026-0001',
    });

    // Check retrieved execution via getExecution
    const fetched = await env.supervisor.getExecution(execResult.executionId, env.workspaceId);
    assert.equal(fetched.isOk, true);
    assert.deepEqual(fetched.unwrapOr(null as any).payload, {
      host: req.target,
      status: 'VULNERABLE',
      cve: 'CVE-2026-0001',
    });
  });

  it('should query execution by ID and enforce multi-tenant isolation', async () => {
    const req = env.createRequest();
    const res = await env.supervisor.execute(req);
    assert.equal(res.isOk, true);
    const execId = res.unwrapOr(null as any).executionId;

    // Same workspace queries successfully
    const successQuery = await env.supervisor.getExecution(execId, env.workspaceId);
    assert.equal(successQuery.isOk, true);

    // Cross-workspace query returns error STORAGE_NOT_FOUND fail-closed
    const deniedQuery = await env.supervisor.getExecution(execId, env.otherWorkspaceId);
    assert.equal(deniedQuery.isErr, true);
    assert.equal(deniedQuery.error.error_code, 'ERR_STORAGE_NOT_FOUND');
  });
});
