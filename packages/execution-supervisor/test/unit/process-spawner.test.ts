import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  buildSanitizedEnvironment,
  validateCommandArguments,
  spawnSandboxedWorker,
} from '../../dist/index.js';

describe('Sandboxed Process Spawner (Unit Tests)', () => {
  describe('Environment Sanitization (SEC-INV-01, INV-14)', () => {
    it('should strip sensitive environment variables and allowlist safe system keys', () => {
      // Simulate dirty host environment
      const originalEnv = { ...process.env };
      try {
        process.env['SHN_AUTH_SIGNING_KEY'] = 'super-secret-auth-key';
        process.env['POSTGRES_PASSWORD'] = 'db-secret-password';
        process.env['DATABASE_URL'] = 'postgres://admin:pass@localhost:5432/db';
        process.env['VAULT_TOKEN'] = 'vt-secret';
        process.env['NODE_OPTIONS'] = '--require /malicious.js';
        process.env['LD_PRELOAD'] = '/malicious.so';
        process.env['SAFE_TEST_VAR'] = 'allowed-maybe';

        const customEnv = {
          SAFE_PARAM: 'user-input',
          SECRET_API_TOKEN: 'should-be-stripped',
          MY_DATABASE_PASS: 'should-be-stripped-too',
          NODE_OPTIONS: '--inspect=0.0.0.0',
        };

        const sanitized = buildSanitizedEnvironment(customEnv, 'exec-123', 'worker-456');

        // Verify sensitive keys are NOT present
        assert.equal(sanitized['SHN_AUTH_SIGNING_KEY'], undefined);
        assert.equal(sanitized['POSTGRES_PASSWORD'], undefined);
        assert.equal(sanitized['DATABASE_URL'], undefined);
        assert.equal(sanitized['VAULT_TOKEN'], undefined);
        assert.equal(sanitized['SECRET_API_TOKEN'], undefined);
        assert.equal(sanitized['MY_DATABASE_PASS'], undefined);
        assert.equal(sanitized['NODE_OPTIONS'], undefined);
        assert.equal(sanitized['LD_PRELOAD'], undefined);

        // Verify custom non-sensitive variable allowed
        assert.equal(sanitized['SAFE_PARAM'], 'user-input');

        // Verify mandatory execution identity injected
        assert.equal(sanitized['SHN_EXECUTION_ID'], 'exec-123');
        assert.equal(sanitized['SHN_WORKER_ID'], 'worker-456');
        assert.equal(sanitized['SHN_SANDBOX'], '1');
      } finally {
        process.env = originalEnv;
      }
    });
  });

  describe('Command & Argument Validation (Command Injection Defenses)', () => {
    it('should reject empty or whitespace-only executable paths', () => {
      assert.equal(validateCommandArguments('', []).isErr, true);
      assert.equal(validateCommandArguments('   ', []).isErr, true);
    });

    it('should reject null-bytes in executable and arguments', () => {
      assert.equal(validateCommandArguments('node\0malicious', []).isErr, true);
      assert.equal(validateCommandArguments('node', ['arg1', 'arg2\0exploit']).isErr, true);
    });

    it('should reject batch script files (.bat, .cmd) fail-closed', () => {
      assert.equal(validateCommandArguments('script.bat', []).isErr, true);
      assert.equal(validateCommandArguments('C:\\tools\\run.CMD', []).isErr, true);
      assert.equal(validateCommandArguments('./exploit.Bat', []).isErr, true);
    });

    it('should reject excessively large arguments (> 64KB)', () => {
      const hugeArg = 'a'.repeat(65 * 1024);
      assert.equal(validateCommandArguments('node', [hugeArg]).isErr, true);
    });

    it('should accept valid commands and arguments', () => {
      const res = validateCommandArguments('node', ['-e', 'console.log("hello")']);
      assert.equal(res.isOk, true);
    });
  });

  describe('Ephemeral Scratch Isolation & Subprocess Execution', () => {
    it('should spawn subprocess in ephemeral directory and clean up on completion', async () => {
      const baseScratchDir = path.join(os.tmpdir(), 'shn-test-scratch-' + Date.now());

      const spawnRes = await spawnSandboxedWorker({
        executable: process.execPath,
        args: ['-e', 'process.stdout.write("hello from worker\n")'],
        baseScratchDir,
        executionId: '01955ef2-2253-7c5e-85a7-d868924ff9cb',
        workerId: 'worker-test-1',
      });

      assert.equal(spawnRes.isOk, true);
      const worker = spawnRes.unwrapOr(null as any);
      assert.ok(worker);
      assert.ok(worker.pid > 0);
      assert.ok(fs.existsSync(worker.scratchDir));

      // Wait for process to exit cleanly
      await new Promise<void>((resolve) => {
        worker.process.on('close', () => resolve());
      });

      // Cleanup scratch directory
      await worker.cleanup();
      assert.equal(fs.existsSync(worker.scratchDir), false);

      // Clean base scratch dir
      try {
        fs.rmSync(baseScratchDir, { recursive: true, force: true });
      } catch {}
    });
  });
});
