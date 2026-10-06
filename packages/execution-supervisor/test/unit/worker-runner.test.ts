import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import {
  SandboxedWorkerRunner,
  decodeWorkerMessage,
  encodeProtocolMessage,
  type WorkerTaskHandler,
} from '../../dist/index.js';

describe('Sandboxed Worker Runner (Unit Tests)', () => {
  it('should initialize, emit STARTUP message, and handle task execution', async () => {
    const originalStdin = process.stdin;
    const originalStdoutWrite = process.stdout.write;

    const mockStdin = new PassThrough();
    const emittedLines: string[] = [];

    // Intercept only JSON protocol messages so test runner output is preserved
    process.stdout.write = ((chunk: any, encoding?: any, cb?: any) => {
      const str = chunk.toString();
      if (str.startsWith('{') && str.includes('"type"')) {
        emittedLines.push(str);
        if (typeof encoding === 'function') encoding();
        else if (typeof cb === 'function') cb();
        return true;
      }
      return originalStdoutWrite.call(process.stdout, chunk, encoding, cb);
    }) as any;

    Object.defineProperty(process, 'stdin', {
      value: mockStdin,
      configurable: true,
    });

    const handler: WorkerTaskHandler = async (init, emitOutput) => {
      emitOutput('stdout', `Running ${init.action} on ${init.target}\n`);
      return {
        exitCode: 0,
        payload: { scanned: true, host: init.target },
      };
    };

    const runner = new SandboxedWorkerRunner('test-worker-1', handler);

    try {
      runner.start();

      // Verify STARTUP message emitted
      assert.ok(emittedLines.length >= 1);
      const startup = decodeWorkerMessage(emittedLines[0]!);
      assert.equal(startup.isOk, true);
      assert.equal(startup.unwrapOr(null as any).type, 'STARTUP');

      // Send INIT message via mock stdin
      const initMsg = encodeProtocolMessage({
        type: 'INIT',
        version: '1.0',
        executionId: '01955ef2-2253-7c5e-85a7-d868924ff9cb',
        target: '192.168.1.50',
        action: 'scan',
        payload: {},
      });
      mockStdin.write(initMsg);

      // Wait a tick for async handler to run
      await new Promise((resolve) => setTimeout(resolve, 50));

      // Verify OUTPUT and COMPLETED messages
      const outputMsg = emittedLines.find((l) => l.includes('"type":"OUTPUT"'));
      assert.ok(outputMsg, 'Expected OUTPUT message');
      const decOutput = decodeWorkerMessage(outputMsg);
      assert.equal(decOutput.isOk, true);
      assert.ok(decOutput.unwrapOr(null as any).data.includes('192.168.1.50'));

      const completedMsg = emittedLines.find((l) => l.includes('"type":"COMPLETED"'));
      assert.ok(completedMsg, 'Expected COMPLETED message');
      const decCompleted = decodeWorkerMessage(completedMsg);
      assert.equal(decCompleted.isOk, true);
      assert.equal(decCompleted.unwrapOr(null as any).exitCode, 0);
      assert.deepEqual(decCompleted.unwrapOr(null as any).payload, { scanned: true, host: '192.168.1.50' });
    } finally {
      runner.stop();
      process.stdout.write = originalStdoutWrite;
      Object.defineProperty(process, 'stdin', {
        value: originalStdin,
        configurable: true,
      });
    }
  });

  it('should propagate cancellation to abortSignal when CANCEL received', async () => {
    const originalStdin = process.stdin;
    const originalStdoutWrite = process.stdout.write;
    const mockStdin = new PassThrough();
    const emittedLines: string[] = [];

    process.stdout.write = ((chunk: any, encoding?: any, cb?: any) => {
      const str = chunk.toString();
      if (str.startsWith('{') && str.includes('"type"')) {
        emittedLines.push(str);
        if (typeof encoding === 'function') encoding();
        else if (typeof cb === 'function') cb();
        return true;
      }
      return originalStdoutWrite.call(process.stdout, chunk, encoding, cb);
    }) as any;

    Object.defineProperty(process, 'stdin', {
      value: mockStdin,
      configurable: true,
    });

    let abortObserved = false;
    const handler: WorkerTaskHandler = async (_init, _emitOutput, abortSignal) => {
      await new Promise<void>((resolve) => {
        abortSignal.addEventListener('abort', () => {
          abortObserved = true;
          resolve();
        });
      });
      return { exitCode: 130 };
    };

    const runner = new SandboxedWorkerRunner('test-worker-cancel', handler);

    try {
      runner.start();

      // Send INIT
      mockStdin.write(
        encodeProtocolMessage({
          type: 'INIT',
          version: '1.0',
          executionId: 'exec-cancel-1',
          target: '10.0.0.1',
          action: 'probe',
        })
      );

      await new Promise((resolve) => setTimeout(resolve, 20));

      // Send CANCEL
      mockStdin.write(
        encodeProtocolMessage({
          type: 'CANCEL',
          reason: 'User aborted',
          gracePeriodMs: 1000,
        })
      );

      await new Promise((resolve) => setTimeout(resolve, 50));
      assert.equal(abortObserved, true);
    } finally {
      runner.stop();
      process.stdout.write = originalStdoutWrite;
      Object.defineProperty(process, 'stdin', {
        value: originalStdin,
        configurable: true,
      });
    }
  });

  it('should emit FAILED message if worker task throws an uncaught error', async () => {
    const originalStdin = process.stdin;
    const originalStdoutWrite = process.stdout.write;
    const mockStdin = new PassThrough();
    const emittedLines: string[] = [];

    process.stdout.write = ((chunk: any, encoding?: any, cb?: any) => {
      const str = chunk.toString();
      if (str.startsWith('{') && str.includes('"type"')) {
        emittedLines.push(str);
        if (typeof encoding === 'function') encoding();
        else if (typeof cb === 'function') cb();
        return true;
      }
      return originalStdoutWrite.call(process.stdout, chunk, encoding, cb);
    }) as any;

    Object.defineProperty(process, 'stdin', {
      value: mockStdin,
      configurable: true,
    });

    const handler: WorkerTaskHandler = async () => {
      throw new Error('Explosion in tool binary simulation');
    };

    const runner = new SandboxedWorkerRunner('test-worker-fail', handler);

    try {
      runner.start();

      mockStdin.write(
        encodeProtocolMessage({
          type: 'INIT',
          version: '1.0',
          executionId: 'exec-fail-1',
          target: 'bad-target',
          action: 'scan',
        })
      );

      await new Promise((resolve) => setTimeout(resolve, 50));

      const failedMsg = emittedLines.find((l) => l.includes('"type":"FAILED"'));
      assert.ok(failedMsg, 'Expected FAILED message');
      const decFailed = decodeWorkerMessage(failedMsg);
      assert.equal(decFailed.isOk, true);
      assert.ok(decFailed.unwrapOr(null as any).error.includes('Explosion in tool binary'));
    } finally {
      runner.stop();
      process.stdout.write = originalStdoutWrite;
      Object.defineProperty(process, 'stdin', {
        value: originalStdin,
        configurable: true,
      });
    }
  });
});
