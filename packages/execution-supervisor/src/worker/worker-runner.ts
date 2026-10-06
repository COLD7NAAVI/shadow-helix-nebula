/**
 * Shadow : Helix Nebula (SHN) — Sandboxed Worker Runner
 *
 * Runs inside the untrusted worker subprocess.
 * Communicates strictly via line-delimited JSON over stdio pipes.
 * Invariant INV-14: Zero database credentials, zero control plane secrets.
 */

import readline from 'node:readline';
import process from 'node:process';
import {
  encodeProtocolMessage,
  decodeSupervisorMessage,
} from '../protocol/codec.js';
import type {
  WorkerToSupervisorMessage,
  SupervisorInitMessage,
} from '../protocol/messages.js';

export interface WorkerTaskHandler {
  (
    init: SupervisorInitMessage,
    emitOutput: (stream: 'stdout' | 'stderr', data: string) => void,
    abortSignal: AbortSignal
  ): Promise<{ exitCode: number; payload?: unknown }>;
}

export class SandboxedWorkerRunner {
  private readonly workerId: string;
  private readonly handler?: WorkerTaskHandler | undefined;
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private readonly abortController = new AbortController();
  private rl: readline.Interface | null = null;

  constructor(workerId?: string, handler?: WorkerTaskHandler) {
    this.workerId =
      workerId ||
      process.env['SHN_WORKER_ID'] ||
      'worker-standalone-' + Math.random().toString(16).substring(2, 10);
    this.handler = handler;
  }

  start(): void {
    // 1. Send STARTUP message
    this.sendMessage({
      type: 'STARTUP',
      version: '1.0',
      workerId: this.workerId,
    });

    // 2. Start heartbeat
    this.heartbeatInterval = setInterval(() => {
      const memory = process.memoryUsage();
      this.sendMessage({
        type: 'HEARTBEAT',
        workerId: this.workerId,
        timestamp: new Date().toISOString(),
        metrics: {
          memoryRssBytes: memory.rss,
        },
      });
    }, 2000);

    // 3. Listen for supervisor messages on stdin
    this.rl = readline.createInterface({
      input: process.stdin,
      terminal: false,
    });

    this.rl.on('line', (line) => {
      this.handleSupervisorLine(line);
    });

    this.rl.on('close', () => {
      this.stop();
    });
  }

  stop(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
    if (this.rl) {
      this.rl.close();
      this.rl = null;
    }
  }

  private handleSupervisorLine(line: string): void {
    const res = decodeSupervisorMessage(line);
    if (res.isErr) {
      this.sendMessage({
        type: 'FAILED',
        error: `Supervisor message decode failed: ${res.error}`,
      });
      return;
    }

    const msg = res.value;
    switch (msg.type) {
      case 'INIT':
        this.runTask(msg);
        break;

      case 'CANCEL':
        this.abortController.abort(msg.reason);
        break;

      case 'TERMINATE':
        this.stop();
        process.exit(1);
        break;
    }
  }

  private async runTask(init: SupervisorInitMessage): Promise<void> {
    const emitOutput = (stream: 'stdout' | 'stderr', data: string) => {
      this.sendMessage({
        type: 'OUTPUT',
        stream,
        data,
      });
    };

    try {
      if (!this.handler) {
        // Default echo / noop handler
        emitOutput('stdout', `Worker ${this.workerId} executed target ${init.target} for action ${init.action}\n`);
        this.sendMessage({
          type: 'COMPLETED',
          exitCode: 0,
          payload: { target: init.target, action: init.action, status: 'DONE' },
        });
        return;
      }

      const res = await this.handler(init, emitOutput, this.abortController.signal);
      this.sendMessage({
        type: 'COMPLETED',
        exitCode: res.exitCode,
        payload: res.payload,
      });
    } catch (e: any) {
      this.sendMessage({
        type: 'FAILED',
        error: e instanceof Error ? e.message : String(e),
        details: e?.stack,
      });
    } finally {
      this.stop();
    }
  }

  private sendMessage(msg: WorkerToSupervisorMessage): void {
    const serialized = encodeProtocolMessage(msg);
    process.stdout.write(serialized);
  }
}
