/**
 * Shadow : Helix Nebula (SHN) — Outbox Poller & Background Worker Engine
 *
 * Implements high-throughput, non-blocking outbox polling using PostgreSQL
 * SKIP LOCKED, backpressure controls, and graceful lifecycle draining (0.13 Section 14).
 */

import os from 'node:os';
import crypto from 'node:crypto';
import type { DatabasePool } from '@shn/data-access';
import { OutboxRepository, type OutboxRecord } from '@shn/data-access';
import type { ILogger, ICounter, IGauge, IHistogram } from '@shn/telemetry';
import type { IEventDispatcher } from '../dispatcher/event-dispatcher.js';

export interface OutboxPollerOptions {
  readonly pool: DatabasePool;
  readonly dispatcher: IEventDispatcher;
  readonly workerId?: string | undefined;
  readonly batchSize?: number | undefined;
  readonly pollIntervalMs?: number | undefined;
  readonly maxConcurrency?: number | undefined;
  readonly leaseDurationMs?: number | undefined;
  readonly logger?: ILogger | undefined;
  readonly metrics?: {
    readonly claimedTotal?: ICounter | undefined;
    readonly pendingDepth?: IGauge | undefined;
    readonly oldestAgeSeconds?: IGauge | undefined;
    readonly workerConcurrency?: IGauge | undefined;
    readonly dispatchDuration?: IHistogram | undefined;
  } | undefined;
}

export interface IOutboxPoller {
  start(): void;
  stop(): Promise<void>;
  drain(timeoutMs?: number): Promise<void>;
  pollOnce(): Promise<number>;
  isRunning(): boolean;
  getActiveWorkerCount(): number;
}

export class OutboxPoller implements IOutboxPoller {
  private readonly outboxRepo: OutboxRepository;
  private readonly dispatcher: IEventDispatcher;
  private readonly workerId: string;
  private readonly batchSize: number;
  private readonly pollIntervalMs: number;
  private readonly maxConcurrency: number;
  private readonly leaseDurationMs: number;
  private readonly logger?: ILogger | undefined;
  private readonly metrics?: OutboxPollerOptions['metrics'] | undefined;

  private running: boolean = false;
  private pollTimer?: NodeJS.Timeout | undefined;
  private activeWorkers: number = 0;
  private readonly inFlightPromises = new Set<Promise<unknown>>();
  private lastLeaseRecovery: number = 0;

  constructor(options: OutboxPollerOptions) {
    this.outboxRepo = new OutboxRepository(options.pool);
    this.dispatcher = options.dispatcher;
    this.workerId = options.workerId ?? `${os.hostname()}-poller-${crypto.randomBytes(4).toString('hex')}`;
    this.batchSize = Math.min(Math.max(1, options.batchSize ?? 25), 500);
    this.pollIntervalMs = Math.max(10, options.pollIntervalMs ?? 100);
    this.maxConcurrency = Math.max(1, options.maxConcurrency ?? 10);
    this.leaseDurationMs = Math.max(1000, options.leaseDurationMs ?? 30000);
    this.logger = options.logger;
    this.metrics = options.metrics;
  }

  isRunning(): boolean {
    return this.running;
  }

  getActiveWorkerCount(): number {
    return this.activeWorkers;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.logger?.info('Outbox poller started', {
      worker_id: this.workerId,
      batch_size: this.batchSize,
      poll_interval_ms: this.pollIntervalMs,
      max_concurrency: this.maxConcurrency,
    });
    this.scheduleNextPoll(0);
  }

  private scheduleNextPoll(delayMs: number): void {
    if (!this.running) return;
    this.pollTimer = setTimeout(async () => {
      if (!this.running) return;
      try {
        const claimed = await this.pollOnce();
        if (!this.running) return;
        // If claimed full batch, poll again immediately; otherwise wait configured interval
        const nextDelay = claimed >= this.batchSize ? 0 : this.pollIntervalMs;
        this.scheduleNextPoll(nextDelay);
      } catch (error) {
        if (!this.running) return;
        this.logger?.error('Error in outbox poll cycle', {}, error);
        this.scheduleNextPoll(this.pollIntervalMs);
      }
    }, delayMs);
    if (this.pollTimer && typeof this.pollTimer.unref === 'function') {
      this.pollTimer.unref();
    }
  }

  async pollOnce(): Promise<number> {
    // 1. Backpressure check: do not claim new events if concurrency limit reached
    if (this.activeWorkers >= this.maxConcurrency) {
      this.logger?.debug('Backpressure: active workers at maximum capacity, deferring poll', {
        active: this.activeWorkers,
        max: this.maxConcurrency,
      });
      return 0;
    }

    // 2. Periodic recovery of abandoned/expired leases (every 15 seconds)
    const now = Date.now();
    if (now - this.lastLeaseRecovery > 15000) {
      this.lastLeaseRecovery = now;
      try {
        const recovered = await this.outboxRepo.recoverExpiredLeases();
        if (recovered > 0) {
          this.logger?.warn('Recovered abandoned outbox leases from expired workers', { recovered });
        }
      } catch (err) {
        this.logger?.error('Failed to recover expired leases', {}, err);
      }
    }

    // 3. Atomically claim batch of eligible events using SKIP LOCKED
    const availableSlots = this.maxConcurrency - this.activeWorkers;
    const fetchLimit = Math.min(this.batchSize, availableSlots);

    let claimedRecords: OutboxRecord[] = [];
    try {
      claimedRecords = await this.outboxRepo.claimBatch({
        workerId: this.workerId,
        batchSize: fetchLimit,
        leaseDurationMs: this.leaseDurationMs,
      });
    } catch (err) {
      this.logger?.error('Database error claiming outbox batch', {}, err);
      return 0;
    }

    if (claimedRecords.length === 0) {
      return 0;
    }

    this.metrics?.claimedTotal?.add(claimedRecords.length);

    // 4. Update queue depth metrics
    this.updateQueueDepthMetrics().catch(() => {});

    // 5. Dispatch each claimed event
    const startTime = Date.now();
    for (const record of claimedRecords) {
      const taskPromise = this.processRecord(record);
      this.inFlightPromises.add(taskPromise);
      taskPromise.finally(() => {
        this.inFlightPromises.delete(taskPromise);
      });
    }

    const durationSec = (Date.now() - startTime) / 1000;
    this.metrics?.dispatchDuration?.record(durationSec);

    return claimedRecords.length;
  }

  private async processRecord(record: OutboxRecord): Promise<void> {
    this.activeWorkers++;
    this.metrics?.workerConcurrency?.set(this.activeWorkers);

    try {
      const envelope = typeof record.envelope === 'string'
        ? JSON.parse(record.envelope)
        : record.envelope;

      await this.dispatcher.dispatch(envelope, record.attempt_count);
    } catch (error) {
      this.logger?.error('Unexpected failure during event dispatch', {
        event_id: record.event_id,
      }, error);
    } finally {
      this.activeWorkers = Math.max(0, this.activeWorkers - 1);
      this.metrics?.workerConcurrency?.set(this.activeWorkers);
    }
  }

  private async updateQueueDepthMetrics(): Promise<void> {
    try {
      const depth = await this.outboxRepo.getPendingDepth();
      this.metrics?.pendingDepth?.set(depth.pendingCount);
      this.metrics?.oldestAgeSeconds?.set(depth.oldestAgeSeconds);
    } catch {
      // Metric update failures are non-critical
    }
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = undefined;
    }
    this.logger?.info('Outbox poller stopped');
  }

  async drain(timeoutMs: number = 5000): Promise<void> {
    await this.stop();
    if (this.inFlightPromises.size === 0) return;

    this.logger?.info('Draining in-flight outbox worker tasks...', {
      in_flight: this.inFlightPromises.size,
      timeout_ms: timeoutMs,
    });

    let timer: NodeJS.Timeout | undefined;
    const timeoutPromise = new Promise<void>((resolve) => {
      timer = setTimeout(() => {
        this.logger?.warn('Drain timeout reached with remaining in-flight tasks', {
          remaining: this.inFlightPromises.size,
        });
        resolve();
      }, timeoutMs);
    });

    const allFinished = Promise.all(Array.from(this.inFlightPromises));

    await Promise.race([allFinished, timeoutPromise]).finally(() => {
      if (timer) clearTimeout(timer);
    });

    this.logger?.info('Outbox worker drain completed');
  }
}

export function createOutboxPoller(options: OutboxPollerOptions): IOutboxPoller {
  return new OutboxPoller(options);
}
