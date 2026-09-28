/**
 * Shadow : Helix Nebula (SHN) — Event Substrate Facade & Lifecycle Manager
 *
 * Assembles and coordinates Event Registry, Publisher, In-Process Bus,
 * Outbox Poller, Dispatcher, and Replay Manager into a unified substrate.
 */

import { type DatabasePool, OutboxRepository } from '@shn/data-access';
import type { ILogger, ITelemetryProvider, ComponentHealth } from '@shn/telemetry';
import { nowIso } from '@shn/shared-kernel';
import { type EventBusConfig } from '../config/event-bus-config.js';
import { type IEventRegistry, createEventRegistry } from '../registry/event-registry.js';
import { type IEventPublisher, createEventPublisher } from '../publisher/event-publisher.js';
import { type IInProcessEventBus, createInProcessEventBus } from '../in-process/in-process-bus.js';
import { type IEventDispatcher, createEventDispatcher } from '../dispatcher/event-dispatcher.js';
import { type IOutboxPoller, createOutboxPoller } from '../outbox/outbox-poller.js';
import { type IReplayManager, createReplayManager } from '../dead-letter/replay-manager.js';

export interface EventBusSubstrateOptions {
  readonly pool: DatabasePool;
  readonly config: EventBusConfig;
  readonly telemetry?: ITelemetryProvider | undefined;
  readonly workerId?: string | undefined;
}

export interface IEventBusSubstrate {
  readonly registry: IEventRegistry;
  readonly publisher: IEventPublisher;
  readonly inProcess: IInProcessEventBus;
  readonly poller: IOutboxPoller;
  readonly replayManager: IReplayManager;
  readonly dispatcher: IEventDispatcher;
  start(): void;
  stop(): Promise<void>;
  drain(timeoutMs?: number): Promise<void>;
  isRunning(): boolean;
  healthCheck(): Promise<ComponentHealth>;
}

export class EventBusSubstrate implements IEventBusSubstrate {
  readonly registry: IEventRegistry;
  readonly publisher: IEventPublisher;
  readonly inProcess: IInProcessEventBus;
  readonly poller: IOutboxPoller;
  readonly replayManager: IReplayManager;
  readonly dispatcher: IEventDispatcher;

  private readonly pool: DatabasePool;
  private readonly config: EventBusConfig;
  private readonly logger?: ILogger | undefined;
  private started: boolean = false;

  constructor(options: EventBusSubstrateOptions) {
    this.pool = options.pool;
    this.config = options.config;
    this.logger = options.telemetry?.logger.child('event-bus');

    this.registry = createEventRegistry();

    this.publisher = createEventPublisher({
      pool: this.pool,
      logger: this.logger,
      publishedMetric: options.telemetry?.standardMetrics.eventsPublishedTotal,
    });

    this.inProcess = createInProcessEventBus(this.logger);

    this.dispatcher = createEventDispatcher({
      db: this.pool,
      registry: this.registry,
      deduplicationTtlHours: this.config.deduplicationTtlHours,
      retryPolicy: {
        maxAttempts: this.config.maxAttempts,
        initialDelayMs: this.config.initialRetryDelayMs,
        multiplier: this.config.retryMultiplier,
        maxDelayMs: this.config.maxRetryDelayMs,
        jitter: this.config.retryJitter,
      },
      logger: this.logger,
      metrics: options.telemetry ? {
        dispatchedTotal: options.telemetry.standardMetrics.eventsDispatchedTotal,
        retriedTotal: options.telemetry.standardMetrics.eventsRetriedTotal,
        deadLetterTotal: options.telemetry.standardMetrics.eventsDeadLetterTotal,
        handlerDurationSeconds: options.telemetry.standardMetrics.handlerDurationSeconds,
      } : undefined,
    });

    this.poller = createOutboxPoller({
      pool: this.pool,
      dispatcher: this.dispatcher,
      workerId: options.workerId,
      batchSize: this.config.batchSize,
      pollIntervalMs: this.config.pollingIntervalMs,
      maxConcurrency: this.config.maxConcurrency,
      leaseDurationMs: this.config.leaseDurationMs,
      logger: this.logger,
      metrics: options.telemetry ? {
        claimedTotal: options.telemetry.standardMetrics.eventsClaimedTotal,
        pendingDepth: options.telemetry.standardMetrics.outboxPendingDepth,
        oldestAgeSeconds: options.telemetry.standardMetrics.outboxOldestAgeSeconds,
        workerConcurrency: options.telemetry.standardMetrics.workerConcurrencyActive,
        dispatchDuration: options.telemetry.standardMetrics.dispatchDurationSeconds,
      } : undefined,
    });

    this.replayManager = createReplayManager(this.pool, this.logger);
  }

  isRunning(): boolean {
    return this.started && this.poller.isRunning();
  }

  start(): void {
    if (this.started) return;
    this.started = true;
    this.poller.start();
    this.logger?.info('Event bus substrate started');
  }

  async stop(): Promise<void> {
    this.started = false;
    await this.poller.stop();
    this.logger?.info('Event bus substrate stopped');
  }

  async drain(timeoutMs?: number): Promise<void> {
    this.started = false;
    const timeout = timeoutMs ?? this.config.gracefulShutdownTimeoutMs;
    await this.poller.drain(timeout);
    this.logger?.info('Event bus substrate drain finished');
  }

  async healthCheck(): Promise<ComponentHealth> {
    const start = Date.now();
    try {
      const outboxRepo = new OutboxRepository(this.pool);
      const depth = await outboxRepo.getPendingDepth();
      const latencyMs = Date.now() - start;

      return {
        status: 'UP',
        latencyMs,
        checkedAt: nowIso(),
        details: {
          running: this.isRunning(),
          activeWorkers: this.poller.getActiveWorkerCount(),
          pendingDepth: depth.pendingCount,
          oldestAgeSeconds: depth.oldestAgeSeconds,
        },
      };
    } catch (error) {
      const latencyMs = Date.now() - start;
      return {
        status: 'DOWN',
        latencyMs,
        message: 'Event bus substrate outbox health check failed',
        checkedAt: nowIso(),
      };
    }
  }
}

export function createEventBusSubstrate(options: EventBusSubstrateOptions): IEventBusSubstrate {
  return new EventBusSubstrate(options);
}
