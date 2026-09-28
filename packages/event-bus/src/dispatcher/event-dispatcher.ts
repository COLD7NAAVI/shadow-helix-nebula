/**
 * Shadow : Helix Nebula (SHN) — Event Dispatcher, Retry & Dead-Letter Pipeline
 *
 * Implements the complete Phase 0.14 Figure 35.7 lifecycle:
 * Deduplication -> Domain Handler -> Success Commit / Exponential Backoff Retry -> DLQ Quarantine.
 */

import {
  type Result,
  ok,
  type CanonicalEventEnvelope,
} from '@shn/shared-kernel';
import type { ProblemDetails } from '@shn/error-catalog';
import {
  OutboxRepository,
  DeduplicationRepository,
  DeadLetterRepository,
  type DatabasePool,
  type DatabaseClient,
} from '@shn/data-access';
import {
  runWithTelemetryContext,
  sanitizeString,
  type ILogger,
  type ICounter,
  type IHistogram,
} from '@shn/telemetry';
import { type IEventRegistry } from '../registry/event-registry.js';

export interface RetryPolicyConfig {
  readonly maxAttempts?: number | undefined;
  readonly initialDelayMs?: number | undefined;
  readonly multiplier?: number | undefined;
  readonly maxDelayMs?: number | undefined;
  readonly jitter?: boolean | undefined;
}

interface ResolvedRetryPolicy {
  readonly maxAttempts: number;
  readonly initialDelayMs: number;
  readonly multiplier: number;
  readonly maxDelayMs: number;
  readonly jitter: boolean;
}

export interface DispatcherMetrics {
  readonly dispatchedTotal?: ICounter | undefined;
  readonly retriedTotal?: ICounter | undefined;
  readonly deadLetterTotal?: ICounter | undefined;
  readonly handlerDurationSeconds?: IHistogram | undefined;
}

export interface EventDispatcherOptions {
  readonly db: DatabasePool | DatabaseClient;
  readonly registry: IEventRegistry;
  readonly retryPolicy?: RetryPolicyConfig | undefined;
  readonly deduplicationTtlHours?: number | undefined;
  readonly logger?: ILogger | undefined;
  readonly metrics?: DispatcherMetrics | undefined;
}

export interface DispatchResult {
  readonly eventId: string;
  readonly status: 'COMPLETED' | 'SKIPPED_DUPLICATE' | 'SCHEDULED_RETRY' | 'DEAD_LETTERED';
  readonly attemptCount: number;
}

export interface IEventDispatcher {
  dispatch<TPayload = unknown>(
    envelope: CanonicalEventEnvelope<TPayload>,
    currentAttemptCount?: number
  ): Promise<Result<DispatchResult, ProblemDetails>>;
}

export class EventDispatcher implements IEventDispatcher {
  private readonly outboxRepo: OutboxRepository;
  private readonly dedupRepo: DeduplicationRepository;
  private readonly deadLetterRepo: DeadLetterRepository;
  private readonly registry: IEventRegistry;
  private readonly retryPolicy: ResolvedRetryPolicy;
  private readonly deduplicationTtlHours: number;
  private readonly logger?: ILogger | undefined;
  private readonly metrics?: DispatcherMetrics | undefined;

  constructor(options: EventDispatcherOptions) {
    this.outboxRepo = new OutboxRepository(options.db);
    this.dedupRepo = new DeduplicationRepository(options.db);
    this.deadLetterRepo = new DeadLetterRepository(options.db);
    this.registry = options.registry;
    this.deduplicationTtlHours = options.deduplicationTtlHours ?? 24;
    this.logger = options.logger;
    this.metrics = options.metrics;

    this.retryPolicy = {
      maxAttempts: options.retryPolicy?.maxAttempts ?? 5,
      initialDelayMs: options.retryPolicy?.initialDelayMs ?? 1000,
      multiplier: options.retryPolicy?.multiplier ?? 2.0,
      maxDelayMs: options.retryPolicy?.maxDelayMs ?? 60000,
      jitter: options.retryPolicy?.jitter ?? true,
    };
  }

  async dispatch<TPayload = unknown>(
    envelope: CanonicalEventEnvelope<TPayload>,
    currentAttemptCount: number = 0
  ): Promise<Result<DispatchResult, ProblemDetails>> {
    const handlers = this.registry.getHandlers(envelope.event_type, envelope.schema_version);

    if (handlers.length === 0) {
      this.logger?.warn('No compatible handlers registered for event; marking published', {
        event_type: envelope.event_type,
        schema_version: envelope.schema_version,
        event_id: envelope.event_id,
      });
      await this.outboxRepo.markPublished(envelope.event_id);
      return ok({
        eventId: envelope.event_id,
        status: 'COMPLETED',
        attemptCount: currentAttemptCount,
      });
    }

    let allCompleted = true;
    let anyRetried = false;
    let anyDeadLettered = false;

    for (const handler of handlers) {
      const idempotencyKey = `${handler.handlerName}:${envelope.event_id}`;

      // 1. Check deduplication / idempotency
      const acquireResult = await this.dedupRepo.acquire(
        idempotencyKey,
        envelope.event_id,
        handler.handlerName,
        envelope.workspace_id,
        this.deduplicationTtlHours
      );

      if (acquireResult === 'ALREADY_COMPLETED') {
        this.logger?.info('Event already processed by handler; skipping re-execution', {
          handler: handler.handlerName,
          event_id: envelope.event_id,
        });
        continue;
      }

      if (acquireResult === 'IN_FLIGHT') {
        this.logger?.info('Event handler currently in-flight; deferring duplicate claim', {
          handler: handler.handlerName,
          event_id: envelope.event_id,
        });
        allCompleted = false;
        continue;
      }

      // 2. Execute Domain Handler inside telemetry context
      const startTime = Date.now();
      let handlerSuccess = false;
      let failureReason = '';

      try {
        const handlerResult = await runWithTelemetryContext(
          {
            correlationId: envelope.correlation_id,
            causationId: envelope.event_id,
            traceId: envelope.trace_id,
            workspaceId: envelope.workspace_id,
          },
          async () => {
            let timer: NodeJS.Timeout | undefined;
            const timeoutPromise = new Promise<never>((_, reject) => {
              timer = setTimeout(() => {
                reject(new Error(`Handler "${handler.handlerName}" timed out after ${handler.timeoutMs}ms`));
              }, handler.timeoutMs);
            });

            return Promise.race([
              handler.handler(envelope),
              timeoutPromise,
            ]).finally(() => {
              if (timer) clearTimeout(timer);
            });
          }
        );

        if (handlerResult.isOk) {
          handlerSuccess = true;
        } else {
          failureReason = handlerResult.error.detail;
        }
      } catch (error) {
        failureReason = error instanceof Error ? error.message : 'Unknown handler failure';
      } finally {
        const durationSec = (Date.now() - startTime) / 1000;
        this.metrics?.handlerDurationSeconds?.record(durationSec, {
          event_type: envelope.event_type,
          handler: handler.handlerName,
        });
      }

      // 3. Handle success or failure
      if (handlerSuccess) {
        await this.dedupRepo.markCompleted(idempotencyKey, this.deduplicationTtlHours);
        this.metrics?.dispatchedTotal?.inc({
          event_type: envelope.event_type,
          status: 'success',
        });
      } else {
        allCompleted = false;
        await this.dedupRepo.markFailed(idempotencyKey);

        const newAttempt = currentAttemptCount + 1;
        const safeErrorMsg = sanitizeString(failureReason);

        if (newAttempt < this.retryPolicy.maxAttempts) {
          // Retry with exponential backoff
          anyRetried = true;
          let delayMs = Math.min(
            this.retryPolicy.maxDelayMs,
            this.retryPolicy.initialDelayMs * Math.pow(this.retryPolicy.multiplier, newAttempt - 1)
          );
          if (this.retryPolicy.jitter) {
            delayMs += Math.random() * (delayMs * 0.2);
          }
          const nextAttemptAt = new Date(Date.now() + Math.round(delayMs));

          await this.outboxRepo.recordFailure(
            envelope.event_id,
            { message: safeErrorMsg },
            nextAttemptAt,
            false
          );

          this.metrics?.retriedTotal?.inc({ event_type: envelope.event_type });
          this.logger?.warn('Event handler failed; scheduled retry', {
            handler: handler.handlerName,
            event_id: envelope.event_id,
            attempt: newAttempt,
            max_attempts: this.retryPolicy.maxAttempts,
            next_attempt_at: nextAttemptAt.toISOString(),
            error: safeErrorMsg,
          });
        } else {
          // Terminal failure -> Dead-Letter Quarantine
          anyDeadLettered = true;
          await this.deadLetterRepo.quarantine({
            eventId: envelope.event_id,
            eventType: envelope.event_type,
            schemaVersion: envelope.schema_version,
            workspaceId: envelope.workspace_id,
            correlationId: envelope.correlation_id,
            causationId: envelope.causation_id,
            traceId: envelope.trace_id,
            envelope,
            attemptCount: newAttempt,
            lastError: safeErrorMsg,
          });

          await this.outboxRepo.recordFailure(
            envelope.event_id,
            { message: safeErrorMsg },
            null,
            true
          );

          this.metrics?.deadLetterTotal?.inc({ event_type: envelope.event_type });
          this.logger?.error('Event exceeded maximum retry attempts; quarantined to dead-letter queue (P1 Alert)', {
            handler: handler.handlerName,
            event_id: envelope.event_id,
            attempts: newAttempt,
            error: safeErrorMsg,
          });
        }
      }
    }

    if (allCompleted) {
      await this.outboxRepo.markPublished(envelope.event_id);
      return ok({
        eventId: envelope.event_id,
        status: 'COMPLETED',
        attemptCount: currentAttemptCount,
      });
    }

    if (anyDeadLettered) {
      return ok({
        eventId: envelope.event_id,
        status: 'DEAD_LETTERED',
        attemptCount: currentAttemptCount + 1,
      });
    }

    if (anyRetried) {
      return ok({
        eventId: envelope.event_id,
        status: 'SCHEDULED_RETRY',
        attemptCount: currentAttemptCount + 1,
      });
    }

    return ok({
      eventId: envelope.event_id,
      status: 'SKIPPED_DUPLICATE',
      attemptCount: currentAttemptCount,
    });
  }
}

export function createEventDispatcher(options: EventDispatcherOptions): IEventDispatcher {
  return new EventDispatcher(options);
}
