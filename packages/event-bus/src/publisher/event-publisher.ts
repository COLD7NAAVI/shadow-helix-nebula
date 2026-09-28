/**
 * Shadow : Helix Nebula (SHN) — Event Publisher & Transactional Outbox Substrate
 *
 * Implements transactional and non-transactional event publication guaranteeing
 * atomic domain write + event persistence (0.13 Section 14, 0.14 Section 12).
 */

import {
  type Result,
  ok,
  err,
  nowIso,
  type CanonicalEventEnvelope,
  type EventId,
  type IsoTimestamp,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
  type ProblemDetails,
} from '@shn/error-catalog';
import {
  type DatabasePool,
  type DatabaseClient,
  OutboxRepository,
} from '@shn/data-access';
import type { ILogger } from '@shn/telemetry';
import type { ICounter } from '@shn/telemetry';
import { validateCanonicalEventEnvelope } from '../registry/event-validator.js';

export type DeliveryMode = 'TRANSACTIONAL_OUTBOX' | 'NON_TRANSACTIONAL_OUTBOX' | 'IN_PROCESS';

export interface PublishReceipt {
  readonly eventId: EventId;
  readonly eventType: string;
  readonly occurredAt: IsoTimestamp;
  readonly deliveryMode: DeliveryMode;
  readonly publishedAt: IsoTimestamp;
}

export interface EventPublisherOptions {
  readonly pool: DatabasePool;
  readonly logger?: ILogger | undefined;
  readonly publishedMetric?: ICounter | undefined;
}

export interface IEventPublisher {
  /**
   * TRANSACTIONAL PUBLICATION GUARANTEE:
   * Inserts the event record into `events.outbox` using the caller's database transaction (`clientOrPool`).
   * When caller's transaction commits, the event commits atomically.
   * When caller's transaction rolls back, the event rolls back atomically.
   */
  publishTransactional<TPayload = unknown>(
    clientOrPool: DatabaseClient | DatabasePool,
    envelope: CanonicalEventEnvelope<TPayload>
  ): Promise<Result<PublishReceipt, ProblemDetails>>;

  /**
   * NON-TRANSACTIONAL PUBLICATION:
   * Persists the event directly to `events.outbox` via a dedicated short transaction.
   * Does NOT participate in or guarantee atomicity with any caller domain writes.
   */
  publish<TPayload = unknown>(
    envelope: CanonicalEventEnvelope<TPayload>
  ): Promise<Result<PublishReceipt, ProblemDetails>>;
}

export class EventPublisher implements IEventPublisher {
  private readonly pool: DatabasePool;
  private readonly logger?: ILogger | undefined;
  private readonly publishedMetric?: ICounter | undefined;

  constructor(options: EventPublisherOptions) {
    this.pool = options.pool;
    this.logger = options.logger;
    this.publishedMetric = options.publishedMetric;
  }

  async publishTransactional<TPayload = unknown>(
    clientOrPool: DatabaseClient | DatabasePool,
    envelope: CanonicalEventEnvelope<TPayload>
  ): Promise<Result<PublishReceipt, ProblemDetails>> {
    // 1. Structural runtime envelope validation
    const validation = validateCanonicalEventEnvelope<TPayload>(envelope);
    if (!validation.isValid) {
      this.logger?.warn('Rejected malformed event envelope during publishTransactional', {
        problem: validation.problem,
      });
      return err(validation.problem);
    }

    const validEnvelope = validation.value;

    try {
      // 2. Persist to outbox using caller's client/transaction
      const outboxRepo = new OutboxRepository(clientOrPool);
      await outboxRepo.insert(validEnvelope);

      // 3. Record metrics
      this.publishedMetric?.inc({
        event_type: validEnvelope.event_type,
        status: 'success',
      });

      this.logger?.debug('Event published to transactional outbox', {
        event_id: validEnvelope.event_id,
        event_type: validEnvelope.event_type,
        workspace_id: validEnvelope.workspace_id,
        correlation_id: validEnvelope.correlation_id,
      });

      return ok({
        eventId: validEnvelope.event_id,
        eventType: validEnvelope.event_type,
        occurredAt: validEnvelope.occurred_at,
        deliveryMode: 'TRANSACTIONAL_OUTBOX',
        publishedAt: nowIso(),
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Storage failure during event publication';
      this.publishedMetric?.inc({
        event_type: validEnvelope.event_type,
        status: 'failure',
      });
      this.logger?.error('Failed to write event to outbox in transaction', {
        event_id: validEnvelope.event_id,
        event_type: validEnvelope.event_type,
        error: msg,
      });

      return err(
        createProblemDetails({
          errorCode: ErrorCode.STORAGE_TRANSACTION_FAILED,
          detail: `Outbox publication failed: ${msg}`,
          instance: `/events/outbox/${validEnvelope.event_id}`,
          correlationId: validEnvelope.correlation_id,
          customStatus: 500,
        })
      );
    }
  }

  async publish<TPayload = unknown>(
    envelope: CanonicalEventEnvelope<TPayload>
  ): Promise<Result<PublishReceipt, ProblemDetails>> {
    const result = await this.publishTransactional(this.pool, envelope);
    if (result.isOk) {
      return ok({
        ...result.value,
        deliveryMode: 'NON_TRANSACTIONAL_OUTBOX',
      });
    }
    return result;
  }
}

export function createEventPublisher(options: EventPublisherOptions): IEventPublisher {
  return new EventPublisher(options);
}
