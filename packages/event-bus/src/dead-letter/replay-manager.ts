/**
 * Shadow : Helix Nebula (SHN) — Dead-Letter Replay Manager
 *
 * Implements controlled administrative replay of quarantined poison-pill events
 * with loop-prevention and operator audit logging (0.14 Section 35.7).
 */

import {
  type Result,
  ok,
  err,
  type CanonicalEventEnvelope,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
  type ProblemDetails,
} from '@shn/error-catalog';
import {
  type DatabasePool,
  DeadLetterRepository,
  OutboxRepository,
} from '@shn/data-access';
import type { ILogger } from '@shn/telemetry';

export interface ReplayOptions {
  readonly authorizedOperator: string;
  readonly maxReplayAttempts?: number | undefined;
}

export interface IReplayManager {
  replay(
    deadLetterId: string,
    options: ReplayOptions
  ): Promise<Result<void, ProblemDetails>>;
}

export class ReplayManager implements IReplayManager {
  private readonly deadLetterRepo: DeadLetterRepository;
  private readonly outboxRepo: OutboxRepository;
  private readonly logger?: ILogger | undefined;

  constructor(pool: DatabasePool, logger?: ILogger) {
    this.deadLetterRepo = new DeadLetterRepository(pool);
    this.outboxRepo = new OutboxRepository(pool);
    this.logger = logger;
  }

  async replay(
    deadLetterId: string,
    options: ReplayOptions
  ): Promise<Result<void, ProblemDetails>> {
    if (!options.authorizedOperator || typeof options.authorizedOperator !== 'string') {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.AUTH_FORBIDDEN,
          detail: 'Administrative replay requires an authorized operator identity',
          instance: `/events/dead-letter/${deadLetterId}/replay`,
          correlationId: 'deadletter.replay',
          customStatus: 403,
        })
      );
    }

    const deadLetter = await this.deadLetterRepo.findById(deadLetterId);
    if (!deadLetter) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.STORAGE_NOT_FOUND,
          detail: `Dead letter record not found: ${deadLetterId}`,
          instance: `/events/dead-letter/${deadLetterId}`,
          correlationId: 'deadletter.replay',
          customStatus: 404,
        })
      );
    }

    const maxReplayAttempts = options.maxReplayAttempts ?? 3;
    if (deadLetter.replay_count >= maxReplayAttempts) {
      this.logger?.warn('Rejected administrative replay: maximum replay count exceeded', {
        dead_letter_id: deadLetterId,
        replay_count: deadLetter.replay_count,
        max_replays: maxReplayAttempts,
      });

      return err(
        createProblemDetails({
          errorCode: ErrorCode.RATE_LIMIT_EXCEEDED,
          detail: `Event has already been replayed ${deadLetter.replay_count} times (maximum allowed: ${maxReplayAttempts}). Replay loop prevented.`,
          instance: `/events/dead-letter/${deadLetterId}/replay`,
          correlationId: deadLetter.correlation_id,
          customStatus: 429,
        })
      );
    }

    const envelope: CanonicalEventEnvelope = typeof deadLetter.envelope === 'string'
      ? JSON.parse(deadLetter.envelope)
      : deadLetter.envelope;

    // 1. Mark replayed in dead-letter table
    await this.deadLetterRepo.markReplayed(deadLetterId, options.authorizedOperator);

    // 2. Re-queue into outbox
    // If outbox record already exists, reset it to PENDING with attempt_count 0
    const existingOutbox = await this.outboxRepo.findByEventId(envelope.event_id);
    if (existingOutbox) {
      // Record failure resets or direct update
      await this.outboxRepo.recordFailure(
        envelope.event_id,
        { message: `Admin replay by ${options.authorizedOperator}` },
        new Date(),
        false
      );
    } else {
      await this.outboxRepo.insert(envelope);
    }

    this.logger?.info('Dead letter event successfully queued for replay', {
      dead_letter_id: deadLetterId,
      event_id: envelope.event_id,
      replayed_by: options.authorizedOperator,
      replay_count: deadLetter.replay_count + 1,
    });

    return ok(undefined);
  }
}

export function createReplayManager(pool: DatabasePool, logger?: ILogger): IReplayManager {
  return new ReplayManager(pool, logger);
}
