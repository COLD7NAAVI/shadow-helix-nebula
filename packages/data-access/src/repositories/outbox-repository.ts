/**
 * Shadow : Helix Nebula (SHN) — Outbox Repository
 *
 * Bounded Context: Event Infrastructure (events.outbox)
 * Manages durable transactional outbox event storage, atomic claiming via SKIP LOCKED,
 * lease recovery, and retry tracking (0.14 Section 12, 16, 35.7).
 */

import {
  isValidUUID,
  type CanonicalEventEnvelope,
  type EventId,
  type WorkspaceId,
  type CorrelationId,
  type CausationId,
  type TraceId,
} from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

export type OutboxStatus = 'PENDING' | 'PROCESSING' | 'PUBLISHED' | 'FAILED' | 'DEAD_LETTER';

export interface OutboxRecord {
  readonly id: string;
  readonly event_id: EventId;
  readonly event_type: string;
  readonly schema_version: string;
  readonly occurred_at: string;
  readonly workspace_id: WorkspaceId;
  readonly correlation_id: CorrelationId;
  readonly causation_id: CausationId;
  readonly trace_id: TraceId;
  readonly envelope: CanonicalEventEnvelope;
  readonly status: OutboxStatus;
  readonly attempt_count: number;
  readonly max_attempts: number;
  readonly next_attempt_at: string;
  readonly claimed_at: string | null;
  readonly claimed_by: string | null;
  readonly lease_expires_at: string | null;
  readonly last_error: string | null;
  readonly error_details: unknown | null;
  readonly published_at: string | null;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface ClaimBatchOptions {
  readonly workerId: string;
  readonly batchSize: number;
  readonly leaseDurationMs: number;
}

export class OutboxRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  /**
   * Inserts a canonical event into the outbox.
   * Can be executed inside an existing transaction using the transaction's DatabaseClient.
   */
  async insert<TPayload = unknown>(
    envelope: CanonicalEventEnvelope<TPayload>,
    options?: { maxAttempts?: number }
  ): Promise<OutboxRecord> {
    if (!envelope || typeof envelope !== 'object') {
      throw new Error('Outbox envelope must be a valid non-null object');
    }
    if (!envelope.event_id || !isValidUUID(envelope.event_id)) {
      throw new Error(`Invalid event_id in outbox envelope: ${String(envelope.event_id)}`);
    }
    if (!envelope.workspace_id || !isValidUUID(envelope.workspace_id)) {
      throw new Error(`Invalid workspace_id in outbox envelope: ${String(envelope.workspace_id)}`);
    }
    if (!envelope.correlation_id || !isValidUUID(envelope.correlation_id)) {
      throw new Error(`Invalid correlation_id in outbox envelope: ${String(envelope.correlation_id)}`);
    }
    if (!envelope.causation_id || !isValidUUID(envelope.causation_id)) {
      throw new Error(`Invalid causation_id in outbox envelope: ${String(envelope.causation_id)}`);
    }

    const maxAttempts = options?.maxAttempts ?? 5;
    if (maxAttempts < 1 || maxAttempts > 100) {
      throw new Error(`Invalid maxAttempts: ${maxAttempts}. Must be between 1 and 100.`);
    }

    const result = await this.db.query<OutboxRecord>(
      `INSERT INTO events.outbox (
        event_id,
        event_type,
        schema_version,
        occurred_at,
        workspace_id,
        correlation_id,
        causation_id,
        trace_id,
        envelope,
        status,
        max_attempts,
        next_attempt_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, 'PENDING', $10, clock_timestamp()
      )
      RETURNING *;`,
      [
        envelope.event_id,
        envelope.event_type,
        envelope.schema_version,
        envelope.occurred_at,
        envelope.workspace_id,
        envelope.correlation_id,
        envelope.causation_id,
        envelope.trace_id,
        JSON.stringify(envelope),
        maxAttempts,
      ]
    );

    const row = result.rows[0];
    if (!row) {
      throw new Error('Failed to insert outbox record: no row returned');
    }
    return row;
  }

  /**
   * Atomically claims a batch of pending or expired-lease events using SKIP LOCKED.
   * Multiple workers can call this concurrently without blocking or claiming the same rows.
   */
  async claimBatch(options: ClaimBatchOptions): Promise<OutboxRecord[]> {
    const { workerId, batchSize, leaseDurationMs } = options;
    if (!workerId || typeof workerId !== 'string') {
      throw new Error('workerId must be a non-empty string');
    }
    if (batchSize < 1 || batchSize > 500) {
      throw new Error(`Invalid batchSize: ${batchSize}. Must be between 1 and 500.`);
    }
    if (leaseDurationMs < 100 || leaseDurationMs > 3600000) {
      throw new Error(`Invalid leaseDurationMs: ${leaseDurationMs}. Must be between 100 and 3600000.`);
    }

    const result = await this.db.query<OutboxRecord>(
      `WITH candidates AS (
        SELECT id
        FROM events.outbox
        WHERE (status = 'PENDING' AND next_attempt_at <= clock_timestamp())
           OR (status = 'PROCESSING' AND lease_expires_at <= clock_timestamp())
        ORDER BY occurred_at ASC, id ASC
        LIMIT $1
        FOR UPDATE SKIP LOCKED
      )
      UPDATE events.outbox o
      SET status = 'PROCESSING',
          claimed_at = clock_timestamp(),
          claimed_by = $2,
          lease_expires_at = clock_timestamp() + ($3 || ' milliseconds')::interval,
          updated_at = clock_timestamp()
      FROM candidates
      WHERE o.id = candidates.id
      RETURNING o.*;`,
      [batchSize, workerId, leaseDurationMs]
    );

    return result.rows;
  }

  /**
   * Marks an outbox event as successfully published/dispatched.
   */
  async markPublished(eventId: string): Promise<void> {
    if (!isValidUUID(eventId)) {
      throw new Error(`Invalid eventId: ${eventId}`);
    }

    await this.db.query(
      `UPDATE events.outbox
       SET status = 'PUBLISHED',
           published_at = clock_timestamp(),
           updated_at = clock_timestamp()
       WHERE event_id = $1;`,
      [eventId]
    );
  }

  /**
   * Records a delivery attempt failure with backoff schedule or terminal quarantine.
   */
  async recordFailure(
    eventId: string,
    error: { message: string; details?: unknown },
    nextAttemptAt: Date | null,
    terminal: boolean
  ): Promise<void> {
    if (!isValidUUID(eventId)) {
      throw new Error(`Invalid eventId: ${eventId}`);
    }

    const nextAttemptIso = nextAttemptAt ? nextAttemptAt.toISOString() : null;
    const errorDetailsJson = error.details ? JSON.stringify(error.details) : null;

    await this.db.query(
      `UPDATE events.outbox
       SET status = CASE WHEN $4::boolean THEN 'DEAD_LETTER' ELSE 'PENDING' END,
           attempt_count = attempt_count + 1,
           last_error = $2,
           error_details = $3,
           next_attempt_at = CASE
             WHEN $4::boolean THEN next_attempt_at
             WHEN $5::timestamptz IS NOT NULL THEN $5::timestamptz
             ELSE clock_timestamp()
           END,
           lease_expires_at = NULL,
           claimed_by = NULL,
           updated_at = clock_timestamp()
       WHERE event_id = $1;`,
      [eventId, error.message, errorDetailsJson, terminal, nextAttemptIso]
    );
  }

  /**
   * Recovers abandoned or crashed worker leases back to PENDING.
   */
  async recoverExpiredLeases(): Promise<number> {
    const result = await this.db.query(
      `UPDATE events.outbox
       SET status = 'PENDING',
           attempt_count = attempt_count + 1,
           claimed_at = NULL,
           claimed_by = NULL,
           lease_expires_at = NULL,
           updated_at = clock_timestamp()
       WHERE status = 'PROCESSING'
         AND lease_expires_at <= clock_timestamp();`
    );
    return result.rowCount ?? 0;
  }

  /**
   * Retrieves pending queue metrics: count and oldest pending event age in seconds.
   */
  async getPendingDepth(workspaceId?: string): Promise<{ pendingCount: number; oldestAgeSeconds: number }> {
    let sql = `SELECT count(*)::int AS pending_count,
                      COALESCE(EXTRACT(EPOCH FROM (clock_timestamp() - min(occurred_at))), 0)::float AS oldest_age_seconds
               FROM events.outbox
               WHERE status IN ('PENDING', 'PROCESSING')`;
    const params: unknown[] = [];

    if (workspaceId) {
      if (!isValidUUID(workspaceId)) {
        throw new Error(`Invalid workspaceId: ${workspaceId}`);
      }
      sql += ' AND workspace_id = $1';
      params.push(workspaceId);
    }

    const result = await this.db.query<{ pending_count: number; oldest_age_seconds: number }>(sql, params);
    const row = result.rows[0];
    return {
      pendingCount: row?.pending_count ?? 0,
      oldestAgeSeconds: Math.max(0, row?.oldest_age_seconds ?? 0),
    };
  }

  /**
   * Retrieves an outbox record by event ID.
   */
  async findByEventId(eventId: string): Promise<OutboxRecord | null> {
    if (!isValidUUID(eventId)) {
      throw new Error(`Invalid eventId: ${eventId}`);
    }

    const result = await this.db.query<OutboxRecord>(
      `SELECT * FROM events.outbox WHERE event_id = $1;`,
      [eventId]
    );
    return result.rows[0] ?? null;
  }
}
