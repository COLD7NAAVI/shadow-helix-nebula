/**
 * Shadow : Helix Nebula (SHN) — Dead-Letter Repository
 *
 * Bounded Context: Event Infrastructure (events.dead_letter)
 * Durable quarantine storage for poison-pill events exceeding retry bounds (0.14 Section 35.7).
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

export interface DeadLetterRecord {
  readonly id: string;
  readonly event_id: EventId;
  readonly event_type: string;
  readonly schema_version: string;
  readonly workspace_id: WorkspaceId;
  readonly correlation_id: CorrelationId;
  readonly causation_id: CausationId;
  readonly trace_id: TraceId;
  readonly envelope: CanonicalEventEnvelope;
  readonly attempt_count: number;
  readonly last_error: string;
  readonly error_details: unknown | null;
  readonly quarantined_at: string;
  readonly replayed_at: string | null;
  readonly replayed_by: string | null;
  readonly replay_count: number;
}

export interface CreateDeadLetterInput {
  readonly eventId: EventId;
  readonly eventType: string;
  readonly schemaVersion: string;
  readonly workspaceId: WorkspaceId;
  readonly correlationId: CorrelationId;
  readonly causationId: CausationId;
  readonly traceId: TraceId;
  readonly envelope: CanonicalEventEnvelope;
  readonly attemptCount: number;
  readonly lastError: string;
  readonly errorDetails?: unknown;
}

export interface ListDeadLettersOptions {
  readonly workspaceId?: WorkspaceId;
  readonly eventType?: string;
  readonly limit?: number;
  readonly offset?: number;
}

export class DeadLetterRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  /**
   * Quarantines an unprocessable or retry-exhausted event into the dead-letter store.
   */
  async quarantine(input: CreateDeadLetterInput): Promise<DeadLetterRecord> {
    if (!isValidUUID(input.eventId)) {
      throw new Error(`Invalid eventId: ${input.eventId}`);
    }
    if (!isValidUUID(input.workspaceId)) {
      throw new Error(`Invalid workspaceId: ${input.workspaceId}`);
    }
    if (!isValidUUID(input.correlationId)) {
      throw new Error(`Invalid correlationId: ${input.correlationId}`);
    }
    if (!isValidUUID(input.causationId)) {
      throw new Error(`Invalid causationId: ${input.causationId}`);
    }

    const errorDetailsJson = input.errorDetails ? JSON.stringify(input.errorDetails) : null;

    const result = await this.db.query<DeadLetterRecord>(
      `INSERT INTO events.dead_letter (
        event_id,
        event_type,
        schema_version,
        workspace_id,
        correlation_id,
        causation_id,
        trace_id,
        envelope,
        attempt_count,
        last_error,
        error_details
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
      )
      ON CONFLICT (event_id) DO UPDATE
      SET attempt_count = $9,
          last_error = $10,
          error_details = $11,
          quarantined_at = clock_timestamp()
      RETURNING *;`,
      [
        input.eventId,
        input.eventType,
        input.schemaVersion,
        input.workspaceId,
        input.correlationId,
        input.causationId,
        input.traceId,
        JSON.stringify(input.envelope),
        input.attemptCount,
        input.lastError,
        errorDetailsJson,
      ]
    );

    const row = result.rows[0];
    if (!row) {
      throw new Error('Failed to insert dead-letter record');
    }
    return row;
  }

  /**
   * Finds a dead-letter record by dead-letter ID.
   */
  async findById(id: string): Promise<DeadLetterRecord | null> {
    if (!isValidUUID(id)) {
      throw new Error(`Invalid dead letter id: ${id}`);
    }

    const result = await this.db.query<DeadLetterRecord>(
      `SELECT * FROM events.dead_letter WHERE id = $1;`,
      [id]
    );
    return result.rows[0] ?? null;
  }

  /**
   * Finds a dead-letter record by original event ID.
   */
  async findByEventId(eventId: EventId): Promise<DeadLetterRecord | null> {
    if (!isValidUUID(eventId)) {
      throw new Error(`Invalid eventId: ${eventId}`);
    }

    const result = await this.db.query<DeadLetterRecord>(
      `SELECT * FROM events.dead_letter WHERE event_id = $1;`,
      [eventId]
    );
    return result.rows[0] ?? null;
  }

  /**
   * Lists dead-letter events with optional workspace and event type filtering.
   */
  async list(options?: ListDeadLettersOptions): Promise<DeadLetterRecord[]> {
    let sql = `SELECT * FROM events.dead_letter WHERE 1=1`;
    const params: unknown[] = [];

    if (options?.workspaceId) {
      if (!isValidUUID(options.workspaceId)) {
        throw new Error(`Invalid workspaceId: ${options.workspaceId}`);
      }
      params.push(options.workspaceId);
      sql += ` AND workspace_id = $${params.length}`;
    }

    if (options?.eventType) {
      params.push(options.eventType);
      sql += ` AND event_type = $${params.length}`;
    }

    sql += ` ORDER BY quarantined_at DESC`;

    const limit = Math.min(Math.max(1, options?.limit ?? 50), 200);
    params.push(limit);
    sql += ` LIMIT $${params.length}`;

    if (options?.offset && options.offset > 0) {
      params.push(options.offset);
      sql += ` OFFSET $${params.length}`;
    }

    const result = await this.db.query<DeadLetterRecord>(sql, params);
    return result.rows;
  }

  /**
   * Marks a dead-letter event as replayed by an authorized administrative operator.
   */
  async markReplayed(id: string, replayedBy: string): Promise<void> {
    if (!isValidUUID(id)) {
      throw new Error(`Invalid dead letter id: ${id}`);
    }
    if (!replayedBy || typeof replayedBy !== 'string') {
      throw new Error('replayedBy must be a non-empty string');
    }

    await this.db.query(
      `UPDATE events.dead_letter
       SET replayed_at = clock_timestamp(),
           replayed_by = $2,
           replay_count = replay_count + 1
       WHERE id = $1;`,
      [id, replayedBy]
    );
  }
}
