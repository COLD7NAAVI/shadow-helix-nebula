/**
 * Shadow : Helix Nebula (SHN) — Deduplication Repository
 *
 * Bounded Context: Event Infrastructure (events.deduplication_log)
 * Implements durable consumer idempotency check-and-set to guarantee
 * effectively-once domain event processing (0.14 Section 16, 17, ADR-API-04).
 */

import { isValidUUID, type WorkspaceId, type EventId } from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

export type DeduplicationStatus = 'IN_FLIGHT' | 'COMPLETED' | 'FAILED';

export interface DeduplicationRecord {
  readonly idempotency_key: string;
  readonly event_id: EventId;
  readonly consumer_id: string;
  readonly workspace_id: WorkspaceId;
  readonly status: DeduplicationStatus;
  readonly processed_at: string;
  readonly expires_at: string;
}

export type DeduplicationAcquireResult = 'ACQUIRED' | 'ALREADY_COMPLETED' | 'IN_FLIGHT';

export class DeduplicationRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  /**
   * Attempts to acquire an idempotency lock for a consumer and event.
   * If already COMPLETED and unexpired -> ALREADY_COMPLETED.
   * If currently IN_FLIGHT and unexpired -> IN_FLIGHT.
   * If not found or expired -> ACQUIRED with status IN_FLIGHT.
   */
  async acquire(
    idempotencyKey: string,
    eventId: EventId,
    consumerId: string,
    workspaceId: WorkspaceId,
    ttlHours: number = 24
  ): Promise<DeduplicationAcquireResult> {
    if (!idempotencyKey || typeof idempotencyKey !== 'string') {
      throw new Error('idempotencyKey must be a non-empty string');
    }
    if (!isValidUUID(eventId)) {
      throw new Error(`Invalid eventId: ${eventId}`);
    }
    if (!consumerId || typeof consumerId !== 'string') {
      throw new Error('consumerId must be a non-empty string');
    }
    if (!isValidUUID(workspaceId)) {
      throw new Error(`Invalid workspaceId: ${workspaceId}`);
    }
    if (ttlHours < 1 || ttlHours > 720) {
      throw new Error(`Invalid ttlHours: ${ttlHours}. Must be between 1 and 720.`);
    }

    // Try to insert fresh IN_FLIGHT record
    const insertResult = await this.db.query<DeduplicationRecord>(
      `INSERT INTO events.deduplication_log (
        idempotency_key,
        event_id,
        consumer_id,
        workspace_id,
        status,
        processed_at,
        expires_at
      ) VALUES (
        $1, $2, $3, $4, 'IN_FLIGHT', clock_timestamp(), clock_timestamp() + ($5 || ' hours')::interval
      )
      ON CONFLICT (idempotency_key) DO NOTHING
      RETURNING *;`,
      [idempotencyKey, eventId, consumerId, workspaceId, ttlHours]
    );

    if (insertResult.rows.length > 0) {
      return 'ACQUIRED';
    }

    // Conflict occurred: inspect existing record
    const existing = await this.db.query<DeduplicationRecord>(
      `SELECT idempotency_key, status, expires_at
       FROM events.deduplication_log
       WHERE idempotency_key = $1;`,
      [idempotencyKey]
    );

    const row = existing.rows[0];
    if (!row) {
      // Rare race where conflict happened but record was deleted; retry acquire
      return 'IN_FLIGHT';
    }

    const isExpired = new Date(row.expires_at).getTime() <= Date.now();
    if (isExpired) {
      // Re-claim expired key
      await this.db.query(
        `UPDATE events.deduplication_log
         SET status = 'IN_FLIGHT',
             event_id = $2,
             consumer_id = $3,
             workspace_id = $4,
             processed_at = clock_timestamp(),
             expires_at = clock_timestamp() + ($5 || ' hours')::interval
         WHERE idempotency_key = $1;`,
        [idempotencyKey, eventId, consumerId, workspaceId, ttlHours]
      );
      return 'ACQUIRED';
    }

    if (row.status === 'COMPLETED') {
      return 'ALREADY_COMPLETED';
    }

    return 'IN_FLIGHT';
  }

  /**
   * Commits the deduplication record as successfully completed.
   */
  async markCompleted(idempotencyKey: string, ttlHours: number = 24): Promise<void> {
    if (!idempotencyKey || typeof idempotencyKey !== 'string') {
      throw new Error('idempotencyKey must be a non-empty string');
    }

    await this.db.query(
      `UPDATE events.deduplication_log
       SET status = 'COMPLETED',
           processed_at = clock_timestamp(),
           expires_at = clock_timestamp() + ($2 || ' hours')::interval
       WHERE idempotency_key = $1;`,
      [idempotencyKey, ttlHours]
    );
  }

  /**
   * Marks deduplication entry as failed (or removes it) so it can be retried.
   */
  async markFailed(idempotencyKey: string): Promise<void> {
    if (!idempotencyKey || typeof idempotencyKey !== 'string') {
      throw new Error('idempotencyKey must be a non-empty string');
    }

    await this.db.query(
      `DELETE FROM events.deduplication_log
       WHERE idempotency_key = $1 AND status = 'IN_FLIGHT';`,
      [idempotencyKey]
    );
  }

  /**
   * Checks whether an idempotency key has already completed successfully and is unexpired.
   */
  async isProcessed(idempotencyKey: string): Promise<boolean> {
    if (!idempotencyKey || typeof idempotencyKey !== 'string') {
      return false;
    }

    const result = await this.db.query(
      `SELECT 1
       FROM events.deduplication_log
       WHERE idempotency_key = $1
         AND status = 'COMPLETED'
         AND expires_at > clock_timestamp();`,
      [idempotencyKey]
    );

    return result.rows.length > 0;
  }

  /**
   * Prunes expired deduplication entries.
   */
  async pruneExpired(): Promise<number> {
    const result = await this.db.query(
      `DELETE FROM events.deduplication_log
       WHERE expires_at <= clock_timestamp();`
    );
    return result.rowCount ?? 0;
  }
}
