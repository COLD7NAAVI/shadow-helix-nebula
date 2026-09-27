/**
 * Shadow : Helix Nebula (SHN) — Audit Event Repository
 *
 * Bounded Context: Audit Ledger
 * Owns table: audit.events
 * Implements append-only persistence of CanonicalEventEnvelope (API-INV-06, SEC-INV-11, DATA-INV-07).
 */

import {
  isValidUUID,
  type CanonicalEventEnvelope,
  type EventId,
  type WorkspaceId,
  type CorrelationId,
  type CausationId,
  type TraceId,
  type IsoTimestamp,
  type ProducerMetadata,
  type SecurityContextToken,
  type ScopeReference,
  type IntegrityBlock,
} from '@shn/shared-kernel';
import type { DatabasePool, DatabaseClient } from '../pool.js';

interface RawAuditEventRow {
  readonly event_id: string;
  readonly event_type: string;
  readonly schema_version: string;
  readonly occurred_at: string;
  readonly producer: ProducerMetadata | string;
  readonly workspace_id: string;
  readonly correlation_id: string;
  readonly causation_id: string;
  readonly trace_id: string;
  readonly authorization_context: SecurityContextToken | string;
  readonly scope_reference: ScopeReference | string;
  readonly payload: unknown;
  readonly integrity: IntegrityBlock | string;
  readonly recorded_at: string;
}

export class AuditEventRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  /**
   * Appends a canonical event envelope to the immutable audit ledger.
   * Attempting to update or delete rows will be rejected by the database engine (SEC-INV-11 / DATA-INV-07).
   */
  async append<TPayload = unknown>(
    envelope: CanonicalEventEnvelope<TPayload>
  ): Promise<void> {
    if (!envelope || typeof envelope !== 'object') {
      throw new Error('Audit envelope must be a valid non-null object');
    }
    if (!envelope.event_id || !isValidUUID(envelope.event_id)) {
      throw new Error(`Invalid event_id in audit envelope: ${String(envelope.event_id)}`);
    }
    if (!envelope.workspace_id || !isValidUUID(envelope.workspace_id)) {
      throw new Error(`Invalid workspace_id in audit envelope: ${String(envelope.workspace_id)}`);
    }

    await this.db.query(
      `INSERT INTO audit.events (
        event_id,
        event_type,
        schema_version,
        occurred_at,
        producer,
        workspace_id,
        correlation_id,
        causation_id,
        trace_id,
        authorization_context,
        scope_reference,
        payload,
        integrity
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
      );`,
      [
        envelope.event_id,
        envelope.event_type,
        envelope.schema_version,
        envelope.occurred_at,
        JSON.stringify(envelope.producer),
        envelope.workspace_id,
        envelope.correlation_id,
        envelope.causation_id,
        envelope.trace_id,
        JSON.stringify(envelope.authorization_context),
        JSON.stringify(envelope.scope_reference),
        JSON.stringify(envelope.payload),
        JSON.stringify(envelope.integrity),
      ]
    );
  }

  async findByEventId<TPayload = unknown>(
    eventId: EventId
  ): Promise<CanonicalEventEnvelope<TPayload> | null> {
    if (typeof eventId !== 'string' || !isValidUUID(eventId)) {
      throw new Error(`Invalid event_id: ${String(eventId)}`);
    }

    const result = await this.db.query<RawAuditEventRow>(
      `SELECT
        event_id,
        event_type,
        schema_version,
        occurred_at,
        producer,
        workspace_id,
        correlation_id,
        causation_id,
        trace_id,
        authorization_context,
        scope_reference,
        payload,
        integrity,
        recorded_at
       FROM audit.events
       WHERE event_id = $1;`,
      [eventId]
    );

    const row = result.rows[0];
    if (!row) return null;
    return this.mapRowToEnvelope<TPayload>(row);
  }

  async listByWorkspace<TPayload = unknown>(
    workspaceId: WorkspaceId,
    limit: number = 50
  ): Promise<CanonicalEventEnvelope<TPayload>[]> {
    if (typeof workspaceId !== 'string' || !isValidUUID(workspaceId)) {
      throw new Error(`Invalid workspace_id: ${String(workspaceId)}`);
    }

    const safeLimit = Math.max(1, Math.min(limit, 1000));
    const result = await this.db.query<RawAuditEventRow>(
      `SELECT
        event_id,
        event_type,
        schema_version,
        occurred_at,
        producer,
        workspace_id,
        correlation_id,
        causation_id,
        trace_id,
        authorization_context,
        scope_reference,
        payload,
        integrity,
        recorded_at
       FROM audit.events
       WHERE workspace_id = $1
       ORDER BY occurred_at DESC
       LIMIT $2;`,
      [workspaceId, safeLimit]
    );

    return result.rows.map(row => this.mapRowToEnvelope<TPayload>(row));
  }

  async listByCorrelation<TPayload = unknown>(
    correlationId: CorrelationId
  ): Promise<CanonicalEventEnvelope<TPayload>[]> {
    if (typeof correlationId !== 'string' || !isValidUUID(correlationId)) {
      throw new Error(`Invalid correlation_id: ${String(correlationId)}`);
    }

    const result = await this.db.query<RawAuditEventRow>(
      `SELECT
        event_id,
        event_type,
        schema_version,
        occurred_at,
        producer,
        workspace_id,
        correlation_id,
        causation_id,
        trace_id,
        authorization_context,
        scope_reference,
        payload,
        integrity,
        recorded_at
       FROM audit.events
       WHERE correlation_id = $1
       ORDER BY occurred_at ASC;`,
      [correlationId]
    );

    return result.rows.map(row => this.mapRowToEnvelope<TPayload>(row));
  }

  private mapRowToEnvelope<TPayload>(
    row: RawAuditEventRow
  ): CanonicalEventEnvelope<TPayload> {
    return Object.freeze({
      event_id: row.event_id as EventId,
      event_type: row.event_type,
      schema_version: row.schema_version,
      occurred_at: (typeof row.occurred_at === 'string'
        ? new Date(row.occurred_at).toISOString()
        : (row.occurred_at as unknown as Date).toISOString()) as IsoTimestamp,
      producer: Object.freeze(
        typeof row.producer === 'string' ? JSON.parse(row.producer) : row.producer
      ),
      workspace_id: row.workspace_id as WorkspaceId,
      correlation_id: row.correlation_id as CorrelationId,
      causation_id: row.causation_id as CausationId,
      trace_id: row.trace_id as TraceId,
      authorization_context: Object.freeze(
        typeof row.authorization_context === 'string'
          ? JSON.parse(row.authorization_context)
          : row.authorization_context
      ),
      scope_reference: Object.freeze(
        typeof row.scope_reference === 'string'
          ? JSON.parse(row.scope_reference)
          : row.scope_reference
      ),
      payload: Object.freeze(
        typeof row.payload === 'string' ? JSON.parse(row.payload) : row.payload
      ) as TPayload,
      integrity: Object.freeze(
        typeof row.integrity === 'string' ? JSON.parse(row.integrity) : row.integrity
      ),
    });
  }
}
