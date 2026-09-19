/**
 * Shadow : Helix Nebula (SHN) — Canonical Event Envelope
 *
 * Enforces API-INV-06: Canonical Envelope Integrity & Cryptographic Lineage Mandatory.
 */

import type {
  EventId,
  WorkspaceId,
  CorrelationId,
  CausationId,
  TraceId,
} from '../primitives/identifiers.js';
import type { IsoTimestamp } from '../primitives/timestamps.js';
import type { SecurityContextToken } from './security-context.js';

export interface ProducerMetadata {
  readonly module_name: string;
  readonly node_id: string;
  readonly environment: string;
  readonly build_version: string;
}

export interface ScopeReference {
  readonly scope_id: string;
  readonly scope_sha256: string;
}

export interface IntegrityBlock {
  readonly algorithm: 'HMAC-SHA256' | 'Ed25519';
  readonly signature: string;
  readonly key_id: string;
}

export interface CanonicalEventEnvelope<TPayload = unknown> {
  /** Time-ordered, globally unique event identifier (UUIDv7) */
  readonly event_id: EventId;
  /** Dot-notated event classification (e.g. 'scan.host.discovered') */
  readonly event_type: string;
  /** SemVer specification of the payload schema (e.g. '1.0.0') */
  readonly schema_version: string;
  /** Microsecond-precision UTC timestamp of domain occurrence */
  readonly occurred_at: IsoTimestamp;
  /** Emitting service and node metadata */
  readonly producer: ProducerMetadata;
  /** Workspace boundary anchor (multi-tenant hermeticity) */
  readonly workspace_id: WorkspaceId;
  /** Distributed root transaction identifier */
  readonly correlation_id: CorrelationId;
  /** Immediate predecessor command or event ID */
  readonly causation_id: CausationId;
  /** W3C / OpenTelemetry distributed trace identifier */
  readonly trace_id: TraceId;
  /** Authorized security principal and role context */
  readonly authorization_context: SecurityContextToken;
  /** Cryptographic hash/ID of the authorized target scope token */
  readonly scope_reference: ScopeReference;
  /** Strongly typed domain event payload */
  readonly payload: TPayload;
  /** Cryptographic signature verifying envelope authenticity */
  readonly integrity: IntegrityBlock;
}

export interface CreateEventEnvelopeOptions<TPayload> {
  eventId: EventId;
  eventType: string;
  schemaVersion: string;
  occurredAt: IsoTimestamp;
  producer: ProducerMetadata;
  workspaceId: WorkspaceId;
  correlationId: CorrelationId;
  causationId: CausationId;
  traceId: TraceId;
  authorizationContext: SecurityContextToken;
  scopeReference: ScopeReference;
  payload: TPayload;
  integrity: IntegrityBlock;
}

export function createCanonicalEventEnvelope<TPayload>(
  options: CreateEventEnvelopeOptions<TPayload>
): CanonicalEventEnvelope<TPayload> {
  return Object.freeze({
    event_id: options.eventId,
    event_type: options.eventType,
    schema_version: options.schemaVersion,
    occurred_at: options.occurredAt,
    producer: Object.freeze({ ...options.producer }),
    workspace_id: options.workspaceId,
    correlation_id: options.correlationId,
    causation_id: options.causationId,
    trace_id: options.traceId,
    authorization_context: Object.freeze({ ...options.authorizationContext }),
    scope_reference: Object.freeze({ ...options.scopeReference }),
    payload: Object.freeze(options.payload),
    integrity: Object.freeze({ ...options.integrity }),
  });
}
