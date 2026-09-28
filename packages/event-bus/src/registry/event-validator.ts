/**
 * Shadow : Helix Nebula (SHN) — Canonical Event Envelope Runtime Validator
 *
 * Enforces API-INV-06 (Canonical Envelope Integrity & Cryptographic Lineage Mandatory)
 * and fail-closed validation of untrusted event payloads at process boundaries.
 */

import {
  isValidUUID,
  parseIsoTimestamp,
  type CanonicalEventEnvelope,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
  type ProblemDetails,
  type InvalidParam,
} from '@shn/error-catalog';

const SEMVER_REGEX = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;
const EVENT_TYPE_REGEX = /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/i;

export function validateCanonicalEventEnvelope<TPayload = unknown>(
  input: unknown
): { isValid: true; value: CanonicalEventEnvelope<TPayload> } | { isValid: false; problem: ProblemDetails } {
  const invalidParams: InvalidParam[] = [];

  if (!input || typeof input !== 'object') {
    return {
      isValid: false,
      problem: createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Event envelope must be a non-null object',
        instance: '/events/validator',
        correlationId: 'validator.envelope',
        customStatus: 400,
      }),
    };
  }

  const raw = input as Record<string, unknown>;

  // 1. event_id (UUIDv7)
  if (!raw['event_id'] || typeof raw['event_id'] !== 'string' || !isValidUUID(raw['event_id'])) {
    invalidParams.push({
      name: 'event_id',
      reason: 'Must be a valid UUIDv7 string',
    });
  }

  // 2. event_type
  if (!raw['event_type'] || typeof raw['event_type'] !== 'string' || !EVENT_TYPE_REGEX.test(raw['event_type'])) {
    invalidParams.push({
      name: 'event_type',
      reason: 'Must be a dot-notated event type identifier (e.g. "scan.host.discovered")',
    });
  }

  // 3. schema_version (SemVer)
  if (!raw['schema_version'] || typeof raw['schema_version'] !== 'string' || !SEMVER_REGEX.test(raw['schema_version'])) {
    invalidParams.push({
      name: 'schema_version',
      reason: 'Must be a valid Semantic Version string (e.g. "1.0.0")',
    });
  }

  // 4. occurred_at (ISO 8601)
  if (!raw['occurred_at'] || typeof raw['occurred_at'] !== 'string') {
    invalidParams.push({
      name: 'occurred_at',
      reason: 'Must be a non-empty ISO 8601 timestamp string',
    });
  } else {
    const parsedTime = parseIsoTimestamp(raw['occurred_at']);
    if (!parsedTime.isOk) {
      invalidParams.push({
        name: 'occurred_at',
        reason: 'Invalid ISO 8601 timestamp format',
      });
    }
  }

  // 5. producer
  if (!raw['producer'] || typeof raw['producer'] !== 'object') {
    invalidParams.push({
      name: 'producer',
      reason: 'Must be an object with module_name, node_id, environment, build_version',
    });
  } else {
    const prod = raw['producer'] as Record<string, unknown>;
    if (!prod['module_name'] || typeof prod['module_name'] !== 'string') {
      invalidParams.push({ name: 'producer.module_name', reason: 'Must be a non-empty string' });
    }
    if (!prod['node_id'] || typeof prod['node_id'] !== 'string') {
      invalidParams.push({ name: 'producer.node_id', reason: 'Must be a non-empty string' });
    }
  }

  // 6. workspace_id (UUID)
  if (!raw['workspace_id'] || typeof raw['workspace_id'] !== 'string' || !isValidUUID(raw['workspace_id'])) {
    invalidParams.push({
      name: 'workspace_id',
      reason: 'Must be a valid UUID string representing the tenant workspace anchor',
    });
  }

  // 7. correlation_id (UUID)
  if (!raw['correlation_id'] || typeof raw['correlation_id'] !== 'string' || !isValidUUID(raw['correlation_id'])) {
    invalidParams.push({
      name: 'correlation_id',
      reason: 'Must be a valid UUID string representing the root transaction identifier',
    });
  }

  // 8. causation_id (UUID)
  if (!raw['causation_id'] || typeof raw['causation_id'] !== 'string' || !isValidUUID(raw['causation_id'])) {
    invalidParams.push({
      name: 'causation_id',
      reason: 'Must be a valid UUID string representing the immediate predecessor identifier',
    });
  }

  // 9. trace_id
  if (!raw['trace_id'] || typeof raw['trace_id'] !== 'string' || raw['trace_id'].trim().length === 0) {
    invalidParams.push({
      name: 'trace_id',
      reason: 'Must be a non-empty W3C distributed trace identifier',
    });
  }

  // 10. authorization_context
  if (!raw['authorization_context'] || typeof raw['authorization_context'] !== 'object') {
    invalidParams.push({
      name: 'authorization_context',
      reason: 'Must be an object containing SecurityContextToken metadata',
    });
  }

  // 11. scope_reference
  if (!raw['scope_reference'] || typeof raw['scope_reference'] !== 'object') {
    invalidParams.push({
      name: 'scope_reference',
      reason: 'Must be an object containing scope_id and scope_sha256',
    });
  } else {
    const scope = raw['scope_reference'] as Record<string, unknown>;
    if (!scope['scope_sha256'] || typeof scope['scope_sha256'] !== 'string' || !/^[0-9a-f]{64}$/i.test(scope['scope_sha256'])) {
      invalidParams.push({
        name: 'scope_reference.scope_sha256',
        reason: 'Must be a 64-character hex SHA-256 hash of the authorized scope',
      });
    }
  }

  // 12. payload
  if (raw['payload'] === undefined) {
    invalidParams.push({
      name: 'payload',
      reason: 'Must be defined domain payload',
    });
  }

  // 13. integrity
  if (!raw['integrity'] || typeof raw['integrity'] !== 'object') {
    invalidParams.push({
      name: 'integrity',
      reason: 'Must be an object containing algorithm, signature, and key_id',
    });
  }

  if (invalidParams.length > 0) {
    const corrId = typeof raw['correlation_id'] === 'string' && isValidUUID(raw['correlation_id'])
      ? raw['correlation_id']
      : 'validator.envelope';

    return {
      isValid: false,
      problem: createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: `Canonical event envelope failed structural validation: ${invalidParams.map(p => `${p.name} (${p.reason})`).join(', ')}`,
        instance: '/events/validator',
        correlationId: corrId,
        customStatus: 400,
        invalidParams,
      }),
    };
  }

  return {
    isValid: true,
    value: input as CanonicalEventEnvelope<TPayload>,
  };
}
