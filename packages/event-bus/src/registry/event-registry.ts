/**
 * Shadow : Helix Nebula (SHN) — Event Handler Registry
 *
 * Implements deterministic handler registration, duplicate prevention,
 * and SemVer compatibility evaluation (0.14 Section 15).
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

export type EventHandler<TPayload = unknown> = (
  envelope: CanonicalEventEnvelope<TPayload>
) => Promise<Result<void, ProblemDetails>>;

export interface HandlerRegistrationOptions {
  readonly schemaVersion: string;
  readonly handlerName: string;
  readonly concurrencyLimit?: number | undefined;
  readonly timeoutMs?: number | undefined;
}

export interface RegisteredHandler<TPayload = unknown> {
  readonly eventType: string;
  readonly handlerName: string;
  readonly schemaVersion: string;
  readonly concurrencyLimit: number;
  readonly timeoutMs: number;
  readonly handler: EventHandler<TPayload>;
}

/**
 * Evaluates whether an incoming event's schemaVersion is compatible with the handler's supported schemaVersion.
 * Invariants (0.14 Section 15.2):
 * - Major versions must match exactly (breaking changes).
 * - Additive minor versions are compatible (event.minor >= handler.minor).
 */
export function isSchemaVersionCompatible(eventVersion: string, handlerVersion: string): boolean {
  const [eMajor, eMinor] = eventVersion.split('.').map(n => parseInt(n ?? '0', 10));
  const [hMajor, hMinor] = handlerVersion.split('.').map(n => parseInt(n ?? '0', 10));

  if (eMajor === undefined || hMajor === undefined) return false;
  if (eMajor !== hMajor) return false;

  // Event with higher minor version is compatible (additive changes)
  return (eMinor ?? 0) >= (hMinor ?? 0);
}

export interface IEventRegistry {
  registerHandler<TPayload = unknown>(
    eventType: string,
    handler: EventHandler<TPayload>,
    options: HandlerRegistrationOptions
  ): Result<void, ProblemDetails>;
  getHandlers(eventType: string, eventVersion?: string): readonly RegisteredHandler[];
  hasHandler(eventType: string, handlerName: string): boolean;
  unregisterHandler(eventType: string, handlerName: string): boolean;
  getAllRegisteredTypes(): readonly string[];
}

export class EventRegistry implements IEventRegistry {
  private readonly handlersByEvent = new Map<string, Map<string, RegisteredHandler>>();

  registerHandler<TPayload = unknown>(
    eventType: string,
    handler: EventHandler<TPayload>,
    options: HandlerRegistrationOptions
  ): Result<void, ProblemDetails> {
    if (!eventType || typeof eventType !== 'string' || eventType.trim().length === 0) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
          detail: 'eventType must be a non-empty string',
          instance: '/registry/events',
          correlationId: 'registry.event.register',
          customStatus: 400,
        })
      );
    }

    if (!options?.handlerName || typeof options.handlerName !== 'string' || options.handlerName.trim().length === 0) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
          detail: 'handlerName must be a non-empty string',
          instance: '/registry/events',
          correlationId: 'registry.event.register',
          customStatus: 400,
        })
      );
    }

    if (typeof handler !== 'function') {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
          detail: 'handler must be an executable function',
          instance: '/registry/events',
          correlationId: 'registry.event.register',
          customStatus: 400,
        })
      );
    }

    let handlersForType = this.handlersByEvent.get(eventType);
    if (!handlersForType) {
      handlersForType = new Map<string, RegisteredHandler>();
      this.handlersByEvent.set(eventType, handlersForType);
    }

    if (handlersForType.has(options.handlerName)) {
      return err(
        createProblemDetails({
          errorCode: ErrorCode.IDEMPOTENCY_CONFLICT,
          detail: `Duplicate handler registration rejected: handler "${options.handlerName}" is already registered for event "${eventType}"`,
          instance: `/registry/events/${eventType}`,
          correlationId: 'registry.event.duplicate',
          customStatus: 409,
        })
      );
    }

    const registered: RegisteredHandler = {
      eventType,
      handlerName: options.handlerName,
      schemaVersion: options.schemaVersion,
      concurrencyLimit: options.concurrencyLimit ?? 10,
      timeoutMs: options.timeoutMs ?? 30000,
      handler: handler as EventHandler<unknown>,
    };

    handlersForType.set(options.handlerName, registered);
    return ok(undefined);
  }

  getHandlers(eventType: string, eventVersion?: string): readonly RegisteredHandler[] {
    const handlersForType = this.handlersByEvent.get(eventType);
    if (!handlersForType) return [];

    const list = Array.from(handlersForType.values());
    if (!eventVersion) return list;

    // Filter compatible versions
    return list.filter(h => isSchemaVersionCompatible(eventVersion, h.schemaVersion));
  }

  hasHandler(eventType: string, handlerName: string): boolean {
    return Boolean(this.handlersByEvent.get(eventType)?.has(handlerName));
  }

  unregisterHandler(eventType: string, handlerName: string): boolean {
    return Boolean(this.handlersByEvent.get(eventType)?.delete(handlerName));
  }

  getAllRegisteredTypes(): readonly string[] {
    return Array.from(this.handlersByEvent.keys());
  }
}

export function createEventRegistry(): IEventRegistry {
  return new EventRegistry();
}
