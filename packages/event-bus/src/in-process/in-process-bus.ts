/**
 * Shadow : Helix Nebula (SHN) — In-Process Asynchronous Event Bus
 *
 * Implements decoupled in-memory domain event dispatching within the local process
 * with W3C trace context propagation (0.7 mod_event_bus, 0.14 Section 12).
 */

import crypto from 'node:crypto';
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
import { runWithTelemetryContext, type ILogger } from '@shn/telemetry';
import { validateCanonicalEventEnvelope } from '../registry/event-validator.js';
import {
  type EventHandler,
  type HandlerRegistrationOptions,
  isSchemaVersionCompatible,
} from '../registry/event-registry.js';

interface InProcessSubscription {
  readonly id: string;
  readonly eventType: string;
  readonly schemaVersion: string;
  readonly handlerName: string;
  readonly handler: EventHandler<unknown>;
  readonly timeoutMs: number;
}

export interface IInProcessEventBus {
  publish<TPayload = unknown>(
    envelope: CanonicalEventEnvelope<TPayload>
  ): Promise<Result<void, ProblemDetails>>;

  subscribe<TPayload = unknown>(
    eventType: string,
    handler: EventHandler<TPayload>,
    options?: Partial<HandlerRegistrationOptions> | undefined
  ): string;

  unsubscribe(subscriptionId: string): boolean;

  getSubscriptionCount(eventType?: string): number;
}

export class InProcessEventBus implements IInProcessEventBus {
  private readonly subscriptions = new Map<string, InProcessSubscription>();
  private readonly logger?: ILogger | undefined;

  constructor(logger?: ILogger) {
    this.logger = logger;
  }

  subscribe<TPayload = unknown>(
    eventType: string,
    handler: EventHandler<TPayload>,
    options?: Partial<HandlerRegistrationOptions> | undefined
  ): string {
    const id = `sub_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const sub: InProcessSubscription = {
      id,
      eventType,
      schemaVersion: options?.schemaVersion ?? '1.0.0',
      handlerName: options?.handlerName ?? `anon_${id}`,
      handler: handler as EventHandler<unknown>,
      timeoutMs: options?.timeoutMs ?? 10000,
    };
    this.subscriptions.set(id, sub);
    return id;
  }

  unsubscribe(subscriptionId: string): boolean {
    return this.subscriptions.delete(subscriptionId);
  }

  getSubscriptionCount(eventType?: string): number {
    if (!eventType) return this.subscriptions.size;
    let count = 0;
    for (const sub of this.subscriptions.values()) {
      if (sub.eventType === eventType) count++;
    }
    return count;
  }

  async publish<TPayload = unknown>(
    envelope: CanonicalEventEnvelope<TPayload>
  ): Promise<Result<void, ProblemDetails>> {
    const validation = validateCanonicalEventEnvelope<TPayload>(envelope);
    if (!validation.isValid) {
      return err(validation.problem);
    }

    const validEnvelope = validation.value;
    const matchingSubs: InProcessSubscription[] = [];

    for (const sub of this.subscriptions.values()) {
      if (sub.eventType === validEnvelope.event_type && isSchemaVersionCompatible(validEnvelope.schema_version, sub.schemaVersion)) {
        matchingSubs.push(sub);
      }
    }

    if (matchingSubs.length === 0) {
      this.logger?.debug('In-process event published with no active subscribers', {
        event_type: validEnvelope.event_type,
        event_id: validEnvelope.event_id,
      });
      return ok(undefined);
    }

    // Execute matching subscribers asynchronously in parallel with trace context propagation
    const executionPromises = matchingSubs.map(async (sub) => {
      return runWithTelemetryContext(
        {
          correlationId: validEnvelope.correlation_id,
          causationId: validEnvelope.event_id,
          traceId: validEnvelope.trace_id,
          workspaceId: validEnvelope.workspace_id,
        },
        async () => {
          let timer: NodeJS.Timeout | undefined;
          const timeoutPromise = new Promise<never>((_, reject) => {
            timer = setTimeout(() => {
              reject(new Error(`Handler "${sub.handlerName}" timed out after ${sub.timeoutMs}ms`));
            }, sub.timeoutMs);
          });

          try {
            const handlerResult = await Promise.race([
              sub.handler(validEnvelope),
              timeoutPromise,
            ]).finally(() => {
              if (timer) clearTimeout(timer);
            });

            return handlerResult;
          } catch (error) {
            const msg = error instanceof Error ? error.message : 'Unknown handler failure';
            this.logger?.error('In-process event handler failed', {
              handler: sub.handlerName,
              event_id: validEnvelope.event_id,
              event_type: validEnvelope.event_type,
              error: msg,
            });

            return err(
              createProblemDetails({
                errorCode: ErrorCode.INTERNAL_FAULT,
                detail: `Handler execution failed: ${msg}`,
                instance: `/events/handler/${sub.handlerName}`,
                correlationId: validEnvelope.correlation_id,
                customStatus: 500,
              })
            );
          }
        }
      );
    });

    const results = await Promise.all(executionPromises);

    // If any handler failed, return the first failure
    for (const res of results) {
      if (res.isErr) {
        return res;
      }
    }

    return ok(undefined);
  }
}

export function createInProcessEventBus(logger?: ILogger): IInProcessEventBus {
  return new InProcessEventBus(logger);
}
