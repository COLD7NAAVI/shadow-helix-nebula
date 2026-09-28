/**
 * Shadow : Helix Nebula (SHN) — Telemetry Context Store
 *
 * Implements asynchronous context propagation across async task boundaries
 * using Node.js AsyncLocalStorage (0.14 Section 14, 18, OBS-TEL-002).
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import type {
  CorrelationId,
  CausationId,
  TraceId,
  WorkspaceId,
} from '@shn/shared-kernel';

export interface TelemetryContextData {
  readonly correlationId?: CorrelationId | string;
  readonly causationId?: CausationId | string;
  readonly traceId?: TraceId | string;
  readonly spanId?: string;
  readonly workspaceId?: WorkspaceId | string;
  readonly actorId?: string;
  readonly attributes?: Readonly<Record<string, unknown>>;
}

const storage = new AsyncLocalStorage<TelemetryContextData>();

export function getTelemetryContext(): TelemetryContextData | undefined {
  return storage.getStore();
}

export function runWithTelemetryContext<R>(
  context: TelemetryContextData,
  fn: () => R
): R {
  const current = storage.getStore();
  const merged: TelemetryContextData = {
    ...current,
    ...context,
    attributes: {
      ...(current?.attributes ?? {}),
      ...(context.attributes ?? {}),
    },
  };
  return storage.run(merged, fn);
}

export function bindTelemetryContext<T extends (...args: unknown[]) => unknown>(
  context: TelemetryContextData,
  fn: T
): T {
  return ((...args: unknown[]) => runWithTelemetryContext(context, () => fn(...args))) as T;
}
