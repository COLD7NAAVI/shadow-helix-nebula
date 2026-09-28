/**
 * Shadow : Helix Nebula (SHN) — OpenTelemetry-Compatible Distributed Tracer
 *
 * Implements in-process span lifecycle, parent-child link tracking, and W3C context
 * propagation using native Node.js AsyncLocalStorage (OBS-TEL-002, 0.14 Section 18).
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import type { TraceId } from '@shn/shared-kernel';
import { redactSensitiveData } from '../redaction/redactor.js';
import {
  type SpanContext,
  generateTraceId,
  generateSpanId,
} from './trace-context.js';
import { runWithTelemetryContext, getTelemetryContext } from '../context/telemetry-context.js';

export type SpanKind = 'INTERNAL' | 'SERVER' | 'CLIENT' | 'PRODUCER' | 'CONSUMER';

export interface SpanStatus {
  readonly code: 'OK' | 'ERROR' | 'UNSET';
  readonly description?: string | undefined;
}

export interface SpanEvent {
  readonly name: string;
  readonly time: number;
  readonly attributes?: Readonly<Record<string, unknown>> | undefined;
}

export interface SpanOptions {
  readonly kind?: SpanKind | undefined;
  readonly parentContext?: SpanContext | undefined;
  readonly attributes?: Record<string, unknown> | undefined;
  readonly startTime?: number | undefined;
}

export interface ISpan {
  readonly context: SpanContext;
  readonly name: string;
  readonly kind: SpanKind;
  readonly parentSpanId?: string | undefined;
  readonly startTime: number;
  readonly endTime?: number | undefined;
  readonly status: SpanStatus;
  readonly attributes: Readonly<Record<string, unknown>>;
  readonly events: readonly SpanEvent[];
  setAttribute(key: string, value: unknown): this;
  setAttributes(attributes: Record<string, unknown>): this;
  addEvent(name: string, attributes?: Record<string, unknown>): this;
  setStatus(code: 'OK' | 'ERROR', description?: string): this;
  recordException(error: unknown): this;
  end(endTime?: number): void;
}

export class Span implements ISpan {
  readonly context: SpanContext;
  readonly name: string;
  readonly kind: SpanKind;
  readonly parentSpanId?: string | undefined;
  readonly startTime: number;
  private _endTime?: number | undefined;
  private _status: SpanStatus = { code: 'UNSET' };
  private readonly _attributes: Record<string, unknown> = {};
  private readonly _events: SpanEvent[] = [];
  private _isEnded: boolean = false;

  constructor(
    name: string,
    context: SpanContext,
    options?: SpanOptions,
    parentSpanId?: string
  ) {
    this.name = name;
    this.context = context;
    this.kind = options?.kind ?? 'INTERNAL';
    this.parentSpanId = parentSpanId;
    this.startTime = options?.startTime ?? Date.now();

    if (options?.attributes) {
      this.setAttributes(options.attributes);
    }
  }

  get endTime(): number | undefined {
    return this._endTime;
  }

  get status(): SpanStatus {
    return this._status;
  }

  get attributes(): Readonly<Record<string, unknown>> {
    return this._attributes;
  }

  get events(): readonly SpanEvent[] {
    return this._events;
  }

  setAttribute(key: string, value: unknown): this {
    if (this._isEnded) return this;
    const sanitized = redactSensitiveData(value);
    this._attributes[key] = sanitized;
    return this;
  }

  setAttributes(attributes: Record<string, unknown>): this {
    if (this._isEnded) return this;
    for (const [k, v] of Object.entries(attributes)) {
      this.setAttribute(k, v);
    }
    return this;
  }

  addEvent(name: string, attributes?: Record<string, unknown>): this {
    if (this._isEnded) return this;
    const sanitized = attributes
      ? (redactSensitiveData(attributes) as Record<string, unknown>)
      : undefined;
    this._events.push({
      name,
      time: Date.now(),
      ...(sanitized ? { attributes: sanitized } : {}),
    });
    return this;
  }

  setStatus(code: 'OK' | 'ERROR', description?: string): this {
    if (this._isEnded) return this;
    this._status = { code, description };
    return this;
  }

  recordException(error: unknown): this {
    if (this._isEnded) return this;
    this.setStatus('ERROR');
    const sanitized = redactSensitiveData(error) as Record<string, unknown>;
    this.addEvent('exception', {
      'exception.type': (error as Error)?.name ?? 'Error',
      'exception.message': (error as Error)?.message ?? String(error),
      ...(sanitized?.['stack'] ? { 'exception.stacktrace': sanitized['stack'] } : {}),
    });
    return this;
  }

  end(endTime?: number): void {
    if (this._isEnded) return;
    this._isEnded = true;
    this._endTime = endTime ?? Date.now();
  }
}

export interface ITracer {
  startSpan(name: string, options?: SpanOptions): ISpan;
  withSpan<T>(name: string, fn: (span: ISpan) => Promise<T>, options?: SpanOptions): Promise<T>;
  getActiveSpan(): ISpan | undefined;
  getActiveContext(): SpanContext | undefined;
}

const activeSpanStorage = new AsyncLocalStorage<ISpan>();

export class DistributedTracer implements ITracer {
  constructor(private readonly serviceName: string = 'shn-node') {}

  getActiveSpan(): ISpan | undefined {
    return activeSpanStorage.getStore();
  }

  getActiveContext(): SpanContext | undefined {
    return this.getActiveSpan()?.context;
  }

  startSpan(name: string, options?: SpanOptions): ISpan {
    const activeSpan = this.getActiveSpan();
    const parentContext = options?.parentContext ?? activeSpan?.context;

    const traceId: TraceId = parentContext ? parentContext.traceId : generateTraceId();
    const spanId = generateSpanId();
    const traceFlags = parentContext ? parentContext.traceFlags : 1;

    const context: SpanContext = {
      traceId,
      spanId,
      traceFlags,
    };

    const span = new Span(name, context, options, parentContext?.spanId);
    span.setAttribute('service.name', this.serviceName);

    return span;
  }

  async withSpan<T>(
    name: string,
    fn: (span: ISpan) => Promise<T>,
    options?: SpanOptions
  ): Promise<T> {
    const span = this.startSpan(name, options);

    return activeSpanStorage.run(span, async () => {
      // Also sync with global telemetry context
      const currentTelem = getTelemetryContext();
      return runWithTelemetryContext(
        {
          ...currentTelem,
          traceId: span.context.traceId,
          spanId: span.context.spanId,
        },
        async () => {
          try {
            const result = await fn(span);
            if (span.status.code === 'UNSET') {
              span.setStatus('OK');
            }
            return result;
          } catch (error) {
            span.recordException(error);
            throw error;
          } finally {
            span.end();
          }
        }
      );
    });
  }
}

export function createTracer(serviceName: string = 'shn-node'): ITracer {
  return new DistributedTracer(serviceName);
}
