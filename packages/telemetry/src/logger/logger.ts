/**
 * Shadow : Helix Nebula (SHN) — Structured Logger Implementation
 *
 * Implements typed, security-redacted structured JSON logging adhering to OBS-TEL-001.
 */

import { nowIso } from '@shn/shared-kernel';
import { redactSensitiveData, type RedactionOptions } from '../redaction/redactor.js';
import { getTelemetryContext } from '../context/telemetry-context.js';
import {
  type LogLevel,
  isLogLevelEnabled,
} from './log-level.js';
import {
  type ILogSink,
  type StructuredLogEntry,
  ConsoleLogSink,
} from './log-sink.js';

export interface LoggerOptions {
  readonly component: string;
  readonly minLevel?: LogLevel | undefined;
  readonly sink?: ILogSink | undefined;
  readonly defaultAttributes?: Readonly<Record<string, unknown>> | undefined;
  readonly enableRedaction?: boolean | undefined;
  readonly redactionOptions?: RedactionOptions | undefined;
}

export interface ILogger {
  readonly component: string;
  readonly minLevel: LogLevel;
  trace(message: string, attributes?: Record<string, unknown>): void;
  debug(message: string, attributes?: Record<string, unknown>): void;
  info(message: string, attributes?: Record<string, unknown>): void;
  warn(message: string, attributes?: Record<string, unknown>): void;
  error(message: string, attributes?: Record<string, unknown>, error?: unknown): void;
  child(componentOrAttributes: string | Record<string, unknown>): ILogger;
}

export class StructuredLogger implements ILogger {
  readonly component: string;
  readonly minLevel: LogLevel;
  private readonly sink: ILogSink;
  private readonly defaultAttributes: Readonly<Record<string, unknown>>;
  private readonly enableRedaction: boolean;
  private readonly redactionOptions?: RedactionOptions | undefined;

  constructor(options: LoggerOptions) {
    this.component = options.component;
    this.minLevel = options.minLevel ?? 'info';
    this.sink = options.sink ?? new ConsoleLogSink();
    this.defaultAttributes = options.defaultAttributes ?? {};
    this.enableRedaction = options.enableRedaction ?? true;
    this.redactionOptions = options.redactionOptions;
  }

  private log(
    level: LogLevel,
    message: string,
    attributes?: Record<string, unknown>,
    error?: unknown
  ): void {
    if (!isLogLevelEnabled(this.minLevel, level)) {
      return;
    }

    const context = getTelemetryContext();

    // Merge default attributes, context attributes, and call-site attributes
    let mergedAttrs: Record<string, unknown> | undefined;
    const hasDefault = Object.keys(this.defaultAttributes).length > 0;
    const hasContext = context?.attributes && Object.keys(context.attributes).length > 0;
    const hasCall = attributes && Object.keys(attributes).length > 0;

    if (hasDefault || hasContext || hasCall) {
      mergedAttrs = {
        ...this.defaultAttributes,
        ...(context?.attributes ?? {}),
        ...(attributes ?? {}),
      };
      if (this.enableRedaction) {
        mergedAttrs = redactSensitiveData(mergedAttrs, this.redactionOptions) as Record<string, unknown>;
      }
    }

    let sanitizedError: unknown | undefined;
    if (error !== undefined) {
      sanitizedError = this.enableRedaction
        ? redactSensitiveData(error, this.redactionOptions)
        : error;
    }

    let sanitizedMessage = message;
    if (this.enableRedaction) {
      sanitizedMessage = redactSensitiveData(message, this.redactionOptions) as string;
    }

    const entry: StructuredLogEntry = {
      timestamp: nowIso(),
      level,
      component: this.component,
      message: sanitizedMessage,
      ...(context?.correlationId ? { correlation_id: String(context.correlationId) } : {}),
      ...(context?.causationId ? { causation_id: String(context.causationId) } : {}),
      ...(context?.traceId ? { trace_id: String(context.traceId) } : {}),
      ...(context?.spanId ? { span_id: context.spanId } : {}),
      ...(context?.workspaceId ? { workspace_id: String(context.workspaceId) } : {}),
      ...(mergedAttrs && Object.keys(mergedAttrs).length > 0 ? { attributes: mergedAttrs } : {}),
      ...(sanitizedError !== undefined ? { error: sanitizedError } : {}),
    };

    this.sink.write(entry);
  }

  trace(message: string, attributes?: Record<string, unknown>): void {
    this.log('trace', message, attributes);
  }

  debug(message: string, attributes?: Record<string, unknown>): void {
    this.log('debug', message, attributes);
  }

  info(message: string, attributes?: Record<string, unknown>): void {
    this.log('info', message, attributes);
  }

  warn(message: string, attributes?: Record<string, unknown>): void {
    this.log('warn', message, attributes);
  }

  error(message: string, attributes?: Record<string, unknown>, error?: unknown): void {
    this.log('error', message, attributes, error);
  }

  child(componentOrAttributes: string | Record<string, unknown>): ILogger {
    if (typeof componentOrAttributes === 'string') {
      return new StructuredLogger({
        component: `${this.component}:${componentOrAttributes}`,
        minLevel: this.minLevel,
        sink: this.sink,
        defaultAttributes: this.defaultAttributes,
        enableRedaction: this.enableRedaction,
        redactionOptions: this.redactionOptions,
      });
    }

    return new StructuredLogger({
      component: this.component,
      minLevel: this.minLevel,
      sink: this.sink,
      defaultAttributes: {
        ...this.defaultAttributes,
        ...componentOrAttributes,
      },
      enableRedaction: this.enableRedaction,
      redactionOptions: this.redactionOptions,
    });
  }
}

export function createLogger(options: LoggerOptions): ILogger {
  return new StructuredLogger(options);
}
