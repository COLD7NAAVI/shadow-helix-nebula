/**
 * Shadow : Helix Nebula (SHN) — W3C Trace Context Propagation Engine
 *
 * Implements OpenTelemetry-compliant W3C Trace Context parsing, validation,
 * formatting, and generation without external runtime dependencies (OBS-TEL-002, 0.14 Section 18).
 */

import crypto from 'node:crypto';
import {
  type Result,
  ok,
  err,
  type TraceId,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
  type ProblemDetails,
} from '@shn/error-catalog';

export interface SpanContext {
  readonly traceId: TraceId;
  readonly spanId: string;
  readonly traceFlags: number;
  readonly traceState?: string | undefined;
  readonly isRemote?: boolean | undefined;
}

const TRACE_ID_REGEX = /^[0-9a-f]{32}$/i;
const SPAN_ID_REGEX = /^[0-9a-f]{16}$/i;
const ALL_ZEROS_TRACE = '00000000000000000000000000000000';
const ALL_ZEROS_SPAN = '0000000000000000';

export function isValidTraceId(id: string): boolean {
  return TRACE_ID_REGEX.test(id) && id !== ALL_ZEROS_TRACE;
}

export function isValidSpanId(id: string): boolean {
  return SPAN_ID_REGEX.test(id) && id !== ALL_ZEROS_SPAN;
}

export function generateTraceId(): TraceId {
  return crypto.randomBytes(16).toString('hex') as TraceId;
}

export function generateSpanId(): string {
  return crypto.randomBytes(8).toString('hex');
}

/**
 * Parses W3C traceparent header format: "00-${traceId}-${spanId}-${traceFlags}"
 * Enforces strict fail-closed validation according to W3C Trace Context specification.
 */
export function parseW3CTraceparent(header: string): Result<SpanContext, ProblemDetails> {
  if (!header || typeof header !== 'string') {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Missing or non-string traceparent header',
        instance: '/tracing/w3c',
        correlationId: 'w3c.traceparent.parser',
        customStatus: 400,
      })
    );
  }

  const parts = header.trim().split('-');
  if (parts.length < 4) {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: `Malformed traceparent: expected 4 parts, received ${parts.length}`,
        instance: '/tracing/w3c',
        correlationId: 'w3c.traceparent.parser',
        customStatus: 400,
      })
    );
  }

  const [version, traceId, spanId, flags] = parts;

  // Version check (00 supported, ff invalid per W3C)
  if (version === 'ff') {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: 'Invalid traceparent version: ff is forbidden by W3C spec',
        instance: '/tracing/w3c',
        correlationId: 'w3c.traceparent.parser',
        customStatus: 400,
      })
    );
  }

  if (!traceId || !isValidTraceId(traceId)) {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: `Invalid trace_id in traceparent: must be 32 non-zero hex characters (received "${traceId}")`,
        instance: '/tracing/w3c',
        correlationId: 'w3c.traceparent.parser',
        customStatus: 400,
      })
    );
  }

  if (!spanId || !isValidSpanId(spanId)) {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: `Invalid span_id in traceparent: must be 16 non-zero hex characters (received "${spanId}")`,
        instance: '/tracing/w3c',
        correlationId: 'w3c.traceparent.parser',
        customStatus: 400,
      })
    );
  }

  if (!flags || !/^[0-9a-f]{2}$/i.test(flags)) {
    return err(
      createProblemDetails({
        errorCode: ErrorCode.INVALID_PAYLOAD_SCHEMA,
        detail: `Invalid trace_flags in traceparent: must be 2 hex characters (received "${flags}")`,
        instance: '/tracing/w3c',
        correlationId: 'w3c.traceparent.parser',
        customStatus: 400,
      })
    );
  }

  const traceFlags = parseInt(flags, 16);

  return ok({
    traceId: traceId.toLowerCase() as TraceId,
    spanId: spanId.toLowerCase(),
    traceFlags,
    isRemote: true,
  });
}

/**
 * Formats a SpanContext into a W3C traceparent header string.
 */
export function formatW3CTraceparent(context: SpanContext): string {
  const flags = (context.traceFlags & 0xff).toString(16).padStart(2, '0');
  return `00-${context.traceId}-${context.spanId}-${flags}`;
}
