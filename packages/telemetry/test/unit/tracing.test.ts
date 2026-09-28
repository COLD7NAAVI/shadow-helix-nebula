/**
 * Shadow : Helix Nebula (SHN) — Distributed Tracing Pure Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseW3CTraceparent,
  formatW3CTraceparent,
  generateTraceId,
  generateSpanId,
  createTracer,
  getTelemetryContext,
} from '../../dist/index.js';

describe('W3C Distributed Tracing (Pure Unit Tests)', () => {
  it('should parse valid W3C traceparent headers', () => {
    const header = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
    const result = parseW3CTraceparent(header);

    assert.ok(result.isOk);
    assert.equal(result.value.traceId, '4bf92f3577b34da6a3ce929d0e0e4736');
    assert.equal(result.value.spanId, '00f067aa0ba902b7');
    assert.equal(result.value.traceFlags, 1);
    assert.equal(result.value.isRemote, true);
  });

  it('should reject invalid or malformed traceparent headers fail-closed', () => {
    // Malformed part counts
    assert.ok(parseW3CTraceparent('invalid-trace').isErr);
    // Version ff forbidden
    assert.ok(parseW3CTraceparent('ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01').isErr);
    // All-zero traceId forbidden
    assert.ok(parseW3CTraceparent('00-00000000000000000000000000000000-00f067aa0ba902b7-01').isErr);
    // All-zero spanId forbidden
    assert.ok(parseW3CTraceparent('00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01').isErr);
    // Non-hex chars
    assert.ok(parseW3CTraceparent('00-4bf92f3577b34da6a3ce929d0e0eZZZZ-00f067aa0ba902b7-01').isErr);
  });

  it('should format SpanContext into compliant W3C traceparent string', () => {
    const context = {
      traceId: '4bf92f3577b34da6a3ce929d0e0e4736' as any,
      spanId: '00f067aa0ba902b7',
      traceFlags: 1,
    };
    const formatted = formatW3CTraceparent(context);
    assert.equal(formatted, '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
  });

  it('should generate valid 32-char traceId and 16-char spanId', () => {
    const traceId = generateTraceId();
    const spanId = generateSpanId();

    assert.equal(traceId.length, 32);
    assert.match(traceId, /^[0-9a-f]{32}$/);
    assert.notEqual(traceId, '00000000000000000000000000000000');

    assert.equal(spanId.length, 16);
    assert.match(spanId, /^[0-9a-f]{16}$/);
    assert.notEqual(spanId, '0000000000000000');
  });

  it('should propagate parent-child span context and active spans via AsyncLocalStorage', async () => {
    const tracer = createTracer('test-subsystem');

    await tracer.withSpan('parent-operation', async (parentSpan) => {
      assert.equal(parentSpan.name, 'parent-operation');
      assert.equal(tracer.getActiveSpan(), parentSpan);

      // Verify global telemetry context synchronization
      const telemContext = getTelemetryContext();
      assert.equal(telemContext?.traceId, parentSpan.context.traceId);
      assert.equal(telemContext?.spanId, parentSpan.context.spanId);

      await tracer.withSpan('child-operation', async (childSpan) => {
        assert.equal(childSpan.name, 'child-operation');
        assert.equal(childSpan.context.traceId, parentSpan.context.traceId);
        assert.equal(childSpan.parentSpanId, parentSpan.context.spanId);
        assert.notEqual(childSpan.context.spanId, parentSpan.context.spanId);

        childSpan.setAttribute('items.processed', 42);
        childSpan.addEvent('checkpoint_reached', { step: 1 });
      });

      assert.equal(tracer.getActiveSpan(), parentSpan);
    });

    assert.equal(tracer.getActiveSpan(), undefined);
  });

  it('should record exceptions on spans and mark status as ERROR', async () => {
    const tracer = createTracer('error-tracing');
    let capturedSpan: any;

    await assert.rejects(
      async () => {
        await tracer.withSpan('failing-span', async (span) => {
          capturedSpan = span;
          throw new Error('Critical probe failure');
        });
      },
      /Critical probe failure/
    );

    assert.equal(capturedSpan.status.code, 'ERROR');
    assert.equal(capturedSpan.events.length, 1);
    assert.equal(capturedSpan.events[0].name, 'exception');
    assert.equal(capturedSpan.events[0].attributes['exception.message'], 'Critical probe failure');
    assert.ok(capturedSpan.endTime !== undefined);
  });
});
