/**
 * Shadow : Helix Nebula (SHN) — In-Process Asynchronous Event Bus Pure Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateUUIDv7,
  nowIso,
  ok,
  err,
  type CanonicalEventEnvelope,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import { getTelemetryContext } from '@shn/telemetry';
import { createInProcessEventBus } from '../../dist/index.js';

function createValidEnvelopeFixture(eventType = 'scan.host.discovered', schemaVersion = '1.0.0'): CanonicalEventEnvelope<Record<string, unknown>> {
  return {
    event_id: generateUUIDv7(),
    event_type: eventType,
    schema_version: schemaVersion,
    occurred_at: nowIso(),
    producer: {
      module_name: 'mod_scanner',
      node_id: 'scanner-node-1',
      environment: 'production',
      build_version: '0.1.0',
    },
    workspace_id: generateUUIDv7(),
    correlation_id: generateUUIDv7(),
    causation_id: generateUUIDv7(),
    trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
    authorization_context: {
      principal_id: 'usr-1',
      token_id: generateUUIDv7(),
      roles: ['operator'],
      signature: 'valid-sig',
      expires_at: nowIso(),
    },
    scope_reference: {
      scope_id: 'scope-1',
      scope_sha256: 'a'.repeat(64),
    },
    payload: {
      target_ip: '10.0.0.1',
      ports: [80, 443],
    },
    integrity: {
      algorithm: 'HMAC-SHA256',
      signature: 'sig-1234',
      key_id: 'key-1',
    },
  };
}

describe('In-Process Asynchronous Event Bus (Pure Unit Tests)', () => {
  it('should deliver events to subscribed handlers and propagate telemetry context', async () => {
    const bus = createInProcessEventBus();
    const envelope = createValidEnvelopeFixture();

    let handled = false;
    let observedCorrelationId = '';
    let observedWorkspaceId = '';

    bus.subscribe(
      'scan.host.discovered',
      async (evt) => {
        handled = true;
        const ctx = getTelemetryContext();
        observedCorrelationId = ctx?.correlationId ?? '';
        observedWorkspaceId = ctx?.workspaceId ?? '';
        assert.equal(evt.event_id, envelope.event_id);
        return ok(undefined);
      },
      { handlerName: 'test-sync-handler', schemaVersion: '1.0.0' }
    );

    const publishResult = await bus.publish(envelope);
    assert.ok(publishResult.isOk);
    assert.equal(handled, true);
    assert.equal(observedCorrelationId, envelope.correlation_id);
    assert.equal(observedWorkspaceId, envelope.workspace_id);
  });

  it('should deliver to multiple matching subscribers concurrently', async () => {
    const bus = createInProcessEventBus();
    const envelope = createValidEnvelopeFixture();

    let handler1Called = false;
    let handler2Called = false;

    bus.subscribe('scan.host.discovered', async () => {
      handler1Called = true;
      return ok(undefined);
    });

    bus.subscribe('scan.host.discovered', async () => {
      handler2Called = true;
      return ok(undefined);
    });

    assert.equal(bus.getSubscriptionCount('scan.host.discovered'), 2);

    const publishResult = await bus.publish(envelope);
    assert.ok(publishResult.isOk);
    assert.equal(handler1Called, true);
    assert.equal(handler2Called, true);
  });

  it('should allow unsubscribing cleanly', async () => {
    const bus = createInProcessEventBus();
    const envelope = createValidEnvelopeFixture();

    let callCount = 0;
    const subId = bus.subscribe('scan.host.discovered', async () => {
      callCount++;
      return ok(undefined);
    });

    assert.equal(bus.getSubscriptionCount('scan.host.discovered'), 1);

    await bus.publish(envelope);
    assert.equal(callCount, 1);

    const unsubscribed = bus.unsubscribe(subId);
    assert.equal(unsubscribed, true);
    assert.equal(bus.getSubscriptionCount('scan.host.discovered'), 0);

    await bus.publish(envelope);
    assert.equal(callCount, 1); // Not called again
  });

  it('should handle handler timeouts and return ProblemDetails fail-closed', async () => {
    const bus = createInProcessEventBus();
    const envelope = createValidEnvelopeFixture();

    bus.subscribe(
      'scan.host.discovered',
      async () => {
        // Deliberately delay longer than timeout
        await new Promise((resolve) => setTimeout(resolve, 150));
        return ok(undefined);
      },
      { handlerName: 'slow-handler', timeoutMs: 50 }
    );

    const result = await bus.publish(envelope);
    assert.ok(result.isErr);
    assert.equal(result.error.error_code, ErrorCode.INTERNAL_FAULT);
    assert.ok(result.error.detail.includes('timed out after 50ms'));
  });

  it('should capture handler exceptions and convert them to ProblemDetails', async () => {
    const bus = createInProcessEventBus();
    const envelope = createValidEnvelopeFixture();

    bus.subscribe(
      'scan.host.discovered',
      async () => {
        throw new Error('Explosion in handler logic');
      },
      { handlerName: 'crashing-handler' }
    );

    const result = await bus.publish(envelope);
    assert.ok(result.isErr);
    assert.equal(result.error.error_code, ErrorCode.INTERNAL_FAULT);
    assert.ok(result.error.detail.includes('Explosion in handler logic'));
  });

  it('should reject malformed event envelope fail-closed without dispatching', async () => {
    const bus = createInProcessEventBus();
    const badEnvelope = createValidEnvelopeFixture() as any;
    badEnvelope.event_id = 'not-a-uuid';

    let called = false;
    bus.subscribe('scan.host.discovered', async () => {
      called = true;
      return ok(undefined);
    });

    const result = await bus.publish(badEnvelope);
    assert.ok(result.isErr);
    assert.equal(result.error.error_code, ErrorCode.INVALID_PAYLOAD_SCHEMA);
    assert.equal(called, false);
  });
});
