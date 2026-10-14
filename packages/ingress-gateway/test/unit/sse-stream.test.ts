/**
 * Shadow : Helix Nebula (SHN) — SSE EventStreamHub Unit Test Suite
 *
 * Verifies multi-tenant isolation, subscriber tracking, event dispatching,
 * and graceful disconnect handling in EventStreamHub.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { EventStreamHub } from '../../dist/index.js';
import type { IngressRequest, IngressResponse } from '../../dist/index.js';

function createMockSseClient() {
  const reqEmitter = new EventEmitter();
  const resEmitter = new EventEmitter();
  const chunks: string[] = [];
  const headers: Record<string, string> = {};
  let statusCode = 0;

  const mockReq = {
    raw: reqEmitter,
  } as unknown as IngressRequest;

  const mockRes = {
    setHeader(k: string, v: string) {
      headers[k.toLowerCase()] = v;
      return this;
    },
    status(c: number) {
      statusCode = c;
      return this;
    },
    raw: Object.assign(resEmitter, {
      destroyed: false,
      writableEnded: false,
      write(chunk: string) {
        chunks.push(chunk);
        return true;
      },
      end() {
        this.writableEnded = true;
      },
    }),
  } as unknown as IngressResponse;

  return { mockReq, mockRes, chunks, headers, reqEmitter, resEmitter, getStatusCode: () => statusCode };
}

describe('EventStreamHub (Unit Tests)', () => {
  it('should register client, set SSE headers, and send handshake event', () => {
    const hub = new EventStreamHub(60000);
    const { mockReq, mockRes, chunks, headers, getStatusCode } = createMockSseClient();

    const client = hub.register(mockReq, mockRes, 'workspace-alpha', 'user-001');

    assert.equal(getStatusCode(), 200);
    assert.equal(headers['content-type'], 'text/event-stream; charset=utf-8');
    assert.equal(headers['cache-control'], 'no-cache, no-transform');
    assert.equal(headers['connection'], 'keep-alive');
    assert.equal(hub.subscriberCount('workspace-alpha'), 1);

    // Initial handshake check
    assert.ok(chunks.length >= 1);
    assert.ok(chunks[0]!.includes('event: connected'));
    assert.ok(chunks[0]!.includes('"status":"CONNECTED"'));
    assert.ok(chunks[0]!.includes('workspace-alpha'));

    hub.unregister(client);
    assert.equal(hub.subscriberCount('workspace-alpha'), 0);
  });

  it('should strictly isolate events between different workspaces (DATA-INV-08)', () => {
    const hub = new EventStreamHub(60000);
    const clientAlpha = createMockSseClient();
    const clientBeta = createMockSseClient();

    const handleA = hub.register(clientAlpha.mockReq, clientAlpha.mockRes, 'ws-alpha');
    const handleB = hub.register(clientBeta.mockReq, clientBeta.mockRes, 'ws-beta');

    assert.equal(hub.subscriberCount('ws-alpha'), 1);
    assert.equal(hub.subscriberCount('ws-beta'), 1);
    assert.equal(hub.subscriberCount(), 2);

    // Clear initial handshake chunks
    clientAlpha.chunks.length = 0;
    clientBeta.chunks.length = 0;

    // Publish event exclusively to ws-alpha
    const delivered = hub.publish('ws-alpha', 'execution.completed', { executionId: 'exec-123', status: 'SUCCESS' });
    assert.equal(delivered, 1);

    // Alpha must receive the event
    assert.equal(clientAlpha.chunks.length, 1);
    assert.ok(clientAlpha.chunks[0]!.includes('event: execution.completed'));
    assert.ok(clientAlpha.chunks[0]!.includes('exec-123'));

    // Beta must receive ZERO events (Strict Workspace Isolation)
    assert.equal(clientBeta.chunks.length, 0);

    hub.unregister(handleA);
    hub.unregister(handleB);
  });

  it('should clean up client on request close event', () => {
    const hub = new EventStreamHub(60000);
    const client = createMockSseClient();

    hub.register(client.mockReq, client.mockRes, 'ws-gamma');
    assert.equal(hub.subscriberCount('ws-gamma'), 1);

    // Simulate client closing browser tab
    client.reqEmitter.emit('close');

    assert.equal(hub.subscriberCount('ws-gamma'), 0);
  });

  it('should broadcast to multiple clients in the same workspace', () => {
    const hub = new EventStreamHub(60000);
    const client1 = createMockSseClient();
    const client2 = createMockSseClient();

    const h1 = hub.register(client1.mockReq, client1.mockRes, 'ws-delta');
    const h2 = hub.register(client2.mockReq, client2.mockRes, 'ws-delta');

    assert.equal(hub.subscriberCount('ws-delta'), 2);

    client1.chunks.length = 0;
    client2.chunks.length = 0;

    const delivered = hub.publish('ws-delta', 'finding.created', { findingId: 'find-99', severity: 'HIGH' });
    assert.equal(delivered, 2);

    assert.equal(client1.chunks.length, 1);
    assert.ok(client1.chunks[0]!.includes('find-99'));
    assert.equal(client2.chunks.length, 1);
    assert.ok(client2.chunks[0]!.includes('find-99'));

    hub.destroy();
    assert.equal(hub.subscriberCount(), 0);
  });
});
