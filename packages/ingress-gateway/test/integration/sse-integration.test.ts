/**
 * Shadow : Helix Nebula (SHN) — SSE Real-Time Stream Integration Test Suite
 *
 * Verifies live HTTP streaming over TCP, authentication header vs token query,
 * initial handshake delivery, and real-time domain event broadcasting.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { startStandaloneServer } from '../../dist/standalone.js';
import type { IngressServer, EventStreamHub } from '../../dist/index.js';

describe('SSE Real-Time Stream Live Integration', () => {
  let serverInstance: IngressServer;
  let hub: EventStreamHub;
  let baseUrl: string;
  let authToken: string;
  let workspaceId: string;

  before(async () => {
    try {
      const res = await startStandaloneServer(0);
      serverInstance = res.server;
      baseUrl = res.url;
      hub = res.eventStreamHub;

      // Login to obtain valid Bearer token
      const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'operator@shn.sovereign',
          password: process.env.SHN_INITIAL_ADMIN_PASSWORD || 'Password123!',
        }),
      });
      assert.equal(loginRes.status, 200);
      const loginData = await loginRes.json();
      authToken = loginData.token;

      // Fetch workspaces
      const wksRes = await fetch(`${baseUrl}/api/v1/workspaces`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      const workspaces = await wksRes.json();
      workspaceId = workspaces[0].id;
    } catch (err) {
      if (serverInstance) {
        await serverInstance.stop().catch(() => {});
      }
      throw err;
    }
  });

  after(async () => {
    if (hub) {
      hub.destroy();
    }
    if (serverInstance) {
      await serverInstance.stop();
    }
  });

  it('should deliver OpenAPI specification at /openapi.json and /api/v1/openapi.json', async () => {
    const res1 = await fetch(`${baseUrl}/openapi.json`);
    assert.equal(res1.status, 200);
    assert.ok(res1.headers.get('content-type')?.includes('application/json'));
    const doc1 = await res1.json();
    assert.equal(doc1.openapi, '3.1.0');

    const res2 = await fetch(`${baseUrl}/api/v1/openapi.json`);
    assert.equal(res2.status, 200);
    const doc2 = await res2.json();
    assert.equal(doc2.openapi, '3.1.0');
    assert.ok(doc2.paths['/api/v1/workspaces/{workspaceId}/events/stream']);
  });

  it('should reject unauthenticated SSE connection fail-closed with 401', async () => {
    const res = await fetch(`${baseUrl}/api/v1/workspaces/${workspaceId}/events/stream`);
    assert.equal(res.status, 401);
    const problem = await res.json();
    assert.equal(problem.error_code, 'ERR_AUTH_UNAUTHENTICATED');
  });

  it('should establish live SSE stream and receive handshake + published domain events', async () => {
    const streamUrl = `${baseUrl}/api/v1/workspaces/${workspaceId}/events/stream?token=${encodeURIComponent(authToken)}`;

    const receivedChunks: string[] = [];

    await new Promise<void>((resolve, reject) => {
      let timeoutTimer: NodeJS.Timeout | null = null;
      let isResolved = false;

      const cleanupAndResolve = () => {
        if (isResolved) return;
        isResolved = true;
        if (timeoutTimer) clearTimeout(timeoutTimer);
        req.destroy();
        resolve();
      };

      const cleanupAndReject = (err: unknown) => {
        if (isResolved) return;
        isResolved = true;
        if (timeoutTimer) clearTimeout(timeoutTimer);
        req.destroy();
        reject(err);
      };

      const req = http.get(streamUrl, (res) => {
        assert.equal(res.statusCode, 200);
        assert.ok(res.headers['content-type']?.includes('text/event-stream'));

        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          receivedChunks.push(chunk);

          // Once handshake is received, publish a live domain event
          if (chunk.includes('event: connected')) {
            hub.publish(workspaceId, 'execution.dispatched', {
              executionId: 'exec-test-sse-001',
              capabilityId: 'shn://capabilities/network/port-scan',
              target: '192.168.1.1',
            });
          }

          // Once published event is received, end test successfully
          if (chunk.includes('event: execution.dispatched')) {
            cleanupAndResolve();
          }
        });

        res.on('error', (err) => {
          cleanupAndReject(err);
        });
      });

      req.on('error', (err) => {
        if ((err as any).code !== 'ECONNRESET') {
          cleanupAndReject(err);
        }
      });

      timeoutTimer = setTimeout(() => {
        if (receivedChunks.some((c) => c.includes('event: execution.dispatched'))) {
          cleanupAndResolve();
        } else {
          cleanupAndReject(new Error(`Timeout waiting for SSE event. Received: ${receivedChunks.join('')}`));
        }
      }, 5000);
    });

    const fullStreamText = receivedChunks.join('');
    assert.ok(fullStreamText.includes('event: connected'), 'Must contain initial connection handshake');
    assert.ok(fullStreamText.includes('event: execution.dispatched'), 'Must contain published event');
    assert.ok(fullStreamText.includes('exec-test-sse-001'), 'Must contain event payload');
  });
});
