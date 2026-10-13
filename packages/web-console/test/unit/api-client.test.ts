/**
 * Shadow : Helix Nebula (SHN) — ApiClient Unit Tests
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { ApiClient, ApiError } from '../../dist/index.js';

describe('ApiClient (Unit Tests)', () => {
  let originalFetch: typeof globalThis.fetch;
  let lastRequest: { url: string; options: RequestInit } | null = null;
  let mockResponse: { status: number; headers?: Record<string, string>; body: any } = {
    status: 200,
    body: { ok: true },
  };

  beforeEach(() => {
    lastRequest = null;
    originalFetch = globalThis.fetch;
    (globalThis as any).localStorage = {
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
    };

    globalThis.fetch = (async (url: string | URL | Request, options?: RequestInit) => {
      lastRequest = { url: String(url), options: options || {} };

      const headers = new Headers(mockResponse.headers || {});
      if (!headers.has('content-type')) {
        headers.set('content-type', 'application/json');
      }

      return {
        ok: mockResponse.status >= 200 && mockResponse.status < 300,
        status: mockResponse.status,
        statusText: mockResponse.status === 200 ? 'OK' : 'Error',
        headers,
        json: async () => mockResponse.body,
        text: async () => (typeof mockResponse.body === 'string' ? mockResponse.body : JSON.stringify(mockResponse.body)),
      } as unknown as Response;
    }) as any;
  });

  it('attaches X-Correlation-ID and Content-Type on POST requests', async () => {
    mockResponse = { status: 200, body: { token: 'mock-jwt-token' } };
    const client = new ApiClient({ baseUrl: 'http://localhost:8080' });

    const result = await client.login({ email: 'test@shn.sovereign', password: 'Password123!' });

    assert.equal(lastRequest?.url, 'http://localhost:8080/api/v1/auth/login');
    assert.equal(lastRequest?.options.method, 'POST');

    const headers = new Headers(lastRequest?.options.headers);
    assert.equal(headers.get('Content-Type'), 'application/json');
    assert.ok(headers.get('X-Correlation-ID')?.startsWith('req-'));
    assert.deepEqual(result, { token: 'mock-jwt-token' });
  });

  it('injects Bearer token from getToken callback', async () => {
    mockResponse = { status: 200, body: [{ id: 'ws-1', name: 'Alpha' }] };
    const client = new ApiClient({
      baseUrl: 'http://localhost:8080',
      getToken: () => 'my-secret-token',
    });

    const workspaces = await client.listWorkspaces();

    assert.equal(lastRequest?.url, 'http://localhost:8080/api/v1/workspaces');
    const headers = new Headers(lastRequest?.options.headers);
    assert.equal(headers.get('Authorization'), 'Bearer my-secret-token');
    assert.equal(workspaces.length, 1);
  });

  it('triggers onUnauthorized callback on HTTP 401', async () => {
    let unauthorizedTriggered = false;
    mockResponse = {
      status: 401,
      body: { title: 'Unauthorized', status: 401, detail: 'Token expired' },
    };

    const client = new ApiClient({
      baseUrl: 'http://localhost:8080',
      onUnauthorized: () => {
        unauthorizedTriggered = true;
      },
    });

    await assert.rejects(
      async () => client.getMe(),
      (err: Error) => {
        assert.ok(err instanceof ApiError);
        assert.equal((err as ApiError).problem.status, 401);
        return true;
      }
    );

    assert.equal(unauthorizedTriggered, true);
  });

  it('handles RFC 7807 problem details error responses', async () => {
    mockResponse = {
      status: 403,
      body: {
        type: 'https://shn.internal/errors/SEC-001',
        title: 'Scope Authorization Denied',
        status: 403,
        detail: 'Target outside authorized CIDR boundary',
        code: 'SCOPE_ACCESS_DENIED',
      },
    };

    const client = new ApiClient();

    await assert.rejects(
      async () => client.executeCapability('ws-1', { capabilityId: 'cap-1', target: '127.0.0.1' }),
      (err: Error) => {
        assert.ok(err instanceof ApiError);
        const apiErr = err as ApiError;
        assert.equal(apiErr.problem.status, 403);
        assert.equal(apiErr.problem.code, 'SCOPE_ACCESS_DENIED');
        assert.equal(apiErr.problem.detail, 'Target outside authorized CIDR boundary');
        return true;
      }
    );
  });

  it('fetches liveness and readiness health checks', async () => {
    mockResponse = {
      status: 200,
      body: { status: 'UP', component: 'ingress-gateway', timestamp: new Date().toISOString() },
    };

    const client = new ApiClient({ baseUrl: 'http://localhost:8080' });
    const live = await client.getLiveness();
    assert.equal(live.status, 'UP');
    assert.equal(lastRequest?.url, 'http://localhost:8080/health/live');

    const ready = await client.getReadiness();
    assert.equal(ready.status, 'UP');
    assert.equal(lastRequest?.url, 'http://localhost:8080/health/ready');
  });

  it('fetches raw Prometheus metrics', async () => {
    const rawMetrics = '# HELP http_requests_total Total requests\nhttp_requests_total 42\n';
    mockResponse = {
      status: 200,
      headers: { 'content-type': 'text/plain; version=0.0.4' },
      body: rawMetrics,
    };

    const client = new ApiClient({ baseUrl: 'http://localhost:8080' });
    const metrics = await client.getMetrics();
    assert.equal(metrics, rawMetrics);
    assert.equal(lastRequest?.url, 'http://localhost:8080/metrics');
  });

  it('executes finding transitions and retrieves history', async () => {
    mockResponse = {
      status: 200,
      body: { id: 'trans-1', findingId: 'find-1', toStatus: 'CONFIRMED', changedBy: 'operator' },
    };

    const client = new ApiClient({ baseUrl: 'http://localhost:8080' });
    const transition = await client.transitionFinding('ws-1', 'find-1', 'CONFIRMED', 'Verified in audit');

    assert.equal(lastRequest?.url, 'http://localhost:8080/api/v1/workspaces/ws-1/findings/find-1/transitions');
    assert.equal(transition.toStatus, 'CONFIRMED');
  });
});
