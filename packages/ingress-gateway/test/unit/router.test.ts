/**
 * Shadow : Helix Nebula (SHN) — Router Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Router } from '../../dist/index.js';
import type { IngressRequest, IngressResponse } from '../../dist/index.js';

function createMockRequest(method: string, path: string): IngressRequest {
  return {
    raw: {} as any,
    method,
    url: path,
    path,
    query: {},
    params: {},
    headers: {},
    body: undefined,
    correlationId: 'test-corr-id',
    requestId: 'test-req-id',
    traceId: 'test-trace-id',
    clientIp: '127.0.0.1',
  };
}

function createMockResponse(): { res: IngressResponse; getStatusCode: () => number; getBody: () => any } {
  let statusCode = 200;
  let body: any = null;

  const res: IngressResponse = {
    raw: {} as any,
    status(code: number) {
      statusCode = code;
      return this;
    },
    setHeader() {
      return this;
    },
    json(payload: unknown) {
      body = payload;
    },
    text(payload: string) {
      body = payload;
    },
    problem(pd) {
      statusCode = pd.status;
      body = pd;
    },
    empty(code?: number) {
      if (code) statusCode = code;
    },
  };

  return { res, getStatusCode: () => statusCode, getBody: () => body };
}

describe('Ingress Router (Unit Tests)', () => {
  it('should route exact paths and execute handler', async () => {
    const router = new Router();
    let executed = false;

    router.get('/health/live', async (_req, res) => {
      executed = true;
      res.status(200).json({ status: 'UP' });
    });

    const req = createMockRequest('GET', '/health/live');
    const { res, getStatusCode, getBody } = createMockResponse();

    await router.handle(req, res);

    assert.strictEqual(executed, true);
    assert.strictEqual(getStatusCode(), 200);
    assert.deepStrictEqual(getBody(), { status: 'UP' });
  });

  it('should extract path parameters correctly', async () => {
    const router = new Router();
    let capturedParams: any = null;

    router.get('/workspaces/:workspaceId/assets/:assetId', async (req, res) => {
      capturedParams = req.params;
      res.status(200).json({ ok: true });
    });

    const req = createMockRequest('GET', '/workspaces/wks-123/assets/ast-456');
    const { res, getStatusCode } = createMockResponse();

    await router.handle(req, res);

    assert.strictEqual(getStatusCode(), 200);
    assert.deepStrictEqual(capturedParams, {
      workspaceId: 'wks-123',
      assetId: 'ast-456',
    });
  });

  it('should return 404 Problem Details when route is not found', async () => {
    const router = new Router();
    const req = createMockRequest('GET', '/non/existent/endpoint');
    const { res, getStatusCode, getBody } = createMockResponse();

    await router.handle(req, res);

    assert.strictEqual(getStatusCode(), 404);
    assert.strictEqual(getBody().error_code, 'ERR_STORAGE_NOT_FOUND');
  });

  it('should respond to OPTIONS preflight with 204 and CORS headers', async () => {
    const router = new Router();
    const req = createMockRequest('OPTIONS', '/api/v1/workspaces');
    const { res, getStatusCode } = createMockResponse();

    await router.handle(req, res);

    assert.strictEqual(getStatusCode(), 204);
  });
});
