/**
 * Shadow : Helix Nebula (SHN) — Rate Limiter Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRateLimiterMiddleware } from '../../dist/index.js';
import type { IngressRequest, IngressResponse } from '../../dist/index.js';

describe('Rate Limiter Middleware (Unit Tests)', () => {
  it('should allow requests within limit and reject with 429 when limit exceeded', async () => {
    const limiter = createRateLimiterMiddleware(3, 10000); // Max 3 requests per 10s
    let executedCount = 0;

    const req: IngressRequest = {
      raw: {} as any,
      method: 'GET',
      url: '/test',
      path: '/test',
      query: {},
      params: {},
      headers: {},
      body: undefined,
      correlationId: 'corr-1',
      requestId: 'req-1',
      traceId: 'trace-1',
      clientIp: '192.168.1.100',
    };

    let lastStatus = 200;
    const res: IngressResponse = {
      raw: {} as any,
      status(code: number) {
        lastStatus = code;
        return this;
      },
      setHeader() {
        return this;
      },
      json() {},
      text() {},
      problem(pd) {
        lastStatus = pd.status;
      },
      empty() {},
    };

    const next = async () => {
      executedCount++;
    };

    // Requests 1, 2, 3 should succeed
    await limiter(req, res, next);
    await limiter(req, res, next);
    await limiter(req, res, next);

    assert.strictEqual(executedCount, 3);
    assert.strictEqual(lastStatus, 200);

    // Request 4 should be rejected with 429
    await limiter(req, res, next);

    assert.strictEqual(executedCount, 3); // next was NOT called
    assert.strictEqual(lastStatus, 429);
  });
});
