/**
 * Shadow : Helix Nebula (SHN) — Request Lineage & Correlation Middleware
 *
 * Authoritative Spec: Phase 0.14 Section 18, Phase 0.11 Section 19.
 * Ensures unbroken causation and distributed trace lineage across ingress boundaries.
 */

import { generateUUIDv7 } from '@shn/shared-kernel';
import type { IngressRequest, IngressResponse, Middleware } from '../contracts.js';

export function createCorrelationMiddleware(): Middleware {
  return async (req: IngressRequest, res: IngressResponse, next: () => Promise<void>) => {
    const rawHeaders = req.headers;

    const correlationId =
      (typeof rawHeaders['x-correlation-id'] === 'string' && rawHeaders['x-correlation-id'].trim()) ||
      generateUUIDv7();

    const requestId =
      (typeof rawHeaders['x-request-id'] === 'string' && rawHeaders['x-request-id'].trim()) ||
      generateUUIDv7();

    const traceId =
      (typeof rawHeaders['x-trace-id'] === 'string' && rawHeaders['x-trace-id'].trim()) ||
      (typeof rawHeaders['traceparent'] === 'string' && rawHeaders['traceparent'].split('-')[1]) ||
      generateUUIDv7().replace(/-/g, '');

    (req as any).correlationId = correlationId;
    (req as any).requestId = requestId;
    (req as any).traceId = traceId;

    res.setHeader('X-Correlation-ID', correlationId);
    res.setHeader('X-Request-ID', requestId);
    res.setHeader('X-Trace-ID', traceId);

    await next();
  };
}
