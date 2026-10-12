/**
 * Shadow : Helix Nebula (SHN) — Ingress Rate Limiter Middleware
 *
 * Authoritative Spec: Phase 0.14 Section 23 (Tier 1 Edge Rate Limiting).
 * Safeguards control plane against resource exhaustion and denial-of-service.
 */

import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import type { IngressRequest, IngressResponse, Middleware } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

interface ClientWindow {
  count: number;
  resetAt: number;
}

export function createRateLimiterMiddleware(
  maxRequests: number = 100,
  windowMs: number = 60000
): Middleware {
  const ipBuckets = new Map<string, ClientWindow>();

  // Cleanup expired buckets every minute
  const cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [ip, window] of ipBuckets.entries()) {
      if (now > window.resetAt) {
        ipBuckets.delete(ip);
      }
    }
  }, 60000);
  cleanupTimer.unref();

  return async (req: IngressRequest, res: IngressResponse, next: () => Promise<void>) => {
    const now = Date.now();
    const clientKey = req.clientIp || '127.0.0.1';

    let bucket = ipBuckets.get(clientKey);
    if (!bucket || now > bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
      ipBuckets.set(clientKey, bucket);
    }

    bucket.count += 1;
    const remaining = Math.max(0, maxRequests - bucket.count);
    const retryAfterSeconds = Math.ceil((bucket.resetAt - now) / 1000);

    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', remaining);

    if (bucket.count > maxRequests) {
      res.setHeader('Retry-After', retryAfterSeconds);

      const problem = createProblemDetails({
        errorCode: ErrorCode.RATE_LIMIT_EXCEEDED,
        detail: `Rate limit of ${maxRequests} requests per minute exceeded. Try again in ${retryAfterSeconds} seconds.`,
        instance: req.path,
        correlationId: req.correlationId,
      });

      sendProblemDetails(res, problem);
      return;
    }

    await next();
  };
}
