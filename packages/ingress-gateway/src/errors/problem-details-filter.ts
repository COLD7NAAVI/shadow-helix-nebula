/**
 * Shadow : Helix Nebula (SHN) — RFC 7807 Problem Details Error Filter
 *
 * Authoritative Spec: Phase 0.14 Section 24 (API-INV-14), Phase 0.11 Section 19.
 * Guarantees machine-readable, sanitized fail-closed error responses. Zero stack leakage.
 */

import {
  ErrorCode,
  createProblemDetails,
  type ProblemDetails,
} from '@shn/error-catalog';
import type { IngressRequest, IngressResponse } from '../contracts.js';

export function sendProblemDetails(
  res: IngressResponse,
  problem: ProblemDetails
): void {
  res
    .status(problem.status)
    .setHeader('Content-Type', 'application/problem+json; charset=utf-8')
    .setHeader('X-Correlation-ID', problem.correlation_id)
    .json(problem);
}

export function handleUnhandledError(
  err: unknown,
  req: IngressRequest,
  res: IngressResponse
): void {
  const detail =
    err instanceof Error && process.env.NODE_ENV !== 'production'
      ? err.message
      : 'An internal error occurred while processing the request.';

  const problem = createProblemDetails({
    errorCode: ErrorCode.INTERNAL_FAULT,
    detail,
    instance: req.path,
    correlationId: req.correlationId,
  });

  sendProblemDetails(res, problem);
}
