/**
 * Shadow : Helix Nebula (SHN) — Granular RBAC Middleware
 *
 * Authoritative Spec: Phase 0.11 Section 3, Phase 0.14 Section 19.
 * Validates required bitmask permissions against verified SecurityContext.
 */

import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import type { IngressRequest, IngressResponse, Middleware } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

export function requirePermission(requiredMask: number): Middleware {
  return async (req: IngressRequest, res: IngressResponse, next: () => Promise<void>) => {
    if (!req.securityContext) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.AUTH_UNAUTHENTICATED,
        detail: 'Authentication required prior to permission evaluation.',
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    const currentMask = req.securityContext.permission_mask;
    if ((currentMask & requiredMask) !== requiredMask) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.AUTH_FORBIDDEN,
        detail: `Actor lacks required operational permissions (required mask: 0x${requiredMask.toString(16)}, held mask: 0x${currentMask.toString(16)}).`,
        instance: req.path,
        correlationId: req.correlationId,
      });
      sendProblemDetails(res, problem);
      return;
    }

    await next();
  };
}
