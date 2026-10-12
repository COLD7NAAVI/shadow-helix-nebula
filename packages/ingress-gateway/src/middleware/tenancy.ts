/**
 * Shadow : Helix Nebula (SHN) — Tenancy & Workspace Isolation Middleware
 *
 * Authoritative Spec: Phase 0.4 (INV-01), Phase 0.14 Section 21.
 * Enforces strict workspace boundaries. Cross-workspace attempts return 404 (IDOR protection).
 */

import {
  isValidUUID,
  type WorkspaceId,
} from '@shn/shared-kernel';
import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import type { TenancyValidator } from '@shn/scope-gatekeeper';
import type { IngressRequest, IngressResponse, Middleware } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

export interface TenancyMiddlewareOptions {
  tenancyValidator?: TenancyValidator | undefined;
}

export function createTenancyMiddleware(options?: TenancyMiddlewareOptions): Middleware {
  const validator = options?.tenancyValidator;

  return async (req: IngressRequest, res: IngressResponse, next: () => Promise<void>) => {
    const rawWorkspaceId = req.params['workspaceId'];

    if (!rawWorkspaceId) {
      return next();
    }

    if (!isValidUUID(rawWorkspaceId)) {
      const problem = createProblemDetails({
        errorCode: ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
        detail: `Invalid workspace ID format "${rawWorkspaceId}".`,
        instance: req.path,
        correlationId: req.correlationId,
        customStatus: 404, // Phase 0.14 Section 21 anti-enumeration
      });
      sendProblemDetails(res, problem);
      return;
    }

    const workspaceId = rawWorkspaceId as WorkspaceId;
    req.workspaceId = workspaceId;

    // If authenticated, check context workspace match
    if (req.securityContext) {
      if (req.securityContext.workspace_id !== workspaceId) {
        // Mismatch between authenticated token workspace and requested workspace
        const problem = createProblemDetails({
          errorCode: ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
          detail: 'Requested workspace does not exist or caller lacks access.',
          instance: req.path,
          correlationId: req.correlationId,
          customStatus: 404, // Phase 0.14 Section 21 anti-enumeration
        });
        sendProblemDetails(res, problem);
        return;
      }
    }

    if (validator && req.securityContext) {
      const validRes = validator.assertWorkspaceMatch(req.securityContext, workspaceId);
      if (validRes.isErr) {
        const problem = createProblemDetails({
          errorCode: ErrorCode.AUTH_CROSS_WORKSPACE_DENIED,
          detail: 'Requested workspace does not exist or caller lacks access.',
          instance: req.path,
          correlationId: req.correlationId,
          customStatus: 404,
        });
        sendProblemDetails(res, problem);
        return;
      }
    }

    await next();
  };
}
